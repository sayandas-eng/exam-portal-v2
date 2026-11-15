"""Gemini MCP server dedicated to Exam Portal V2.

Run: python mcp_v2.py
Required environment: MCP_PUBLIC_URL, MCP_LOGIN_USERNAME, MCP_LOGIN_PASSWORD,
MCP_API_TOKEN, PORTAL_BASE_URL
"""
import html
import os
import json
import re
import secrets
import time
from typing import Any

import requests
import psycopg
from psycopg.rows import dict_row
from pydantic import AnyHttpUrl
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams,
    OAuthAuthorizationServerProvider, RefreshToken, construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

BASE = os.environ.get("PORTAL_BASE_URL", "https://exam-portal-v2.onrender.com").rstrip("/")
API_TOKEN = os.environ.get("MCP_API_TOKEN", "")
LOGIN_USER = os.environ.get("MCP_LOGIN_USERNAME", "")
LOGIN_PASS = os.environ.get("MCP_LOGIN_PASSWORD", "")
PUBLIC_URL = os.environ.get("MCP_PUBLIC_URL", "").rstrip("/")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))

if not all((BASE, API_TOKEN, LOGIN_USER, LOGIN_PASS, PUBLIC_URL, DATABASE_URL)):
    raise RuntimeError("Set MCP_API_TOKEN, MCP_LOGIN_USERNAME, MCP_LOGIN_PASSWORD, MCP_PUBLIC_URL and DATABASE_URL.")

class PortalOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """OAuth provider with dynamic client registration and PKCE."""
    def __init__(self):
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.states: dict[str, dict[str, Any]] = {}
        # Persist Gemini's dynamic OAuth client registration across service restarts.
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS portal_v2_mcp_oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_info JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            rows = conn.execute(
                "SELECT client_id, client_info FROM portal_v2_mcp_oauth_clients"
            ).fetchall()
        for row in rows:
            self.clients[row["client_id"]] = OAuthClientInformationFull.model_validate(row["client_info"])

    async def get_client(self, client_id: str):
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        if not client_info.client_id:
            raise ValueError("Missing OAuth client ID")
        payload = client_info.model_dump(mode="json", exclude_none=True)
        with psycopg.connect(DATABASE_URL) as conn:
            conn.execute(
                """INSERT INTO portal_v2_mcp_oauth_clients (client_id, client_info)
                   VALUES (%s, %s::jsonb)
                   ON CONFLICT (client_id) DO UPDATE SET client_info = EXCLUDED.client_info""",
                (client_info.client_id, json.dumps(payload)),
            )
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        state = params.state or secrets.token_urlsafe(24)
        self.states[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "explicit": bool(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
            "resource": params.resource,
            "scopes": params.scopes or ["portal"],
        }
        return f"{PUBLIC_URL}/login?state={state}"

    async def load_authorization_code(self, client, authorization_code: str):
        return self.codes.get(authorization_code)

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        code = self.codes.get(authorization_code.code)
        if code is None or code.expires_at < time.time():
            raise ValueError("Authorization code expired or invalid")
        if code.client_id != client.client_id:
            raise ValueError("OAuth client mismatch")
        token = "v2portal_" + secrets.token_urlsafe(48)
        self.tokens[token] = AccessToken(
            token=token, client_id=client.client_id or "",
            scopes=code.scopes, expires_at=int(time.time()) + 3600,
            resource=code.resource,
        )
        del self.codes[authorization_code.code]
        return OAuthToken(access_token=token, token_type="Bearer", expires_in=3600, scope=" ".join(code.scopes))

    async def load_access_token(self, token: str):
        item = self.tokens.get(token)
        if item and item.expires_at and item.expires_at <= time.time():
            self.tokens.pop(token, None)
            return None
        return item

    async def load_refresh_token(self, client, refresh_token: str):
        return None

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]):
        raise NotImplementedError("Refresh tokens are not enabled")

    async def revoke_token(self, token: str, token_type_hint: str | None = None):
        self.tokens.pop(token, None)

    async def login_page(self, state: str) -> HTMLResponse:
        if state not in self.states:
            raise HTTPException(400, "Invalid or expired login state")
        safe_state = html.escape(state, quote=True)
        page = f"""<!doctype html><html><head><meta name="viewport" content="width=device-width">
        <title>Exam Portal V2 MCP Login</title></head><body style="font:16px Arial;max-width:420px;margin:60px auto;padding:20px">
        <h2>Exam Portal V2 · Gemini</h2><p>Sign in to authorize Gemini to create and publish V2 examinations.</p>
        <form method="post" action="/login">
        <input type="hidden" name="state" value="{safe_state}">
        <p><label>Username<br><input name="username" required autocomplete="username"></label></p>
        <p><label>Password<br><input type="password" name="password" required autocomplete="current-password"></label></p>
        <button type="submit">Authorize Gemini</button></form></body></html>"""
        return HTMLResponse(page)

    async def login_callback(self, request: Request) -> Response:
        form = await request.form()
        state, username, password = form.get("state"), form.get("username"), form.get("password")
        if not all(isinstance(x, str) for x in (state, username, password)):
            raise HTTPException(400, "Missing login fields")
        data = self.states.get(state)
        if not data or not secrets.compare_digest(username, LOGIN_USER) or not secrets.compare_digest(password, LOGIN_PASS):
            raise HTTPException(401, "Invalid login or expired authorization request")
        code_value = "code_" + secrets.token_urlsafe(32)
        self.codes[code_value] = AuthorizationCode(
            code=code_value, client_id=data["client_id"],
            redirect_uri=AnyHttpUrl(data["redirect_uri"]),
            redirect_uri_provided_explicitly=data["explicit"],
            expires_at=time.time() + 300, scopes=data["scopes"],
            code_challenge=data["code_challenge"], resource=data["resource"],
        )
        del self.states[state]
        return RedirectResponse(
            construct_redirect_uri(data["redirect_uri"], code=code_value, state=state),
            status_code=302,
        )

provider = PortalOAuthProvider()
auth = AuthSettings(
    issuer_url=AnyHttpUrl(PUBLIC_URL),
    resource_server_url=AnyHttpUrl(PUBLIC_URL),
    client_registration_options=ClientRegistrationOptions(
        enabled=True, valid_scopes=["portal"], default_scopes=["portal"]
    ),
    required_scopes=["portal"],
    validate_token_resource=True,
)
mcp = FastMCP(
    name="Exam Portal V2",
    instructions=(
        "You are connected to the NEW Exam Portal V2 only. When the teacher asks for an exam, "
        "generate the question paper and answer key, then generate a NEW strong common password "
        "for that exam (at least 16 characters, uppercase, lowercase, digit and symbol). "
        "Pass that exact password to create_and_publish_exam and return it to the teacher. "
        "Never reuse a previous exam password. Students sign in with name, class and this password. "
        "Do not call or use the legacy V1 portal."
    ),
    host=HOST, port=PORT, auth_server_provider=provider, auth=auth,
)

@mcp.custom_route("/", methods=["GET"])
async def root_info(request: Request) -> Response:
    return JSONResponse({"service": "Exam Portal V2 Gemini MCP", "status": "online", "mcp_endpoint": "/mcp"})

@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> Response:
    return JSONResponse({"ok": True, "service": "exam-portal-v2-gemini-mcp"})

@mcp.custom_route("/login", methods=["GET"])
async def login_page(request: Request) -> Response:
    return await provider.login_page(request.query_params.get("state", ""))

@mcp.custom_route("/login", methods=["POST"])
async def login_post(request: Request) -> Response:
    return await provider.login_callback(request)

def portal_call(method: str, path: str, **kwargs):
    response = requests.request(
        method, BASE + path,
        headers={"X-Admin-Key": API_TOKEN},
        timeout=90, **kwargs,
    )
    if not response.ok:
        raise RuntimeError(f"Exam Portal V2 returned HTTP {response.status_code}: {response.text[:1200]}")
    return response.json()

def normalize_class(value: str) -> str:
    value = str(value).strip()
    if value.isdigit():
        value = f"Class {value}"
    if not value or len(value) > 60:
        raise ValueError("Provide a valid target class, for example Class 10.")
    return value

@mcp.tool()
def create_and_publish_exam(
    title: str,
    subject: str,
    topic: str,
    class_level: str,
    questions_json: str,
    common_password: str,
    duration_minutes: int = 45,
    review_minutes: int = 0,
    difficulty: str = "moderate",
) -> dict:
    """Create and publish an examination in Exam Portal V2. Gemini must first generate a fresh unique strong common_password (minimum 16 characters with uppercase, lowercase, number and symbol) and include it here. questions_json is a JSON array of objects with prompt, question_type (mcq, saq or laq), marks, options and correct_option for MCQs, or expected_answer and marking_scheme for written questions. Supports aliases question/type/answer. The tool creates a draft, publishes it, and returns the common password once for the teacher to distribute. Students sign in with name, class and this password."""
    class_level = normalize_class(class_level)
    if len(common_password) < 16 or not all((
        re.search(r"[A-Z]", common_password),
        re.search(r"[a-z]", common_password),
        re.search(r"\d", common_password),
        re.search(r"[^A-Za-z0-9]", common_password),
    )):
        raise ValueError("Gemini must generate a strong password of at least 16 characters including uppercase, lowercase, a number and a symbol.")
    try:
        raw_questions = __import__("json").loads(questions_json)
    except Exception as exc:
        raise ValueError("questions_json must be a valid JSON array.") from exc
    if not isinstance(raw_questions, list) or not raw_questions or len(raw_questions) > 100:
        raise ValueError("Provide between 1 and 100 questions.")
    questions = []
    for index, item in enumerate(raw_questions, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Question {index} must be an object.")
        prompt = str(item.get("prompt", item.get("question", ""))).strip()
        kind = str(item.get("question_type", item.get("type", "mcq"))).lower().strip()
        aliases = {"multiple_choice": "mcq", "multiple choice": "mcq", "fill": "saq", "text": "laq", "short": "saq", "long": "laq"}
        kind = aliases.get(kind, kind)
        if kind not in ("mcq", "saq", "laq") or not prompt:
            raise ValueError(f"Question {index} needs a prompt and type mcq, saq or laq.")
        try:
            marks = float(item.get("marks", 1))
        except Exception as exc:
            raise ValueError(f"Question {index} has invalid marks.") from exc
        if marks <= 0:
            raise ValueError(f"Question {index} marks must be positive.")
        q = {
            "prompt": prompt, "question_type": kind, "marks": marks,
            "expected_answer": str(item.get("expected_answer", item.get("answer", ""))),
            "marking_scheme": item.get("marking_scheme", {}),
        }
        if kind == "mcq":
            options = item.get("options") or []
            if not isinstance(options, list) or len(options) < 2 or len(options) > 4:
                raise ValueError(f"Question {index} MCQ requires 2–4 options.")
            correct = str(item.get("correct_option", item.get("answer", ""))).strip()
            if correct.upper() in ("A", "B", "C", "D"):
                correct_option = correct.upper()
            else:
                matches = [i for i, option in enumerate(options) if str(option).strip().lower() == correct.lower()]
                if not matches:
                    raise ValueError(f"Question {index} correct_option must be A-D or match an option.")
                correct_option = "ABCD"[matches[0]]
            q.update({"options": options, "correct_option": correct_option})
        questions.append(q)
    created = portal_call("POST", "/api/admin/exams", json={
        "title": title, "subject": subject, "topic": topic,
        "target_class": class_level, "difficulty": difficulty,
        "duration_minutes": int(duration_minutes), "review_minutes": int(review_minutes),
        "exam_password": common_password, "questions": questions,
    })
    exam_id = created["exam_id"]
    published = portal_call("POST", f"/api/admin/exams/{exam_id}/publish", json={})
    return {
        "ok": True, "exam_id": exam_id, "title": title,
        "class_level": class_level, "status": published.get("status", "live"),
        "question_count": created.get("question_count"),
        "total_marks": created.get("total_marks"),
        "common_password": common_password,
        "student_portal": BASE + "/student",
        "message": "Exam published. Share the common_password with students; students sign in with their name, class and this password.",
    }

@mcp.tool()
def list_examinations() -> dict:
    """List V2 examinations and their status for the authorized teacher."""
    return portal_call("GET", "/api/admin/exams")

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
