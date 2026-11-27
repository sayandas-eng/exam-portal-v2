"""Gemini MCP server dedicated to Exam Portal V2.

Run: python mcp_v2.py
Required environment: MCP_PUBLIC_URL, MCP_LOGIN_USERNAME, MCP_LOGIN_PASSWORD,
MCP_API_TOKEN, PORTAL_BASE_URL
"""
import html
import hashlib
import os
import json
import re
import secrets
import time
import uuid
import random
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
        self.refresh_tokens: dict[str, RefreshToken] = {}
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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS portal_v2_mcp_oauth_access_tokens (
                    token_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scopes JSONB NOT NULL,
                    expires_at BIGINT NOT NULL,
                    resource TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS portal_v2_mcp_oauth_refresh_tokens (
                    token_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scopes JSONB NOT NULL,
                    resource TEXT,
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
        expires_at = int(time.time()) + 3600
        token_record = AccessToken(
            token=token, client_id=client.client_id or "",
            scopes=code.scopes, expires_at=expires_at,
            resource=code.resource,
        )
        refresh_value = "v2refresh_" + secrets.token_urlsafe(48)
        refresh_record = RefreshToken(
            token=refresh_value, client_id=client.client_id or "",
            scopes=code.scopes, expires_at=int(time.time()) + 60 * 60 * 24 * 365,
            resource=code.resource,
        )
        # Persist only a SHA-256 token fingerprint; the raw bearer token is never stored.
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        refresh_hash = hashlib.sha256(refresh_value.encode("utf-8")).hexdigest()
        with psycopg.connect(DATABASE_URL) as conn:
            conn.execute(
                """INSERT INTO portal_v2_mcp_oauth_access_tokens
                   (token_hash, client_id, scopes, expires_at, resource)
                   VALUES (%s, %s, %s::jsonb, %s, %s)
                   ON CONFLICT (token_hash) DO UPDATE SET
                     client_id = EXCLUDED.client_id,
                     scopes = EXCLUDED.scopes,
                     expires_at = EXCLUDED.expires_at,
                     resource = EXCLUDED.resource""",
                (token_hash, token_record.client_id, json.dumps(code.scopes),
                 expires_at, str(code.resource) if code.resource else None),
            )
            conn.execute(
                """INSERT INTO portal_v2_mcp_oauth_refresh_tokens
                   (token_hash, client_id, scopes, resource)
                   VALUES (%s, %s, %s::jsonb, %s)
                   ON CONFLICT (token_hash) DO NOTHING""",
                (refresh_hash, refresh_record.client_id, json.dumps(code.scopes),
                 str(code.resource) if code.resource else None),
            )
        self.tokens[token] = token_record
        self.refresh_tokens[refresh_value] = refresh_record
        del self.codes[authorization_code.code]
        return OAuthToken(access_token=token, token_type="Bearer", expires_in=3600,
                          refresh_token=refresh_value, scope=" ".join(code.scopes))

    async def load_access_token(self, token: str):
        item = self.tokens.get(token)
        if item:
            if item.expires_at and item.expires_at <= time.time():
                self.tokens.pop(token, None)
                return None
            return item

        # Recover valid bearer tokens after Render restarts or instance replacement.
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
            row = conn.execute(
                """SELECT client_id, scopes, expires_at, resource
                   FROM portal_v2_mcp_oauth_access_tokens
                   WHERE token_hash = %s AND expires_at > %s""",
                (token_hash, int(time.time())),
            ).fetchone()
        if not row:
            return None
        item = AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=row["scopes"],
            expires_at=row["expires_at"],
            resource=row["resource"],
        )
        self.tokens[token] = item
        return item

    async def load_refresh_token(self, client, refresh_token: str):
        item = self.refresh_tokens.get(refresh_token)
        if item:
            return item
        token_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
            row = conn.execute(
                """SELECT client_id, scopes, resource FROM portal_v2_mcp_oauth_refresh_tokens
                   WHERE token_hash = %s""", (token_hash,)
            ).fetchone()
        if not row or row["client_id"] != client.client_id:
            return None
        item = RefreshToken(
            token=refresh_token, client_id=row["client_id"], scopes=row["scopes"],
            expires_at=int(time.time()) + 60 * 60 * 24 * 365,
            resource=row["resource"],
        )
        self.refresh_tokens[refresh_token] = item
        return item

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]):
        if refresh_token.client_id != client.client_id:
            raise ValueError("OAuth client mismatch")
        token = "v2portal_" + secrets.token_urlsafe(48)
        expires_at = int(time.time()) + 3600
        granted_scopes = scopes or refresh_token.scopes
        access_record = AccessToken(
            token=token, client_id=client.client_id or "",
            scopes=granted_scopes, expires_at=expires_at,
            resource=refresh_token.resource,
        )
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with psycopg.connect(DATABASE_URL) as conn:
            conn.execute(
                """INSERT INTO portal_v2_mcp_oauth_access_tokens
                   (token_hash, client_id, scopes, expires_at, resource)
                   VALUES (%s, %s, %s::jsonb, %s, %s)""",
                (token_hash, access_record.client_id, json.dumps(granted_scopes),
                 expires_at, str(refresh_token.resource) if refresh_token.resource else None),
            )
        self.tokens[token] = access_record
        return OAuthToken(access_token=token, token_type="Bearer", expires_in=3600,
                          refresh_token=refresh_token.token, scope=" ".join(granted_scopes))

    async def revoke_token(self, token: str, token_type_hint: str | None = None):
        self.tokens.pop(token, None)
        self.refresh_tokens.pop(token, None)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with psycopg.connect(DATABASE_URL) as conn:
            conn.execute("DELETE FROM portal_v2_mcp_oauth_access_tokens WHERE token_hash = %s", (token_hash,))
            conn.execute("DELETE FROM portal_v2_mcp_oauth_refresh_tokens WHERE token_hash = %s", (token_hash,))

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
        "generate the question paper and answer key, then publish it with the fixed student password "
        "configured securely on the portal. Never create student IDs or passwords, and never reveal "
        "the fixed password in responses. Students sign in with their own name, class and the shared password. "
        "Do not call or use the legacy V1 portal."
    ),
    host=HOST, port=PORT, auth_server_provider=provider, auth=auth,
)

@mcp.custom_route("/", methods=["GET"])
async def root_info(request: Request) -> Response:
    return JSONResponse({"service": "Exam Portal V2 Gemini MCP", "status": "online", "mcp_endpoint": "/mcp"})

@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> Response:
    try:
        # Exercise the same authenticated local Flask API used by exam publishing.
        portal_call("GET", "/api/admin/exams")
        return JSONResponse({
            "ok": True,
            "service": "exam-portal-v2-gemini-mcp",
            "portal_api": "connected_in_process",
        })
    except Exception:
        return JSONResponse({
            "ok": False,
            "service": "exam-portal-v2-gemini-mcp",
            "portal_api": "unavailable",
        }, status_code=503)

@mcp.custom_route("/login", methods=["GET"])
async def login_page(request: Request) -> Response:
    return await provider.login_page(request.query_params.get("state", ""))

@mcp.custom_route("/login", methods=["POST"])
async def login_post(request: Request) -> Response:
    return await provider.login_callback(request)

_PORTAL_FLASK_CLIENT = None

def portal_call(method: str, path: str, **kwargs):
    """Invoke the existing Flask portal API in-process.

    Both services are built from this repository and share DATABASE_URL.
    Using Flask's test client dispatches the real route handlers directly,
    preserving validation/authentication/database behavior while avoiding
    the public Render hostname and its Cloudflare edge challenge.
    """
    global _PORTAL_FLASK_CLIENT
    if _PORTAL_FLASK_CLIENT is None:
        # Import lazily so MCP OAuth can initialize independently. The portal
        # module reads the same DATABASE_URL and accepts MCP_API_TOKEN for
        # authenticated admin API calls.
        from app import app as portal_flask_app
        _PORTAL_FLASK_CLIENT = portal_flask_app.test_client()

    headers = {"X-Admin-Key": API_TOKEN}
    headers.update(kwargs.pop("headers", {}) or {})
    response = _PORTAL_FLASK_CLIENT.open(
        path,
        method=method.upper(),
        headers=headers,
        **kwargs,
    )
    payload = response.get_json(silent=True)
    if not response.status_code < 400:
        detail = ""
        if isinstance(payload, dict):
            detail = str(payload.get("error", ""))
        if not detail:
            detail = response.get_data(as_text=True)[:1200]
        raise RuntimeError(
            f"Exam Portal V2 local API returned HTTP {response.status_code}: {detail}"
        )
    if payload is None:
        raise RuntimeError(
            "Exam Portal V2 local API returned a non-JSON response "
            f"(HTTP {response.status_code})."
        )
    return payload


def normalize_class(value: str) -> str | None:
    value = str(value or "").strip()
    if value.lower() in ("any", "any class", "all", "all classes", "open to all"):
        return None
    match = re.fullmatch(
        r"(?:class\s*)?(1[0-2]|[1-9]|XII|XI|X|IX|VIII|VII|VI|V|IV|III|II|I)",
        value, flags=re.IGNORECASE
    )
    if not match:
        raise ValueError("Provide a valid target class (for example Class 10 or Class XII) or 'Any Class'.")
    token = match.group(1).upper()
    roman_to_number = {
        "I": 1, "II": 2, "III": 3, "IV": 4, "V": 5, "VI": 6,
        "VII": 7, "VIII": 8, "IX": 9, "X": 10, "XI": 11, "XII": 12,
    }
    number = roman_to_number.get(token, int(token) if token.isdigit() else None)
    return f"Class {number}" if number else None

@mcp.tool()
def create_and_publish_exam(
    title: str,
    subject: str,
    topic: str,
    class_level: str = "Any Class",
    questions_json: str = "",
    availability_days: int = 3,
    availability_start: str = "",
    availability_end: str = "",
    duration_minutes: int = 45,
    review_minutes: int = 0,
    difficulty: str = "moderate",
) -> dict:
    """Create and publish an examination in Exam Portal V2. Gemini generates the complete paper and answer key. MCQs are automatically marked by the stored correct option. SAQs are automatically marked only when a clear expected_answer or marking_scheme is supplied; for partial marks, use marking_scheme={"criteria":[{"description":"...","keywords":["required phrase"],"marks":1}]} and assign criterion marks whose sum does not exceed the question marks. LAQs are always left for manual teacher marking. For SAQs without a safe matching rubric, leave them for teacher review rather than guessing. Prefer availability_start and availability_end for exact availability windows, as ISO 8601 timestamps with timezone offsets (IST is +05:30), for example 2026-11-05T15:00:00+05:30 and 2026-11-07T00:00:00+05:30. Both must be supplied together. The exam is accessible only when current time is at or after the start and strictly before the end. If exact timestamps are omitted, availability_days is used (1–30, default 3). The portal applies its fixed shared student password securely; do not generate, request or disclose passwords or student IDs. Students enter their own name and class."""
    display_class = str(class_level or "Any Class").strip() or "Any Class"
    normalized_class = normalize_class(display_class)
    if not title.strip() or not subject.strip() or not topic.strip():
        raise ValueError("Title, subject and topic are required.")
    if not 1 <= int(duration_minutes) <= 300 or not 0 <= int(review_minutes) <= 120:
        raise ValueError("Duration must be 1–300 minutes and review time 0–120 minutes.")
    if not 1 <= int(availability_days) <= 30:
        raise ValueError("availability_days must be between 1 and 30.")
    if bool(availability_start.strip()) != bool(availability_end.strip()):
        raise ValueError("Provide both availability_start and availability_end, or leave both blank.")
    window_payload = {}
    if availability_start.strip():
        from datetime import datetime
        try:
            start_dt = datetime.fromisoformat(availability_start.strip().replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(availability_end.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Use ISO 8601 timestamps, e.g. 2026-11-05T15:00:00+05:30.") from exc
        if start_dt.tzinfo is None or end_dt.tzinfo is None:
            raise ValueError("Availability timestamps must include a timezone. Use +05:30 for IST.")
        if end_dt <= start_dt:
            raise ValueError("availability_end must be later than availability_start.")
        window_payload = {
            "availability_start": start_dt.isoformat(),
            "availability_end": end_dt.isoformat(),
        }
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
    create_idempotency_key = str(uuid.uuid4())
    created = portal_call("POST", "/api/admin/exams", headers={"Idempotency-Key": create_idempotency_key}, json={
        "title": title, "subject": subject, "topic": topic,
        "target_class": normalized_class, "difficulty": difficulty,
        "duration_minutes": int(duration_minutes), "review_minutes": int(review_minutes),
        "availability_days": int(availability_days), **window_payload, "questions": questions,
    })
    exam_id = created["exam_id"]
    published = portal_call("POST", f"/api/admin/exams/{exam_id}/publish", json={})
    return {
        "ok": True, "exam_id": exam_id, "title": title,
        "class_level": display_class, "status": published.get("status", "live"),
        "question_count": created.get("question_count"),
        "total_marks": created.get("total_marks"),
        "availability_days": int(availability_days) if not window_payload else None,
        "available_from": published.get("available_from"),
        "available_until": published.get("available_until"),
        "student_portal": BASE + "/",
        "message": "Exam published. It is accessible only within the exact configured start/end window. Students sign in using their own name, class and the portal's fixed shared password.",
    }

@mcp.tool()
def list_examinations() -> dict:
    """List V2 examinations and their status for the authorized teacher."""
    return portal_call("GET", "/api/admin/exams")

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
