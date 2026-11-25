import os
import codecs
import encodings.idna
# Some minimal Python 3.14 images fail to register the standard IDNA codec.
# Render hostnames arrive as ASCII/punycode, so an ASCII fallback is safe.
try:
    codecs.lookup("idna")
except LookupError:
    codecs.register(lambda name: codecs.lookup("ascii") if name.replace("-", "_") == "idna" else None)
    codecs.lookup("idna")
import uuid
import hmac
import secrets
import threading
import time
import io
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import psycopg
from psycopg.rows import dict_row
from flask import Flask, jsonify, request, render_template, session, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)
limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")
DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
ADMIN_LOGIN_USERNAME = os.getenv("ADMIN_LOGIN_USERNAME", "")
ADMIN_LOGIN_PASSWORD = os.getenv("ADMIN_LOGIN_PASSWORD", "")
STUDENT_EXAM_PASSWORD = os.getenv("STUDENT_EXAM_PASSWORD", "")


SCHEMA_READY = False


def db():
    global SCHEMA_READY
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    if not SCHEMA_READY:
        conn.execute("ALTER TABLE portal_v2_exams ADD COLUMN IF NOT EXISTS pdf_enabled BOOLEAN NOT NULL DEFAULT TRUE")
        conn.execute("ALTER TABLE portal_v2_exams ADD COLUMN IF NOT EXISTS pdf_cleared_at TIMESTAMPTZ")
        conn.execute("ALTER TABLE portal_v2_exams ADD COLUMN IF NOT EXISTS availability_days INTEGER NOT NULL DEFAULT 3")
        conn.execute("ALTER TABLE portal_v2_exams ADD COLUMN IF NOT EXISTS available_until TIMESTAMPTZ")
        conn.execute("ALTER TABLE portal_v2_exams ADD COLUMN IF NOT EXISTS available_from TIMESTAMPTZ")
        # Stable keys make exam creation safe to retry after transient throttling.
        conn.execute("ALTER TABLE portal_v2_exams ADD COLUMN IF NOT EXISTS idempotency_key TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS portal_v2_exams_idempotency_key_uidx ON portal_v2_exams (idempotency_key) WHERE idempotency_key IS NOT NULL")
        conn.execute("ALTER TABLE portal_v2_exams DROP CONSTRAINT IF EXISTS portal_v2_exams_status_check")
        conn.execute("""
            ALTER TABLE portal_v2_exams
            ADD CONSTRAINT portal_v2_exams_status_check
            CHECK (status IN ('draft', 'live', 'paused', 'archived', 'deleted'))
        """)
        conn.execute("""UPDATE portal_v2_exams
                        SET available_until = published_at + (availability_days::text || ' days')::interval
                        WHERE status='live' AND available_until IS NULL AND published_at IS NOT NULL""")
        conn.execute("""UPDATE portal_v2_exams
                        SET available_from = published_at
                        WHERE status='live' AND available_from IS NULL AND published_at IS NOT NULL""")
        SCHEMA_READY = True
    return conn


def purge_expired_exams():
    """Archive expired exams while retaining student submissions and results."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT id FROM portal_v2_exams
            WHERE status = 'live'
              AND available_until IS NOT NULL AND available_until <= now()
            FOR UPDATE
        """)
        cur.fetchall()
        expired_exam_filter = """
            SELECT id FROM portal_v2_exams
            WHERE status = 'live'
              AND available_until IS NOT NULL AND available_until <= now()
        """
        # Archive expired exams without deleting attempts, answers, or evaluation records.
        # Teachers must retain access to every submission and be able to correct marks later.
        cur.execute(f"UPDATE portal_v2_exams SET status='archived' WHERE id IN ({expired_exam_filter})")


def _expiry_cleanup_loop():
    """Run independently of web traffic; advisory lock prevents worker overlap."""
    while True:
        try:
            purge_expired_exams()
            app.logger.info("Expired exam cleanup check completed")
        except Exception:
            app.logger.exception("Expired exam cleanup failed; will retry")
        time.sleep(60)


if DATABASE_URL:
    threading.Thread(
        target=_expiry_cleanup_loop,
        name="exam-expiry-cleanup",
        daemon=True,
    ).start()


def valid_admin_session_token():
    token = request.headers.get("X-Admin-Session", "") or request.cookies.get("exam_portal_admin_token", "")
    if not token or not app.secret_key:
        return False
    try:
        payload = URLSafeTimedSerializer(app.secret_key, salt="exam-portal-admin-session").loads(token, max_age=7 * 24 * 60 * 60)
        return payload.get("role") == "admin"
    except (BadSignature, SignatureExpired, AttributeError):
        return False


def admin_required():
    supplied = request.headers.get("X-Admin-Key", "")
    valid_admin = bool(ADMIN_API_KEY and supplied and hmac.compare_digest(supplied, ADMIN_API_KEY))
    mcp_token = os.getenv("MCP_API_TOKEN", "")
    valid_mcp = bool(mcp_token and supplied and hmac.compare_digest(supplied, mcp_token))
    return valid_admin or valid_mcp or bool(session.get("admin_authenticated")) or valid_admin_session_token()


def error(message, status=400):
    return jsonify({"ok": False, "error": message}), status


@app.get("/")
def home():
    # Public entry point: students must see the login page first.
    return render_template("student.html")


@app.get("/student")
def student_portal():
    return render_template("student.html")


@app.get("/admin")
def admin_portal():
    return render_template("index.html")


@app.post("/api/admin/session/login")
@limiter.limit("8 per minute")
def admin_session_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    valid_user = bool(ADMIN_LOGIN_USERNAME and username and hmac.compare_digest(username, ADMIN_LOGIN_USERNAME))
    valid_password = bool(ADMIN_LOGIN_PASSWORD and password and hmac.compare_digest(password, ADMIN_LOGIN_PASSWORD))
    if not (valid_user and valid_password):
        return error("Incorrect admin username or password", 401)
    session.clear()
    session["admin_authenticated"] = True
    session["admin_csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    admin_token = URLSafeTimedSerializer(app.secret_key, salt="exam-portal-admin-session").dumps({"role": "admin"})
    response = jsonify({"ok": True, "csrf_token": session["admin_csrf_token"], "admin_token": admin_token})
    response.set_cookie("exam_portal_admin_token", admin_token, max_age=7 * 24 * 60 * 60, httponly=True, secure=True, samesite="Lax", path="/")
    return response


@app.get("/api/admin/session")
def admin_session_status():
    authenticated = bool(session.get("admin_authenticated")) or valid_admin_session_token()
    response = jsonify({"ok": authenticated, "csrf_token": session.get("admin_csrf_token", "")})
    # Never cache authentication state: a cached logged-out response can make the
    # teacher/results page ask for credentials again after the admin has signed in.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.post("/api/admin/session/logout")
def admin_session_logout():
    session.clear()
    response = jsonify({"ok": True})
    response.delete_cookie("exam_portal_admin_token", path="/", secure=True, httponly=True, samesite="Lax")
    return response



def student_required():
    return bool(session.get("student_name") and session.get("student_class"))


def normalize_student_class(value):
    value = str(value).strip()
    match = __import__("re").fullmatch(r"class\s*(1[0-2]|[1-9])", value, flags=__import__("re").IGNORECASE)
    return f"Class {match.group(1)}" if match else ""


@app.before_request
def protect_student_mutations():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    if request.endpoint in ("student_login", "admin_session_login", "admin_session_logout"):
        return None
    if request.path.startswith(("/api/student/", "/api/exams/", "/api/attempts/")) and student_required():
        expected = session.get("csrf_token", "")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            return error("Your session security token is missing or expired. Please sign in again.", 403)
    if request.path.startswith("/api/admin/") and session.get("admin_authenticated"):
        expected = session.get("admin_csrf_token", "")
        supplied = request.headers.get("X-Admin-CSRF", "")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            return error("Admin session security token is missing or expired. Please sign in again.", 403)
    return None


@app.post("/api/student/login")
@limiter.limit("8 per minute")
def student_login():
    data = request.get_json(silent=True) or {}
    name = str(data.get("full_name", "")).strip()
    student_class = normalize_student_class(data.get("student_class", ""))
    password = str(data.get("password", ""))
    if not name or not student_class or len(name) > 120 or len(student_class) > 60 or not password:
        return error("Enter your student name, class and examination password")
    if not STUDENT_EXAM_PASSWORD or not hmac.compare_digest(password, STUDENT_EXAM_PASSWORD):
        return error("Incorrect examination password", 401)
    # Authentication is independent of exam scheduling. Students can always sign in;
    # the exam list and start endpoint enforce each exam's live availability window.
    session.clear()
    session["student_name"] = name
    session["student_class"] = student_class
    session["authorized_exam_id"] = None
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    return jsonify({
        "ok": True,
        "student": {"full_name": name, "student_class": student_class},
        "exam_id": session["authorized_exam_id"],
        "csrf_token": session["csrf_token"],
    })


@app.get("/api/student/me")
def student_me():
    if not student_required():
        return error("Student sign-in required", 401)
    return jsonify({"ok": True, "student": {
        "full_name": session["student_name"],
        "student_class": session["student_class"]
    }, "exam_id": session.get("authorized_exam_id"), "csrf_token": session.get("csrf_token", "")})


@app.post("/api/student/logout")
def student_logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api")
def api_info():
    return jsonify({
        "name": "Exam Portal V2",
        "status": "online",
        "api": {
            "health": "/health",
            "public_exams": "GET /api/exams",
            "start_exam": "POST /api/exams/<exam_id>/start",
            "save_answer": "PUT /api/attempts/<attempt_id>/answers/<question_id>",
            "submit": "POST /api/attempts/<attempt_id>/submit",
            "result": "GET /api/attempts/<attempt_id>/result",
            "admin_create_exam": "POST /api/admin/exams (X-Admin-Key required)",
            "admin_list_exams": "GET /api/admin/exams (X-Admin-Key required)",
            "admin_publish_exam": "POST /api/admin/exams/<exam_id>/publish (X-Admin-Key required)"
        }
    })


@app.get("/health")
def health():
    if not DATABASE_URL:
        return jsonify({"ok": False, "database": "not_configured"}), 503
    try:
        with db() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
        return jsonify({"ok": True, "database": "connected"})
    except Exception:
        app.logger.exception("Database health check failed")
        return jsonify({"ok": False, "database": "unavailable"}), 503


@app.get("/api/exams")
def public_exams():
    if not student_required():
        return error("Student sign-in required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT e.id, e.title, e.subject, NULL::text AS target_class, e.topic, e.difficulty,
                   e.duration_minutes, e.review_minutes, e.total_marks, e.published_at,
                   e.available_from, e.available_until, true AS has_password,
                   EXISTS (
                     SELECT 1 FROM portal_v2_attempts a
                     WHERE a.exam_id=e.id
                       AND lower(btrim(a.student_name)) = lower(btrim(%s))
                       AND lower(btrim(a.student_class)) = lower(btrim(%s))
                       AND a.status <> 'in_progress'
                   ) AS already_submitted,
                   EXISTS (
                     SELECT 1 FROM portal_v2_attempts a
                     WHERE a.exam_id=e.id
                       AND lower(btrim(a.student_name)) = lower(btrim(%s))
                       AND lower(btrim(a.student_class)) = lower(btrim(%s))
                       AND a.status = 'in_progress'
                   ) AS already_started
            FROM portal_v2_exams e
            WHERE e.status = 'live' AND e.available_from <= now() AND now() < e.available_until
            ORDER BY e.published_at DESC NULLS LAST
        """, (session["student_name"], session["student_class"],
              session["student_name"], session["student_class"]))
        return jsonify({"ok": True, "exams": cur.fetchall()})


@app.get("/api/admin/exams")
def admin_list_exams():
    if not admin_required():
        return error("Admin authentication required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT e.id, e.title, e.subject, e.target_class, e.topic,
                   e.difficulty, CASE WHEN e.status='live' AND e.available_until <= now() THEN 'closed' ELSE e.status END AS status, e.duration_minutes, e.review_minutes,
                   e.total_marks, e.created_at, e.published_at,
                   e.availability_days, e.available_from, e.available_until,
                   COUNT(q.id)::int AS question_count
            FROM portal_v2_exams e
            LEFT JOIN portal_v2_questions q ON q.exam_id=e.id
            WHERE e.status NOT IN ('archived','deleted')
            GROUP BY e.id
            ORDER BY e.created_at DESC
        """)
        return jsonify({"ok": True, "exams": cur.fetchall()})


@app.post("/api/admin/exams")
@limiter.limit("60 per minute")
def create_exam():
    if not admin_required():
        return error("Admin authentication required", 401)
    data = request.get_json(silent=True) or {}
    idempotency_key = request.headers.get("Idempotency-Key", "").strip() or None
    if idempotency_key and len(idempotency_key) > 200:
        return error("Idempotency-Key must be 200 characters or fewer")
    required = ["title", "subject", "topic", "duration_minutes", "questions"]
    if any(k not in data for k in required):
        return error("Required fields: title, subject, topic, duration_minutes, questions")
    questions = data["questions"]
    if not isinstance(questions, list) or not questions:
        return error("At least one question is required")
    try:
        duration = int(data["duration_minutes"])
        review = int(data.get("review_minutes", 0))
        if not 1 <= duration <= 300 or not 0 <= review <= 120:
            return error("Duration must be 1–300 minutes; review time 0–120")
        total = sum(float(q.get("marks", 1)) for q in questions)
        exam_id = str(uuid.uuid4())
        if not STUDENT_EXAM_PASSWORD:
            return error("STUDENT_EXAM_PASSWORD is not configured on the server", 500)
        password_hash = generate_password_hash(STUDENT_EXAM_PASSWORD)
        availability_days = int(data.get("availability_days", 3))
        if not 1 <= availability_days <= 30:
            return error("Availability must be between 1 and 30 days")
        availability_start = data.get("availability_start")
        availability_end = data.get("availability_end")
        if bool(availability_start) != bool(availability_end):
            return error("Provide both availability_start and availability_end, or neither.")
        if availability_start:
            try:
                availability_start = datetime.fromisoformat(str(availability_start).replace("Z", "+00:00"))
                availability_end = datetime.fromisoformat(str(availability_end).replace("Z", "+00:00"))
                if availability_start.tzinfo is None or availability_end.tzinfo is None:
                    return error("Availability timestamps must include a timezone offset (for example +05:30).")
                availability_start = availability_start.astimezone(timezone.utc)
                availability_end = availability_end.astimezone(timezone.utc)
                if availability_end <= availability_start:
                    return error("Availability end must be later than availability start.")
            except (TypeError, ValueError):
                return error("Use valid ISO 8601 availability timestamps with timezone offsets.")
        with db() as conn, conn.cursor() as cur:
            if idempotency_key:
                # Serialize duplicate requests across workers before checking/inserting.
                cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (idempotency_key,))
                cur.execute("""
                    SELECT e.id, e.status, COUNT(q.id)::int AS question_count, e.total_marks
                    FROM portal_v2_exams e
                    LEFT JOIN portal_v2_questions q ON q.exam_id=e.id
                    WHERE e.idempotency_key=%s
                    GROUP BY e.id
                """, (idempotency_key,))
                existing = cur.fetchone()
                if existing:
                    return jsonify({"ok": True, "exam_id": existing["id"], "status": existing["status"],
                                    "question_count": existing["question_count"], "total_marks": existing["total_marks"],
                                    "idempotent_replay": True}), 200
            cur.execute("""
                INSERT INTO portal_v2_exams
                (id, title, subject, target_class, topic, difficulty, status,
                 exam_password_hash, duration_minutes, review_minutes, total_marks, availability_days,
                 available_from, available_until, idempotency_key)
                VALUES (%s, %s, %s, %s, %s, %s, 'draft', %s, %s, %s, %s, %s, %s, %s, %s)
            """, (exam_id, data["title"], data["subject"], data.get("target_class"),
                  data["topic"], data.get("difficulty", "moderate"), password_hash,
                  duration, review, total, availability_days, availability_start, availability_end, idempotency_key))
            for index, q in enumerate(questions, start=1):
                qtype = q.get("question_type", "mcq")
                if qtype not in ("mcq", "saq"):
                    raise ValueError("Only MCQ and SAQ questions are supported. LAQs are not allowed.")
                cur.execute("""
                    INSERT INTO portal_v2_questions
                    (exam_id, position, question_type, prompt, options,
                     correct_option, expected_answer, marking_scheme, marks)
                    VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb, %s)
                """, (exam_id, index, qtype, q["prompt"],
                      __import__("json").dumps(q.get("options")) if q.get("options") is not None else None,
                      q.get("correct_option"), q.get("expected_answer", ""),                      __import__("json").dumps(q.get("marking_scheme", {})),                      float(q.get("marks", 1))))
            cur.execute("""
                INSERT INTO portal_v2_audit_log (actor, action, entity_type, entity_id, details)
                VALUES ('admin', 'exam_created', 'exam', %s, %s::jsonb)
            """, (exam_id, __import__("json").dumps({"question_count": len(questions)})))
        return jsonify({"ok": True, "exam_id": exam_id, "status": "draft",
                        "question_count": len(questions), "total_marks": total}), 201
    except (KeyError, TypeError, ValueError) as exc:
        return error(str(exc))
    except Exception:
        app.logger.exception("Exam creation failed")
        return error("Could not create exam", 500)


@app.post("/api/admin/exams/<exam_id>/publish")
@limiter.limit("60 per minute")
def publish_exam(exam_id):
    if not admin_required():
        return error("Admin authentication required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM portal_v2_questions WHERE exam_id=%s", (exam_id,))
        if cur.fetchone()["n"] == 0:
            return error("An exam must contain questions before publishing")
        cur.execute("SELECT exam_password_hash, availability_days, available_from, available_until, status FROM portal_v2_exams WHERE id=%s", (exam_id,))
        password_row = cur.fetchone()
        if password_row and password_row["status"] == "live":
            return jsonify({"ok": True, "exam_id": exam_id, "status": "live",
                            "available_from": password_row["available_from"],
                            "available_until": password_row["available_until"],
                            "idempotent_replay": True})
        if not password_row or not password_row["exam_password_hash"]:
            return error("The fixed student password is not configured for this exam", 500)
        now = datetime.now(timezone.utc)
        starts_at = password_row["available_from"] or now
        ends_at = password_row["available_until"] or (starts_at + timedelta(days=password_row["availability_days"] or 3))
        if ends_at <= starts_at:
            return error("Availability end must be later than availability start.")
        if ends_at <= now:
            return error("This exam's availability end is already in the past.")
        cur.execute("""
            UPDATE portal_v2_exams
            SET status='live', published_at=now(),
                available_from=%s, available_until=%s
            WHERE id=%s AND status IN ('draft','paused') RETURNING id
        """, (starts_at, ends_at, exam_id))
        if not cur.fetchone():
            return error("Exam not found or cannot be published", 404)
        cur.execute("UPDATE portal_v2_exams SET pdf_enabled=TRUE WHERE id=%s", (exam_id,))
        cur.execute("""
            INSERT INTO portal_v2_audit_log (actor, action, entity_type, entity_id)
            VALUES ('admin', 'exam_published', 'exam', %s)
        """, (exam_id,))
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT available_from, available_until FROM portal_v2_exams WHERE id=%s", (exam_id,))
        window = cur.fetchone()
    return jsonify({"ok": True, "exam_id": exam_id, "status": "live",
                    "available_from": window["available_from"], "available_until": window["available_until"]})


@app.post("/api/admin/exams/<exam_id>/delete")
def delete_exam(exam_id):
    if not admin_required():
        return error("Admin authentication required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, status FROM portal_v2_exams WHERE id=%s AND status <> 'deleted' FOR UPDATE", (exam_id,))
        exam = cur.fetchone()
        if not exam:
            return error("Exam not found or already removed", 404)
        # Removing an exam from the portals must NOT erase completed student
        # work. Keep submitted/evaluated attempts, answers, evaluations, and the
        # exam questions so students can still view/download their results for
        # the full five-minute + 48-hour result-access window.
        # Only unfinished attempts are discarded because they have no result.
        cur.execute("""
            DELETE FROM portal_v2_evaluations
            WHERE attempt_id IN (
                SELECT id FROM portal_v2_attempts
                WHERE exam_id=%s AND status='in_progress'
            )
        """, (exam_id,))
        cur.execute("""
            DELETE FROM portal_v2_answers
            WHERE attempt_id IN (
                SELECT id FROM portal_v2_attempts
                WHERE exam_id=%s AND status='in_progress'
            )
        """, (exam_id,))
        cur.execute("""
            DELETE FROM portal_v2_attempts
            WHERE exam_id=%s AND status='in_progress'
        """, (exam_id,))
        deleted_attempts = cur.rowcount
        cur.execute("""
            SELECT COUNT(*)::int AS preserved_results
            FROM portal_v2_attempts
            WHERE exam_id=%s
              AND status IN ('submitted', 'evaluated')
              AND submitted_at IS NOT NULL
        """, (exam_id,))
        preserved_results = cur.fetchone()["preserved_results"]
        # Soft-delete the exam definition. Questions remain attached to it and
        # are needed to render the complete student answer review.
        cur.execute("""
            UPDATE portal_v2_exams
            SET status='deleted', pdf_enabled=FALSE, pdf_cleared_at=now()
            WHERE id=%s
        """, (exam_id,))
        cur.execute("""
            INSERT INTO portal_v2_audit_log (actor, action, entity_type, entity_id)
            VALUES ('admin', 'exam_deleted_results_preserved', 'exam', %s)
        """, (exam_id,))
    return jsonify({"ok": True, "exam_id": exam_id, "status": "deleted",
                    "deleted_in_progress_attempts": deleted_attempts,
                    "preserved_student_results": preserved_results,
                    "message": "The examination was removed from the portals. Completed student results and answer reviews have been preserved."})


@app.post("/api/exams/<exam_id>/start")
def start_exam(exam_id):
    if not student_required():
        return error("Please sign in first", 401)
    data = request.get_json(silent=True) or {}
    with db() as conn, conn.cursor() as cur:
        name, student_class = session["student_name"], session["student_class"]
        # One attempt per exam and case-insensitive student name + class.
        # A different class is treated as a separate student identity.
        lock_key = f"{exam_id}:{name.strip().casefold()}:{student_class.strip().casefold()}"
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_key,))
        cur.execute("""
            SELECT id, status, exam_deadline, review_deadline
            FROM portal_v2_attempts
            WHERE exam_id=%s
              AND lower(btrim(student_name)) = lower(btrim(%s))
              AND lower(btrim(student_class)) = lower(btrim(%s))
            ORDER BY started_at ASC
            LIMIT 1
            FOR UPDATE
        """, (exam_id, name, student_class))
        previous_attempt = cur.fetchone()
        if previous_attempt:
            if previous_attempt["status"] == "in_progress":
                now_check = datetime.now(timezone.utc)
                if now_check > previous_attempt["review_deadline"]:
                    cur.execute("""
                        UPDATE portal_v2_attempts
                        SET status='submitted', submitted_at=COALESCE(submitted_at, now())
                        WHERE id=%s AND status='in_progress'
                    """, (previous_attempt["id"],))
                    cur.execute("UPDATE portal_v2_answers SET is_final=true WHERE attempt_id=%s", (previous_attempt["id"],))
                    return error("Your previous attempt has expired and has been submitted. Retakes are not allowed.", 409)
                return error("You have already started this exam. Please resume your existing attempt from My examinations.", 409)
            return error("You have already submitted this exam. Each student can take an exam only once.", 409)
        cur.execute("""
            SELECT id, target_class, exam_password_hash, duration_minutes, review_minutes, available_from,
                   available_until, available_until AS student_until
            FROM portal_v2_exams WHERE id=%s AND status='live' AND available_from <= now()
              AND now() < available_until
        """, (exam_id,))
        exam = cur.fetchone()
        if not exam:
            return error("Exam not found or not currently live", 404)
        if exam["student_until"] <= datetime.now(timezone.utc):
            return error("The student examination window has closed. The remaining time is reserved for teacher review.", 403)
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        exam_deadline = min(now + timedelta(minutes=exam["duration_minutes"]), exam["student_until"])
        review_deadline = min(exam_deadline + timedelta(minutes=exam["review_minutes"]), exam["student_until"])
        cur.execute("""
            INSERT INTO portal_v2_attempts
            (exam_id, student_name, student_class, student_session_id,
             exam_deadline, review_deadline)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, started_at, exam_deadline, review_deadline
        """, (exam_id, name, student_class, session_id, exam_deadline, review_deadline))
        attempt = cur.fetchone()
        cur.execute("""
            SELECT id, position, question_type, prompt, options, marks
            FROM portal_v2_questions WHERE exam_id=%s ORDER BY position
        """, (exam_id,))
        return jsonify({"ok": True, "attempt": attempt, "questions": cur.fetchall()}), 201




@app.get("/api/attempts/<attempt_id>/resume")
def resume_attempt(attempt_id):
    if not student_required():
        return error("Student sign-in required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.id, a.status, a.exam_deadline, a.review_deadline,
                   e.id AS exam_id, e.title, e.subject, e.topic, e.available_from, e.available_until, e.status AS exam_status
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE a.id=%s
              AND lower(btrim(a.student_name)) = lower(btrim(%s))
              AND lower(btrim(a.student_class)) = lower(btrim(%s))
            FOR UPDATE OF a
        """, (attempt_id, session["student_name"], session["student_class"]))
        attempt = cur.fetchone()
        if not attempt:
            return error("Attempt not found", 404)
        if attempt["status"] != "in_progress":
            return error("This attempt is no longer in progress", 409)
        now = datetime.now(timezone.utc)
        if attempt["exam_status"] != "live" or now < attempt["available_from"] or now >= attempt["available_until"]:
            cur.execute("UPDATE portal_v2_attempts SET status='submitted', submitted_at=now() WHERE id=%s AND status='in_progress'", (attempt_id,))
            cur.execute("UPDATE portal_v2_answers SET is_final=true WHERE attempt_id=%s", (attempt_id,))
            return error("The examination availability window has closed.", 409)
        if now > attempt["review_deadline"]:
            cur.execute("""
                UPDATE portal_v2_attempts
                SET status='submitted', submitted_at=now()
                WHERE id=%s AND status='in_progress'
            """, (attempt_id,))
            cur.execute("UPDATE portal_v2_answers SET is_final=true WHERE attempt_id=%s", (attempt_id,))
            return error("The answer window has closed. Your saved answers have been submitted.", 409)
        cur.execute("""
            SELECT q.id, q.position, q.question_type, q.prompt, q.options, q.marks,
                   ans.answer_text, ans.selected_option
            FROM portal_v2_questions q
            LEFT JOIN portal_v2_answers ans
              ON ans.question_id=q.id AND ans.attempt_id=%s
            WHERE q.exam_id=%s
            ORDER BY q.position
        """, (attempt_id, attempt["exam_id"]))
        questions = cur.fetchall()
    return jsonify({"ok": True, "attempt": attempt, "questions": questions})


@app.put("/api/attempts/<attempt_id>/answers/<question_id>")
def save_answer(attempt_id, question_id):
    if not student_required():
        return error("Student sign-in required", 401)
    data = request.get_json(silent=True) or {}
    answer_text = data.get("answer_text")
    selected_option = data.get("selected_option")
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.status, a.review_deadline, q.id, e.available_from,
                   e.available_until AS student_until, e.status AS exam_status
            FROM portal_v2_attempts a
            JOIN portal_v2_questions q ON q.exam_id=a.exam_id
            JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE a.id=%s AND q.id=%s AND a.student_name=%s AND a.student_class=%s
            FOR UPDATE OF a
        """, (attempt_id, question_id, session["student_name"], session["student_class"]))
        row = cur.fetchone()
        if not row:
            return error("Attempt or question not found", 404)
        if row["status"] != "in_progress":
            return error("The answer window has closed", 409)
        if row["exam_status"] != "live" or datetime.now(timezone.utc) < row["available_from"] or datetime.now(timezone.utc) >= row["student_until"]:
            cur.execute("UPDATE portal_v2_attempts SET status='submitted', submitted_at=now() WHERE id=%s AND status='in_progress'", (attempt_id,))
            cur.execute("UPDATE portal_v2_answers SET is_final=true WHERE attempt_id=%s", (attempt_id,))
            return error("The examination availability window has closed.", 409)
        if datetime.now(timezone.utc) > row["review_deadline"]:
            cur.execute("""
                UPDATE portal_v2_attempts
                SET status='submitted', submitted_at=now()
                WHERE id=%s AND status='in_progress'
            """, (attempt_id,))
            cur.execute("UPDATE portal_v2_answers SET is_final=true WHERE attempt_id=%s", (attempt_id,))
            return error("The deadline passed. Your saved answers have been submitted.", 409)
        cur.execute("""
            INSERT INTO portal_v2_answers
            (attempt_id, question_id, answer_text, selected_option, is_final, saved_at)
            VALUES (%s, %s, %s, %s, false, now())
            ON CONFLICT (attempt_id, question_id) DO UPDATE SET
              answer_text=EXCLUDED.answer_text,
              selected_option=EXCLUDED.selected_option,
              saved_at=now()
        """, (attempt_id, question_id, answer_text, selected_option))
    return jsonify({"ok": True, "saved": True})


def _normalize_marking_text(value):
    import re
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", str(value or "").lower())).strip()


def _auto_mark_saq(answer, expected_answer, marking_scheme, maximum_marks):
    """Conservative SAQ auto-marker. Returns (marks, feedback) or None for teacher review."""
    normalized = _normalize_marking_text(answer)
    if not normalized:
        return 0.0, "Automatically marked: no answer was provided."
    scheme = marking_scheme if isinstance(marking_scheme, dict) else {}
    criteria = scheme.get("criteria")
    if isinstance(criteria, list) and criteria:
        earned = 0.0
        notes = []
        for criterion in criteria:
            if not isinstance(criterion, dict):
                continue
            try:
                weight = float(criterion.get("marks", 0))
            except (TypeError, ValueError):
                continue
            if weight <= 0:
                continue
            required = [str(x).strip().lower() for x in criterion.get("keywords", []) if str(x).strip()]
            any_of = [str(x).strip().lower() for x in criterion.get("any_of", []) if str(x).strip()]
            required_ok = all(_normalize_marking_text(term) in normalized for term in required)
            any_ok = not any_of or any(_normalize_marking_text(term) in normalized for term in any_of)
            if required_ok and any_ok:
                earned += weight
                notes.append(str(criterion.get("description") or "Criterion met"))
        earned = min(float(maximum_marks), earned)
        return earned, ("Automatically marked against the supplied criteria. Met: " + (", ".join(notes) if notes else "no rubric criteria") + ".")
    expected = _normalize_marking_text(expected_answer)
    if expected:
        if normalized == expected:
            return float(maximum_marks), "Automatically marked: the answer matches the supplied answer key."
        return 0.0, "Automatically marked: the answer does not match the supplied answer key."
    return 0.0, "Automatically marked: no answer key or marking criteria were configured; zero awarded."


@app.post("/api/attempts/<attempt_id>/submit")
def submit_attempt(attempt_id):
    if not student_required():
        return error("Student sign-in required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.status, a.review_deadline, e.available_from,
                   e.available_until AS student_until, e.status AS exam_status
            FROM portal_v2_attempts a JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE a.id=%s AND a.student_name=%s AND a.student_class=%s FOR UPDATE OF a
        """, (attempt_id, session["student_name"], session["student_class"]))
        row = cur.fetchone()
        if not row:
            return error("Attempt not found", 404)
        if row["status"] != "in_progress":
            return error("Attempt already submitted", 409)
        expired = (datetime.now(timezone.utc) < row["available_from"] or datetime.now(timezone.utc) >= row["student_until"] or row["exam_status"] != "live" or datetime.now(timezone.utc) > row["review_deadline"])
        cur.execute("""
            UPDATE portal_v2_attempts SET status='submitted', submitted_at=now()
            WHERE id=%s AND student_name=%s AND student_class=%s AND status='in_progress'
        """, (attempt_id, session["student_name"], session["student_class"]))
        cur.execute("UPDATE portal_v2_answers SET is_final=true WHERE attempt_id=%s", (attempt_id,))
        # Auto-grade every question and release a provisional result immediately. LAQs start at zero and can be adjusted later.
        cur.execute("""
            SELECT q.id AS question_id, q.question_type, q.correct_option,
                   q.expected_answer, q.marking_scheme, q.marks,
                   ans.selected_option, ans.answer_text
            FROM portal_v2_questions q
            LEFT JOIN portal_v2_answers ans
              ON ans.question_id=q.id AND ans.attempt_id=%s
            JOIN portal_v2_attempts a ON a.exam_id=q.exam_id
            WHERE a.id=%s
            ORDER BY q.position
        """, (attempt_id, attempt_id))
        for q in cur.fetchall():
            auto_marks = None
            feedback = ""
            if q["question_type"] == "mcq":
                auto_marks = float(q["marks"]) if q["selected_option"] and q["selected_option"] == q["correct_option"] else 0.0
                feedback = "Automatically marked: correct option." if auto_marks else "Automatically marked: incorrect or unanswered."
            elif q["question_type"] == "saq":
                scheme = q["marking_scheme"] or {}
                if isinstance(scheme, str):
                    try:
                        scheme = __import__("json").loads(scheme)
                    except Exception:
                        scheme = {}
                auto_marks, feedback = _auto_mark_saq(q["answer_text"], q["expected_answer"], scheme, q["marks"])
            elif q["question_type"] == "laq":
                # Long answers also receive a numeric automatic mark from the configured
                # rubric/reference answer. If no key exists, record zero with an explicit
                # note rather than leaving the result pending.
                scheme = q["marking_scheme"] or {}
                if isinstance(scheme, str):
                    try:
                        scheme = __import__("json").loads(scheme)
                    except Exception:
                        scheme = {}
                auto_marks, feedback = _auto_mark_saq(
                    q["answer_text"], q["expected_answer"], scheme, q["marks"]
                )
                if not q["expected_answer"] and not scheme:
                    feedback = "Automatically evaluated: no answer key or marking criteria were configured; zero awarded. Teacher may review."
            else:
                auto_marks = 0.0
                feedback = "Automatically evaluated: unsupported question type; zero awarded. Teacher may review."
            cur.execute("""
                INSERT INTO portal_v2_evaluations
                (attempt_id, question_id, ai_marks, final_marks, ai_feedback,
                 reviewed_by, reviewed_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, 'AutoMark', now(), now())
                ON CONFLICT (attempt_id, question_id) DO UPDATE SET
                  ai_marks=EXCLUDED.ai_marks, final_marks=EXCLUDED.final_marks,
                  ai_feedback=EXCLUDED.ai_feedback, reviewed_by='AutoMark',
                  reviewed_at=now(), updated_at=now()
            """, (attempt_id, q["question_id"], auto_marks, auto_marks, feedback))
        cur.execute("UPDATE portal_v2_attempts SET status='evaluated', evaluated_at=now() WHERE id=%s", (attempt_id,))
        # A new submission after the teacher cleared PDFs makes this exam's
        # dynamically generated individual and ranking PDFs available again.
        cur.execute("""
            UPDATE portal_v2_exams
            SET pdf_enabled=TRUE
            WHERE id=(SELECT exam_id FROM portal_v2_attempts WHERE id=%s)
              AND status='live' AND available_from <= now() AND now() < available_until
        """, (attempt_id,))
    return jsonify({"ok": True, "status": "evaluated", "result_released": True, "auto_submitted": expired})


def _student_result_attempt(cur, attempt_id):
    cur.execute("""
        SELECT a.id, a.status, a.student_name, a.student_class, a.started_at,
               a.submitted_at, a.evaluated_at, e.title AS exam_title,
               e.subject, e.total_marks,
               a.submitted_at + interval '5 minutes' AS result_available_at,
               a.submitted_at + interval '53 hours' AS result_expires_at,
               COALESCE((SELECT SUM(ev.final_marks)
                         FROM portal_v2_evaluations ev
                         WHERE ev.attempt_id=a.id), 0)::float AS obtained_marks
        FROM portal_v2_attempts a
        JOIN portal_v2_exams e ON e.id=a.exam_id
        WHERE a.id=%s
          AND lower(btrim(a.student_name)) = lower(btrim(%s))
          AND lower(btrim(a.student_class)) = lower(btrim(%s))
    """, (attempt_id, session["student_name"], session["student_class"]))
    return cur.fetchone()


def _student_result_questions(cur, attempt_id):
    cur.execute("""
        SELECT q.id AS question_id, q.position, q.question_type, q.prompt,
               q.options, q.correct_option, q.expected_answer,
               q.marks AS maximum_marks, ans.answer_text, ans.selected_option,
               COALESCE(ev.final_marks, ev.ai_marks, 0)::float AS awarded_marks,
               COALESCE(ev.teacher_feedback, ev.ai_feedback, '') AS feedback
        FROM portal_v2_questions q
        JOIN portal_v2_attempts a ON a.exam_id=q.exam_id
        LEFT JOIN portal_v2_answers ans
          ON ans.question_id=q.id AND ans.attempt_id=a.id
        LEFT JOIN portal_v2_evaluations ev
          ON ev.question_id=q.id AND ev.attempt_id=a.id
        WHERE a.id=%s
        ORDER BY q.position
    """, (attempt_id,))
    return cur.fetchall()


def _student_result_gate(attempt):
    if not attempt or attempt["status"] not in ("submitted", "evaluated") or not attempt["submitted_at"]:
        return error("Submitted result not found", 404)
    now = datetime.now(timezone.utc)
    available_at = attempt["result_available_at"]
    expires_at = attempt["result_expires_at"]
    if now < available_at:
        return error("Your result will be available five minutes after submission.", 425)
    if now >= expires_at:
        return error("The 48-hour student result access period has ended.", 410)
    return None


@app.get("/api/attempts/<attempt_id>/result")
def attempt_result(attempt_id):
    if not student_required():
        return error("Student sign-in required", 401)
    with db() as conn, conn.cursor() as cur:
        attempt = _student_result_attempt(cur, attempt_id)
        denied = _student_result_gate(attempt)
        if denied:
            return denied
        questions = _student_result_questions(cur, attempt_id)
    total = float(attempt["total_marks"] or 0)
    obtained = float(attempt["obtained_marks"] or 0)
    percentage = (obtained / total * 100) if total else 0
    for q in questions:
        maximum = float(q["maximum_marks"] or 0)
        awarded = float(q["awarded_marks"] or 0)
        if q["question_type"] == "mcq":
            q["is_correct"] = bool(q["selected_option"] and
                                   str(q["selected_option"]).strip().upper() ==
                                   str(q["correct_option"] or "").strip().upper())
            q["answer_status"] = "Correct" if q["is_correct"] else "Incorrect"
        elif awarded >= maximum and maximum > 0:
            q["answer_status"] = "Correct"
        elif awarded > 0:
            q["answer_status"] = "Partially correct"
        else:
            q["answer_status"] = "Incorrect"
    return jsonify({
        "ok": True, "attempt": attempt, "questions": questions,
        "summary": {"obtained_marks": obtained, "total_marks": total,
                    "percentage": round(percentage, 2)}
    })


@app.get("/api/attempts/<attempt_id>/result.pdf")
def download_student_result_pdf(attempt_id):
    if not student_required():
        return error("Student sign-in required", 401)
    with db() as conn, conn.cursor() as cur:
        attempt = _student_result_attempt(cur, attempt_id)
        denied = _student_result_gate(attempt)
        if denied:
            return denied
        questions = _student_result_questions(cur, attempt_id)

    from xml.sax.saxutils import escape
    import unicodedata
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

    clean = lambda value: unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")
    total = float(attempt["total_marks"] or 0)
    obtained = float(attempt["obtained_marks"] or 0)
    percentage = (obtained / total * 100) if total else 0
    submitted = attempt["submitted_at"]
    if submitted.tzinfo is None:
        submitted = submitted.replace(tzinfo=timezone.utc)
    submitted_text = submitted.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%d %B %Y, %I:%M %p IST")
    expiry = attempt["result_expires_at"].astimezone(ZoneInfo("Asia/Kolkata")).strftime("%d %B %Y, %I:%M %p IST")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("StudentResultTitle", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#172554"), fontSize=18, leading=23, spaceAfter=6)
    meta_style = ParagraphStyle("StudentResultMeta", parent=styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#334155"))
    q_style = ParagraphStyle("StudentResultQuestion", parent=styles["Normal"], fontSize=10, leading=14, spaceAfter=5)
    small_style = ParagraphStyle("StudentResultSmall", parent=styles["Normal"], fontSize=9, leading=12, leftIndent=10)
    story = [
        Paragraph("EXAMINATION RESULT & ANSWER REVIEW", title_style),
        Paragraph(escape(clean(attempt["exam_title"])), ParagraphStyle("StudentExamName", parent=meta_style, alignment=TA_CENTER, fontSize=11, spaceAfter=14)),
    ]
    summary = [
        ["Student", clean(attempt["student_name"]), "Class", clean(attempt["student_class"])],
        ["Marks obtained", f"{obtained:g}", "Total marks", f"{total:g}"],
        ["Percentage", f"{percentage:.2f}%", "Submitted", submitted_text],
        ["Student access until", expiry, "", ""],
    ]
    table = Table(summary, colWidths=[100, 160, 75, 145])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),
        ("BACKGROUND", (2, 0), (2, 1), colors.HexColor("#eef2ff")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), .5, colors.HexColor("#d8deeb")),
        ("SPAN", (1, 3), (3, 3)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story += [table, Spacer(1, 18), Paragraph("COMPLETE QUESTION PAPER & ANSWER REVIEW", styles["Heading2"]), Spacer(1, 6)]
    for idx, q in enumerate(questions, 1):
        maximum = float(q["maximum_marks"] or 0)
        awarded = float(q["awarded_marks"] or 0)
        status = q.get("answer_status")
        if not status:
            if q["question_type"] == "mcq":
                status = "Correct" if q["selected_option"] and str(q["selected_option"]).strip().upper() == str(q["correct_option"] or "").strip().upper() else "Incorrect"
            elif awarded >= maximum and maximum > 0:
                status = "Correct"
            elif awarded > 0:
                status = "Partially correct"
            else:
                status = "Incorrect"
        parts = [Paragraph(f'<b>Q{idx}. {escape(clean(q["prompt"]))}</b> <font color="#64748b">({maximum:g} marks)</font>', q_style)]
        opts = q["options"] or []
        opt_items = list(opts.items()) if isinstance(opts, dict) else [(chr(65+i), val) for i, val in enumerate(opts)] if isinstance(opts, list) else []
        for key, value in opt_items:
            selected = str(q["selected_option"] or "").strip().upper() == str(key).strip().upper()
            correct = str(q["correct_option"] or "").strip().upper() == str(key).strip().upper()
            suffix = " — Your answer" if selected else ""
            suffix += " — Correct answer" if correct else ""
            parts.append(Paragraph(f'{"[x]" if selected else "[ ]"} {escape(clean(key))}. {escape(clean(value))}{escape(suffix)}', small_style))
        if q["question_type"] != "mcq":
            parts.append(Paragraph("<b>Your answer:</b> " + escape(clean(q["answer_text"] or "Not answered")), small_style))
            parts.append(Paragraph("<b>Reference answer:</b> " + escape(clean(q["expected_answer"] or "No reference answer configured")), small_style))
        elif not q["selected_option"]:
            parts.append(Paragraph("<b>Your answer:</b> Not answered", small_style))
        if q["question_type"] == "mcq":
            correct_text = next((str(v) for k, v in opt_items if str(k).strip().upper() == str(q["correct_option"] or "").strip().upper()), "")
            parts.append(Paragraph("<b>Correct answer:</b> " + escape(clean((str(q["correct_option"] or "") + ". " + correct_text).strip(". "))), small_style))
        parts.append(Paragraph(f'<b>Result:</b> {escape(status)} &nbsp;&nbsp; <b>Marks awarded:</b> {awarded:g} / {maximum:g}', small_style))
        if q["feedback"]:
            parts.append(Paragraph("<b>Feedback:</b> " + escape(clean(q["feedback"])), small_style))
        story.append(KeepTogether(parts))
        story.append(Spacer(1, 10))

    def branding(canvas, page_doc):
        width, height = A4
        canvas.saveState()
        canvas.translate(width/2, height/2)
        canvas.rotate(35)
        canvas.setFillColor(colors.HexColor("#cbd5e1"))
        if hasattr(canvas, "setFillAlpha"):
            canvas.setFillAlpha(.10)
        canvas.setFont("Helvetica-Bold", 27)
        canvas.drawCentredString(0, 0, "Abhishek Santra English Guidance")
        canvas.restoreState()
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#475569"))
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawRightString(width-42, 22, "Abhishek Santra English Guidance")
        canvas.restoreState()
    doc.build(story, onFirstPage=branding, onLaterPages=branding)
    buffer.seek(0)
    safe_name = "".join(ch for ch in str(attempt["student_name"]) if ch.isalnum() or ch in (" ", "-", "_")).strip().replace(" ", "_") or "student"
    response = send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name=f"{safe_name}_exam_result_review.pdf")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.get("/api/student/attempts")
def student_attempts():
    if not student_required():
        return error("Student sign-in required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.id, a.status, a.started_at, a.submitted_at, a.evaluated_at,
                   e.title AS exam_title, e.subject, e.total_marks,
                   a.submitted_at + interval '5 minutes' AS result_available_at,
                   a.submitted_at + interval '53 hours' AS result_expires_at,
                   CASE WHEN a.status='evaluated' THEN
                     COALESCE((SELECT SUM(ev.final_marks)
                               FROM portal_v2_evaluations ev
                               WHERE ev.attempt_id=a.id), 0)::float
                   ELSE NULL END AS obtained_marks
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE lower(btrim(a.student_name)) = lower(btrim(%s))
              AND lower(btrim(a.student_class)) = lower(btrim(%s))
              AND (
                a.status='in_progress'
                OR (a.status IN ('submitted', 'evaluated')
                    AND a.submitted_at IS NOT NULL
                    AND now() < a.submitted_at + interval '53 hours')
              )
            ORDER BY a.started_at DESC
        """, (session["student_name"], session["student_class"]))
        return jsonify({"ok": True, "attempts": cur.fetchall()})




@app.get("/teacher")
def teacher_portal():
    return render_template("teacher.html")


def _auto_evaluate_pending_attempts(cur):
    """Backfill automatic marks for submitted attempts created before auto-grading completed."""
    cur.execute("""
        SELECT a.id FROM portal_v2_attempts a
        WHERE a.status IN ('submitted', 'evaluated')
          AND (
               EXISTS (
                   SELECT 1 FROM portal_v2_evaluations ev
                   WHERE ev.attempt_id=a.id AND ev.final_marks IS NULL
                     AND ev.reviewed_by='AutoMark'
               )
               OR EXISTS (
                   SELECT 1 FROM portal_v2_questions q
                   WHERE q.exam_id=a.exam_id
                     AND NOT EXISTS (
                         SELECT 1 FROM portal_v2_evaluations ev
                         WHERE ev.attempt_id=a.id AND ev.question_id=q.id
                     )
               )
          )
        ORDER BY a.submitted_at
    """)
    pending = [row["id"] for row in cur.fetchall()]
    for attempt_id in pending:
        cur.execute("""
            SELECT q.id AS question_id, q.question_type, q.correct_option,
                   q.expected_answer, q.marking_scheme, q.marks,
                   ans.selected_option, ans.answer_text
            FROM portal_v2_questions q
            JOIN portal_v2_attempts a ON a.exam_id=q.exam_id
            LEFT JOIN portal_v2_answers ans ON ans.question_id=q.id AND ans.attempt_id=a.id
            WHERE a.id=%s ORDER BY q.position
        """, (attempt_id,))
        for q in cur.fetchall():
            if q["question_type"] == "mcq":
                marks = float(q["marks"]) if q["selected_option"] and str(q["selected_option"]).strip().upper() == str(q["correct_option"] or "").strip().upper() else 0.0
                feedback = "Automatically marked using the MCQ answer key."
            elif q["question_type"] == "saq":
                scheme = q["marking_scheme"] or {}
                if isinstance(scheme, str):
                    try:
                        scheme = __import__("json").loads(scheme)
                    except Exception:
                        scheme = {}
                marks, feedback = _auto_mark_saq(q["answer_text"], q["expected_answer"], scheme, q["marks"])
            else:
                marks, feedback = 0.0, "Automatically marked: no supported answer key for this question type."
            cur.execute("""
                INSERT INTO portal_v2_evaluations
                (attempt_id, question_id, ai_marks, final_marks, ai_feedback,
                 reviewed_by, reviewed_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, 'AutoMark', now(), now())
                ON CONFLICT (attempt_id, question_id) DO UPDATE SET
                    ai_marks=EXCLUDED.ai_marks,
                    final_marks=EXCLUDED.final_marks,
                    ai_feedback=EXCLUDED.ai_feedback,
                    reviewed_at=now(), updated_at=now()
                WHERE portal_v2_evaluations.reviewed_by='AutoMark'
                  AND portal_v2_evaluations.final_marks IS NULL
            """, (attempt_id, q["question_id"], marks, marks, feedback))
        cur.execute("UPDATE portal_v2_attempts SET status='evaluated', evaluated_at=COALESCE(evaluated_at, now()) WHERE id=%s", (attempt_id,))


def _apply_teacher_exam_visibility_cleanup(cur):
    """
    One-time cleanup requested for the teacher exam forum:
    retain all currently live exams and the named archived exam only.
    Future archived exams remain visible after this marker is recorded.
    """
    cur.execute("""
        CREATE TABLE IF NOT EXISTS portal_v2_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    marker = "teacher_exam_forum_cleanup_2026_11_21"
    cur.execute("SELECT setting_value FROM portal_v2_settings WHERE setting_key=%s", (marker,))
    if cur.fetchone():
        return

    cur.execute("""
        SELECT id FROM portal_v2_exams
        WHERE status='archived'
          AND title <> %s
        FOR UPDATE
    """, ("Tense and Parts of Speech Assessment",))
    remove_ids = [row["id"] for row in cur.fetchall()]
    if remove_ids:
        cur.execute("""
            DELETE FROM portal_v2_evaluations
            WHERE attempt_id IN (
                SELECT id FROM portal_v2_attempts WHERE exam_id = ANY(%s)
            )
        """, (remove_ids,))
        cur.execute("""
            DELETE FROM portal_v2_answers
            WHERE attempt_id IN (
                SELECT id FROM portal_v2_attempts WHERE exam_id = ANY(%s)
            )
        """, (remove_ids,))
        cur.execute("DELETE FROM portal_v2_attempts WHERE exam_id = ANY(%s)", (remove_ids,))
        cur.execute("""
            UPDATE portal_v2_exams
            SET status='deleted', pdf_enabled=FALSE, pdf_cleared_at=now()
            WHERE id = ANY(%s) AND status='archived'
        """, (remove_ids,))
    cur.execute("""
        INSERT INTO portal_v2_settings (setting_key, setting_value, updated_at)
        VALUES (%s, %s, now())
        ON CONFLICT (setting_key) DO NOTHING
    """, (marker, "completed"))


@app.get("/api/teacher/exams")
def teacher_exam_overview():
    with db() as conn, conn.cursor() as cur:
        _apply_teacher_exam_visibility_cleanup(cur)
        cur.execute("""
            SELECT e.id, e.title, e.subject, e.status, e.available_from, e.available_until,
                   COUNT(a.id) FILTER (
                       WHERE a.status IN ('submitted', 'evaluated')
                         AND a.submitted_at IS NOT NULL
                         AND (e.pdf_cleared_at IS NULL OR a.submitted_at > e.pdf_cleared_at)
                   )::int AS submission_count
            FROM portal_v2_exams e
            LEFT JOIN portal_v2_attempts a ON a.exam_id=e.id
            WHERE e.status <> 'deleted'
            GROUP BY e.id
            ORDER BY e.created_at DESC
        """)
        return jsonify({"ok": True, "exams": cur.fetchall()})


@app.get("/api/admin/attempts")
def admin_list_attempts():
    with db() as conn, conn.cursor() as cur:
        # Never let a grading/backfill problem hide the submissions list.
        try:
            _auto_evaluate_pending_attempts(cur)
        except Exception:
            app.logger.exception("Automatic grading backfill failed; returning submissions anyway")
            conn.rollback()
        cur.execute("""
            SELECT a.id, a.student_name, a.student_class, a.status,
                   a.started_at, a.submitted_at, e.id AS exam_id,
                   e.title AS exam_title, e.subject, e.total_marks,
                   (e.pdf_enabled AND (e.pdf_cleared_at IS NULL OR a.submitted_at > e.pdf_cleared_at)) AS pdf_available,
                   COALESCE(SUM(ev.final_marks), 0)::float AS obtained_marks
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            LEFT JOIN portal_v2_evaluations ev ON ev.attempt_id=a.id
            WHERE a.status IN ('submitted', 'evaluated')
              AND a.submitted_at IS NOT NULL
              AND (e.pdf_cleared_at IS NULL OR a.submitted_at > e.pdf_cleared_at)
              AND (CAST(%s AS TEXT) IS NULL OR e.id::text = %s)
            GROUP BY a.id, e.id
            ORDER BY a.submitted_at DESC NULLS LAST, a.started_at DESC
        """, (request.args.get("exam_id") or None, request.args.get("exam_id") or None))
        return jsonify({"ok": True, "attempts": cur.fetchall()})


@app.get("/api/admin/attempts/<attempt_id>")
def admin_attempt_detail(attempt_id):
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.id, a.student_name, a.student_class, a.status,
                   a.started_at, a.submitted_at, e.title AS exam_title,
                   e.subject, e.total_marks
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE a.id=%s
              AND (e.pdf_cleared_at IS NULL OR a.submitted_at > e.pdf_cleared_at)
        """, (attempt_id,))
        attempt = cur.fetchone()
        if not attempt:
            return error("Attempt not found", 404)
        cur.execute("""
            SELECT q.id AS question_id, q.position, q.question_type,
                   q.prompt, q.options, q.correct_option, q.expected_answer,
                   q.marking_scheme, q.marks AS maximum_marks,
                   ans.answer_text, ans.selected_option,
                   ev.ai_marks, ev.final_marks, ev.ai_feedback, ev.teacher_feedback, ev.reviewed_by
            FROM portal_v2_questions q
            JOIN portal_v2_attempts a ON a.exam_id=q.exam_id
            LEFT JOIN portal_v2_answers ans
              ON ans.question_id=q.id AND ans.attempt_id=a.id
            LEFT JOIN portal_v2_evaluations ev
              ON ev.question_id=q.id AND ev.attempt_id=a.id
            WHERE a.id=%s ORDER BY q.position
        """, (attempt_id,))
        return jsonify({"ok": True, "attempt": attempt, "questions": cur.fetchall()})


@app.post("/api/admin/attempts/<attempt_id>/evaluate")
@limiter.limit("60 per minute")
def evaluate_attempt(attempt_id):
    # Teacher review workspace is intentionally accessible without a separate sign-in.
    # Keep strict validation and rate limiting on this write endpoint.
    data = request.get_json(silent=True) or {}
    evaluations = data.get("evaluations")
    reviewer = str(data.get("reviewer", "Teacher")).strip()[:120] or "Teacher"
    if not isinstance(evaluations, list):
        return error("Evaluations must be provided as a list")
    try:
        with db() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT a.status FROM portal_v2_attempts a
                JOIN portal_v2_exams e ON e.id=a.exam_id
                WHERE a.id=%s AND e.status='live'
                  AND e.available_from IS NOT NULL AND e.available_from <= now()
                  AND e.available_until IS NOT NULL AND now() < e.available_until
                FOR UPDATE OF a
            """, (attempt_id,))
            attempt = cur.fetchone()
            if not attempt:
                return error("Attempt not found", 404)
            if attempt["status"] not in ("submitted", "evaluated"):
                return error("Only submitted attempts can be reviewed", 409)
            cur.execute("SELECT id, marks FROM portal_v2_questions WHERE exam_id=(SELECT exam_id FROM portal_v2_attempts WHERE id=%s)", (attempt_id,))
            maxima = {str(row["id"]): float(row["marks"]) for row in cur.fetchall()}
            seen = set()
            for item in evaluations:
                qid = str(item.get("question_id", ""))
                if qid not in maxima or qid in seen:
                    return error("Invalid or duplicate question in evaluation")
                cur.execute("SELECT question_type FROM portal_v2_questions WHERE id=%s", (qid,))
                question_type = cur.fetchone()["question_type"]
                seen.add(qid)
                marks = float(item.get("final_marks", 0))
                if marks < 0 or marks > maxima[qid]:
                    return error("Marks must be between zero and the question maximum")
                feedback = str(item.get("teacher_feedback", ""))[:4000]
                cur.execute("""
                    INSERT INTO portal_v2_evaluations
                    (attempt_id, question_id, ai_marks, final_marks, teacher_feedback,
                     reviewed_by, reviewed_at, updated_at)
                    VALUES (%s, %s, NULL, %s, %s, %s, now(), now())
                    ON CONFLICT (attempt_id, question_id) DO UPDATE SET
                      final_marks=EXCLUDED.final_marks,
                      teacher_feedback=EXCLUDED.teacher_feedback,
                      reviewed_by=EXCLUDED.reviewed_by,
                      reviewed_at=now(), updated_at=now()
                """, (attempt_id, qid, marks, feedback, reviewer))
            # Results are already released automatically at submission.
            # Teacher corrections may override automatic marks for MCQ, SAQ, and LAQ answers.
            cur.execute("UPDATE portal_v2_attempts SET status='evaluated', evaluated_at=now() WHERE id=%s", (attempt_id,))
            cur.execute("""
                INSERT INTO portal_v2_audit_log (actor, action, entity_type, entity_id)
                VALUES (%s, 'attempt_evaluated', 'attempt', %s)
            """, (reviewer, attempt_id))
        return jsonify({"ok": True, "status": "evaluated"})
    except (TypeError, ValueError):
        return error("Marks must be valid numbers")
    except Exception:
        app.logger.exception("Attempt evaluation failed")
        return error("Could not save evaluation", 500)


@app.get("/api/admin/attempts/<attempt_id>/result.pdf")
def download_attempt_result_pdf(attempt_id):
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.id, a.student_name, a.student_class, a.status,
                   a.submitted_at, e.title AS exam_title, e.total_marks, e.pdf_enabled,
                   e.pdf_cleared_at
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE a.id=%s
        """, (attempt_id,))
        result = cur.fetchone()
        if not result:
            return error("Attempt not found", 404)
        if not result["pdf_enabled"]:
            return error("PDF downloads for this exam have been cleared by the teacher.", 410)
        if result["pdf_cleared_at"] and (not result["submitted_at"] or result["submitted_at"] <= result["pdf_cleared_at"]):
            return error("This result PDF was cleared by the teacher.", 410)
        if result["status"] != "evaluated":
            return error("The result PDF is available after marks are finalised.", 409)
        cur.execute("""
            SELECT q.position, q.question_type, q.prompt, q.options,
                   q.marks AS maximum_marks, ans.answer_text, ans.selected_option,
                   ev.final_marks, ev.ai_marks
            FROM portal_v2_questions q
            JOIN portal_v2_attempts a ON a.exam_id=q.exam_id
            LEFT JOIN portal_v2_answers ans
              ON ans.question_id=q.id AND ans.attempt_id=a.id
            LEFT JOIN portal_v2_evaluations ev
              ON ev.question_id=q.id AND ev.attempt_id=a.id
            WHERE a.id=%s
            ORDER BY q.position
        """, (attempt_id,))
        question_rows = cur.fetchall()
        cur.execute("""
            SELECT COALESCE(SUM(ev.final_marks), 0) AS obtained_marks,
                   COALESCE(SUM(q.marks), 0) AS total_marks
            FROM portal_v2_questions q
            JOIN portal_v2_attempts a ON a.exam_id=q.exam_id
            LEFT JOIN portal_v2_evaluations ev
              ON ev.question_id=q.id AND ev.attempt_id=a.id
            WHERE a.id=%s
        """, (attempt_id,))
        marks = cur.fetchone()

    from xml.sax.saxutils import escape
    import unicodedata
    pdf_text = lambda value: unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib import colors
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

    def add_pdf_branding(canvas, doc):
        page_width, page_height = A4
        canvas.saveState()
        canvas.translate(page_width / 2, page_height / 2)
        canvas.rotate(35)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        if hasattr(canvas, "setFillAlpha"):
            canvas.setFillAlpha(0.5)
        watermark = "Abhishek Santra English Guidance"
        canvas.setFont("Helvetica-Bold", 30)
        canvas.drawCentredString(0, 0, watermark)
        canvas.restoreState()
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#475569"))
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawRightString(page_width - 42, 22, "Checked By Abhishek Santra")
        canvas.restoreState()

    submitted = result["submitted_at"]
    if submitted:
        if submitted.tzinfo is None:
            submitted = submitted.replace(tzinfo=timezone.utc)
        submitted_text = submitted.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%d %B %Y, %I:%M %p IST")
    else:
        submitted_text = "Not available"

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("DetailedResultTitle", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#172554"), fontSize=18, leading=23, spaceAfter=6)
    meta_style = ParagraphStyle("DetailedResultMeta", parent=styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#334155"))
    q_style = ParagraphStyle("QuestionText", parent=styles["Normal"], fontSize=10, leading=14, spaceAfter=5)
    small_style = ParagraphStyle("OptionText", parent=styles["Normal"], fontSize=9, leading=12, leftIndent=10)
    story = [
        Paragraph("EXAMINATION RESULT", title_style),
        Paragraph(escape(pdf_text(result["exam_title"])), ParagraphStyle("ExamName", parent=meta_style, alignment=TA_CENTER, fontSize=11, spaceAfter=14)),
    ]
    summary = [
        ["Student", pdf_text(result["student_name"]), "Class", pdf_text(result["student_class"])],
        ["Marks obtained", f'{float(marks["obtained_marks"]):g}', "Total marks", f'{float(marks["total_marks"]):g}'],
        ["Submitted", submitted_text, "", ""],
    ]
    summary_table = Table(summary, colWidths=[85, 175, 75, 145])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),
        ("BACKGROUND", (2, 0), (2, 1), colors.HexColor("#eef2ff")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), .5, colors.HexColor("#d8deeb")),
        ("SPAN", (1, 2), (3, 2)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story += [summary_table, Spacer(1, 18), Paragraph("QUESTIONS AND STUDENT RESPONSES", styles["Heading2"]), Spacer(1, 6)]
    for idx, q in enumerate(question_rows, 1):
        parts = [Paragraph(f'<b>Q{idx}. {escape(pdf_text(q["prompt"]))}</b> <font color="#64748b">({float(q["maximum_marks"]):g} marks)</font>', q_style)]
        opts = q["options"] or []
        if isinstance(opts, dict):
            opt_items = list(opts.items())
        elif isinstance(opts, list):
            opt_items = [(chr(65+i), val) for i, val in enumerate(opts)]
        else:
            opt_items = []
        for key, value in opt_items:
            selected = str(q["selected_option"] or "").strip().upper() == str(key).strip().upper()
            prefix = "[x]" if selected else "[ ]"
            parts.append(Paragraph(f'{prefix} {escape(pdf_text(key))}. {escape(pdf_text(value))}' + ("  <b>(Selected)</b>" if selected else ""), small_style))
        if q["question_type"] == "mcq":
            if not opt_items:
                parts.append(Paragraph("Options: not available", small_style))
            if not q["selected_option"]:
                parts.append(Paragraph("<b>Selected option:</b> Not answered", small_style))
        else:
            parts.append(Paragraph("<b>Student answer:</b> " + escape(pdf_text(q["answer_text"] or "Not answered")), small_style))
        awarded = q["final_marks"] if q["final_marks"] is not None else (q["ai_marks"] or 0)
        parts.append(Paragraph(f'<b>Marks awarded:</b> {float(awarded):g} / {float(q["maximum_marks"]):g}', small_style))
        story.append(KeepTogether(parts))
        story.append(Spacer(1, 10))
    doc.build(story, onFirstPage=add_pdf_branding, onLaterPages=add_pdf_branding)
    buffer.seek(0)
    safe_name = "".join(ch for ch in str(result["student_name"]) if ch.isalnum() or ch in (" ", "-", "_")).strip().replace(" ", "_") or "student"
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name=f"{safe_name}_exam_result.pdf")


@app.get("/api/admin/pdfs/status")
def admin_pdf_status():
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT EXISTS(SELECT 1 FROM portal_v2_exams WHERE pdf_enabled=TRUE) AS enabled")
        state = cur.fetchone()
    return jsonify({"ok": True, "enabled": bool(state["enabled"])})


@app.post("/api/admin/pdfs/delete-all")
def admin_delete_all_pdfs():
    if not admin_required():
        return error("Admin authentication required", 401)
    with db() as conn, conn.cursor() as cur:
        # This is a global reset: remove every student's attempt, saved answer,
        # and evaluation across every exam. Exam definitions/questions remain.
        cur.execute("""
            DELETE FROM portal_v2_evaluations
            WHERE attempt_id IN (SELECT id FROM portal_v2_attempts)
        """)
        cur.execute("""
            DELETE FROM portal_v2_answers
            WHERE attempt_id IN (SELECT id FROM portal_v2_attempts)
        """)
        cur.execute("DELETE FROM portal_v2_attempts")
        deleted_attempts = cur.rowcount
        # Keep all exams usable; new submissions will appear in the portal and PDFs.
        cur.execute("UPDATE portal_v2_exams SET pdf_enabled=TRUE, pdf_cleared_at=NULL")
    response = jsonify({
        "ok": True,
        "enabled": True,
        "deleted_attempts": deleted_attempts,
        "message": "All student submissions, answers, marks, and results have been deleted across every exam."
    })
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.post("/api/admin/exams/<exam_id>/submissions/delete")
def admin_delete_exam_submissions(exam_id):
    if not admin_required():
        return error("Admin authentication required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM portal_v2_exams WHERE id=%s", (exam_id,))
        if not cur.fetchone():
            return error("Examination not found", 404)
        cur.execute("""
            DELETE FROM portal_v2_evaluations
            WHERE attempt_id IN (SELECT id FROM portal_v2_attempts WHERE exam_id=%s)
        """, (exam_id,))
        cur.execute("""
            DELETE FROM portal_v2_answers
            WHERE attempt_id IN (SELECT id FROM portal_v2_attempts WHERE exam_id=%s)
        """, (exam_id,))
        cur.execute("DELETE FROM portal_v2_attempts WHERE exam_id=%s", (exam_id,))
        deleted_attempts = cur.rowcount
        cur.execute("UPDATE portal_v2_exams SET pdf_enabled=TRUE, pdf_cleared_at=NULL WHERE id=%s", (exam_id,))
    response = jsonify({
        "ok": True,
        "deleted_attempts": deleted_attempts,
        "message": "All submissions and results for this examination have been deleted."
    })
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/api/admin/rankings.pdf")
def download_all_student_rankings_pdf():
    with db() as conn, conn.cursor() as cur:
        _auto_evaluate_pending_attempts(cur)
        cur.execute("""
            SELECT e.id AS exam_id, e.title AS exam_title, e.target_class,
                   e.total_marks, a.student_name, a.student_class, a.submitted_at,
                   COALESCE(SUM(ev.final_marks), 0)::float AS obtained_marks
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            LEFT JOIN portal_v2_evaluations ev ON ev.attempt_id=a.id
            WHERE a.status IN ('submitted', 'evaluated') AND a.submitted_at IS NOT NULL
              AND e.pdf_enabled=TRUE
              AND (e.pdf_cleared_at IS NULL OR a.submitted_at > e.pdf_cleared_at)
              AND (CAST(%s AS TEXT) IS NULL OR e.id::text = %s)
            GROUP BY e.id, a.id
            ORDER BY e.title ASC, obtained_marks DESC, a.submitted_at ASC NULLS LAST, a.student_name ASC
        """, (request.args.get("exam_id") or None, request.args.get("exam_id") or None))
        records = cur.fetchall()

    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas as pdf_canvas
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from xml.sax.saxutils import escape
    import unicodedata

    W, H = A4
    navy = colors.HexColor("#12396d")
    blue = colors.HexColor("#2362aa")
    mid_blue = colors.HexColor("#6e9bd3")
    pale_blue = colors.HexColor("#cfe2fb")
    grid_blue = colors.HexColor("#7f9fc9")
    pdf_text = lambda value: unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")

    buffer = io.BytesIO()
    c = pdf_canvas.Canvas(buffer, pagesize=A4)

    def centered_fit(text, x, y, max_width, font, size, color):
        text = pdf_text(text)
        while size > 6 and stringWidth(text, font, size) > max_width:
            size -= .5
        c.setFillColor(color)
        c.setFont(font, size)
        c.drawCentredString(x, y, text)

    def draw_book(cx, cy, scale=1):
        c.saveState()
        c.setFillColor(navy)
        c.setStrokeColor(navy)
        c.setLineWidth(1.5*scale)
        # Two open pages and a central spine, matching the reference logo.
        p = c.beginPath()
        p.moveTo(cx, cy-8*scale); p.curveTo(cx-9*scale, cy-2*scale, cx-18*scale, cy+5*scale, cx-29*scale, cy+3*scale)
        p.lineTo(cx-29*scale, cy+24*scale); p.curveTo(cx-17*scale, cy+27*scale, cx-8*scale, cy+20*scale, cx, cy+15*scale); p.close()
        c.drawPath(p, fill=1, stroke=0)
        p = c.beginPath()
        p.moveTo(cx, cy-8*scale); p.curveTo(cx+9*scale, cy-2*scale, cx+18*scale, cy+5*scale, cx+29*scale, cy+3*scale)
        p.lineTo(cx+29*scale, cy+24*scale); p.curveTo(cx+17*scale, cy+27*scale, cx+8*scale, cy+20*scale, cx, cy+15*scale); p.close()
        c.drawPath(p, fill=1, stroke=0)
        c.setStrokeColor(colors.white)
        c.setLineWidth(1.1*scale)
        c.line(cx, cy-5*scale, cx, cy+18*scale)
        c.restoreState()

    def draw_cap(cx, cy, scale=1):
        c.saveState()
        c.setFillColor(navy)
        p=c.beginPath()
        p.moveTo(cx-18*scale,cy+3*scale); p.lineTo(cx,cy+12*scale); p.lineTo(cx+18*scale,cy+3*scale); p.lineTo(cx,cy-5*scale); p.close()
        c.drawPath(p,fill=1,stroke=0)
        c.setFillColor(navy)
        c.rect(cx-10*scale,cy-8*scale,20*scale,4*scale,fill=1,stroke=0)
        c.setStrokeColor(navy); c.setLineWidth(1.2*scale)
        c.line(cx+14*scale,cy+4*scale,cx+17*scale,cy-8*scale)
        c.circle(cx+17*scale,cy-10*scale,1.7*scale,fill=1,stroke=0)
        c.restoreState()

    def draw_watermark():
        c.saveState()
        c.translate(W/2, H/2-5)
        c.rotate(34)
        try:
            c.setFillAlpha(.008)
        except Exception:
            pass
        c.setFillColor(colors.HexColor("#c8d8e8"))
        c.setFont("Times-Bold", 35)
        c.drawCentredString(0, 0, "Abhishek Santra English Guidance")
        c.restoreState()

    def draw_page_header(exam_title):
        # Pale corner ribbons and white page, matching the supplied portrait sheet.
        c.setFillColor(colors.HexColor("#f9fbff")); c.rect(0,0,W,H,fill=1,stroke=0)
        c.saveState()
        c.setStrokeColor(colors.HexColor("#a9c9f1")); c.setLineWidth(8)
        p=c.beginPath(); p.moveTo(0,H-76); p.curveTo(28,H-45,62,H-20,112,H); c.drawPath(p,stroke=1,fill=0)
        p=c.beginPath(); p.moveTo(W,H-76); p.curveTo(W-28,H-45,W-62,H-20,W-112,H); c.drawPath(p,stroke=1,fill=0)
        p=c.beginPath(); p.moveTo(0,76); p.curveTo(28,45,62,20,112,0); c.drawPath(p,stroke=1,fill=0)
        p=c.beginPath(); p.moveTo(W,76); p.curveTo(W-28,45,W-62,20,W-112,0); c.drawPath(p,stroke=1,fill=0)
        c.setStrokeColor(colors.HexColor("#d1e2f8")); c.setLineWidth(3)
        p=c.beginPath(); p.moveTo(0,H-92); p.curveTo(38,H-55,75,H-25,125,H); c.drawPath(p,stroke=1,fill=0)
        p=c.beginPath(); p.moveTo(W,H-92); p.curveTo(W-38,H-55,W-75,H-25,W-125,H); c.drawPath(p,stroke=1,fill=0)
        c.restoreState()

        draw_book(103,H-42,.72)
        c.setFillColor(navy); c.setFont("Times-Bold",25)
        c.drawString(146,H-34,"Abhishek Santra English Guidance")
        c.setStrokeColor(blue); c.setLineWidth(1.1)
        c.line(146,H-46, W-28,H-46)
        draw_cap(W/2,H-55,.72)

        # Blue pill title and thin frame with a deliberate gap behind the title.
        c.setFillColor(blue); c.roundRect(W/2-110,H-101,220,31,16,fill=1,stroke=0)
        centered_fit("Exam Ranking",W/2,H-91,205,"Times-Bold",19,colors.white)
        c.setStrokeColor(grid_blue); c.setLineWidth(1)
        c.roundRect(13,15,W-26,H-119,10,fill=0,stroke=1)
        c.line(13,H-108,W/2-120,H-108)
        c.line(W/2+120,H-108,W-13,H-108)
        if exam_title:
            centered_fit(exam_title,W/2,H-126,W-80,"Helvetica-Bold",8.5,navy)

    # Column positions mirror the five-column reference grid.
    x0=23; x1=90; x2=245; x3=305; x4=420; x5=W-23
    table_top=H-157
    header_h=25
    row_h=19.35
    rows_per_page=30
    grouped={}
    for row in records:
        grouped.setdefault(str(row["exam_id"]),[]).append(row)

    if not grouped:
        draw_page_header("")
        c.setFillColor(navy); c.setFont("Helvetica",11)
        c.drawCentredString(W/2,H/2,"No submitted student results are available yet.")
        draw_watermark()
        c.showPage()

    for exam_id, rows in grouped.items():
        chunks=[rows[i:i+rows_per_page] for i in range(0,len(rows),rows_per_page)] or [[]]
        for chunk_index, chunk in enumerate(chunks):
            exam_title=pdf_text(chunk[0]["exam_title"] if chunk else "")
            draw_page_header(exam_title)
            top=table_top
            # Keep the watermark behind every table fill and text so it never obscures results.
            draw_watermark()
            # Header cells.
            c.setFillColor(pale_blue); c.roundRect(x0,top-header_h,x5-x0,header_h,6,fill=1,stroke=0)
            c.setFillColor(navy); c.setFont("Helvetica-Bold",9)
            c.drawCentredString((x0+x1)/2,top-16,"Rank")
            c.drawCentredString((x1+x2)/2,top-16,"Name")
            c.drawCentredString((x2+x3)/2,top-16,"Class")
            c.drawCentredString((x3+x4)/2,top-16,"Obtained / Total")
            c.drawCentredString((x4+x5)/2,top-16,"Submission Time")

            for idx,row in enumerate(chunk):
                y_top=top-header_h-idx*row_h
                y_bottom=y_top-row_h
                global_rank=chunk_index*rows_per_page+idx+1
                # Rounded highlight bands for the first three ranks.
                medal=[colors.HexColor("#ffe7a6"),colors.HexColor("#e5e8ee"),colors.HexColor("#f7d9c3")]
                if global_rank<=3:
                    c.setFillColor(medal[global_rank-1])
                    c.roundRect(x0+1,y_bottom+1,x5-x0-2,row_h-2,7,fill=1,stroke=0)
                c.setFillColor(colors.HexColor("#101828")); c.setFont("Helvetica-Bold" if global_rank<=3 else "Helvetica",10)
                c.drawCentredString((x0+x1)/2,y_bottom+6.2,str(global_rank))
                name=pdf_text(row["student_name"])
                centered_fit(name,(x1+x2)/2,y_bottom+6.2,x2-x1-12,"Helvetica-Bold",9.5,colors.HexColor("#101828"))
                centered_fit(pdf_text(row["student_class"]),(x2+x3)/2,y_bottom+6.2,x3-x2-8,"Helvetica",9.5,colors.HexColor("#101828"))
                obtained=float(row["obtained_marks"] or 0)
                total=float(row["total_marks"] or 0)
                c.setFillColor(navy); c.setFont("Helvetica-Bold",10)
                c.drawCentredString((x3+x4)/2,y_bottom+6.2,f"{obtained:g} / {total:g}")
                submitted=row["submitted_at"]
                if submitted:
                    if submitted.tzinfo is None:
                        submitted=submitted.replace(tzinfo=timezone.utc)
                    date_text=submitted.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%d %b %Y, %I:%M %p")
                else:
                    date_text=""
                centered_fit(date_text,(x4+x5)/2,y_bottom+6.2,x5-x4-10,"Helvetica",8.5,colors.HexColor("#101828"))

            # Fine blue table grid, drawn over the watermark like the reference.
            table_bottom=top-header_h-len(chunk)*row_h
            c.saveState()
            c.setStrokeColor(grid_blue); c.setLineWidth(.45)
            for xx in (x0,x1,x2,x3,x4,x5):
                c.line(xx,table_bottom,xx,top)
            c.line(x0,top,x5,top)
            c.line(x0,top-header_h,x5,top-header_h)
            for ri in range(1,len(chunk)+1):
                yy=top-header_h-ri*row_h
                c.line(x0,yy,x5,yy)
            c.restoreState()
            c.showPage()

    c.save()
    buffer.seek(0)
    response=send_file(buffer,mimetype="application/pdf",as_attachment=True,download_name="student_rankings.pdf")
    response.headers["Cache-Control"]="no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"]="no-cache"
    return response

@app.errorhandler(404)
def not_found(_):
    return error("Route not found", 404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))