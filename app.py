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
            cur.execute("""
                INSERT INTO portal_v2_exams
                (id, title, subject, target_class, topic, difficulty, status,
                 exam_password_hash, duration_minutes, review_minutes, total_marks, availability_days,
                 available_from, available_until)
                VALUES (%s, %s, %s, %s, %s, %s, 'draft', %s, %s, %s, %s, %s, %s, %s)
            """, (exam_id, data["title"], data["subject"], data.get("target_class"),
                  data["topic"], data.get("difficulty", "moderate"), password_hash,
                  duration, review, total, availability_days, availability_start, availability_end))
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
        cur.execute("SELECT exam_password_hash, availability_days, available_from, available_until FROM portal_v2_exams WHERE id=%s", (exam_id,))
        password_row = cur.fetchone()
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
        # Delete all exam-specific student data, including in-progress attempts.
        # The exam definition is retained internally with status='deleted' so
        # audit/history references remain valid, but it disappears from portals.
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
        cur.execute("""
            UPDATE portal_v2_exams
            SET status='deleted', pdf_enabled=FALSE, pdf_cleared_at=now()
            WHERE id=%s
        """, (exam_id,))
        cur.execute("""
            INSERT INTO portal_v2_audit_log (actor, action, entity_type, entity_id)
            VALUES ('admin', 'exam_deleted_with_submissions', 'exam', %s)
        """, (exam_id,))
    return jsonify({"ok": True, "exam_id": exam_id, "status": "deleted",
                    "deleted_attempts": deleted_attempts,
                    "message": "The examination and all its submissions, answers, marks, and results have been deleted."})


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


@app.get("/api/attempts/<attempt_id>/result")
def attempt_result(attempt_id):
    if not student_required():
        return error("Student sign-in required", 401)
    return error("Results are not available in the student portal.", 403)


@app.get("/api/student/attempts")
def student_attempts():
    if not student_required():
        return error("Student sign-in required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.id, a.status, a.started_at, a.submitted_at, a.evaluated_at,
                   e.title AS exam_title, e.subject, e.total_marks,
                   CASE WHEN a.status='evaluated' THEN
                     COALESCE((SELECT SUM(ev.final_marks)
                               FROM portal_v2_evaluations ev
                               WHERE ev.attempt_id=a.id), 0)
                   ELSE NULL END AS obtained_marks
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE lower(btrim(a.student_name)) = lower(btrim(%s))
              AND lower(btrim(a.student_class)) = lower(btrim(%s))
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
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    from reportlab.pdfgen import canvas as pdf_canvas
    from reportlab.lib.units import mm
    from xml.sax.saxutils import escape
    import unicodedata

    pdf_text = lambda value: unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")
    page_width, page_height = A4
    navy = colors.HexColor("#15396b")
    blue = colors.HexColor("#2463ad")
    pale_blue = colors.HexColor("#d9eaff")
    line_blue = colors.HexColor("#7298ca")

    class RankingWatermarkCanvas(pdf_canvas.Canvas):
        def showPage(self):
            # Overlay a light, diagonal watermark over all page content, as in the supplied reference.
            self.saveState()
            self.translate(page_width / 2, page_height / 2)
            self.rotate(34)
            self.setFillColor(colors.HexColor("#2b5f9d"))
            if hasattr(self, "setFillAlpha"):
                self.setFillAlpha(0.22)
            self.setFont("Helvetica-Bold", 34)
            self.drawCentredString(0, 0, "Abhishek Santra English Guidance")
            self.restoreState()
            super().showPage()

    def add_pdf_branding(canvas, doc):
        canvas.saveState()
        # Thin blue page frame and restrained corner accents.
        canvas.setStrokeColor(blue)
        canvas.setLineWidth(1.0)
        canvas.roundRect(13, 13, page_width - 26, page_height - 26, 11, stroke=1, fill=0)
        canvas.setStrokeColor(colors.HexColor("#8bb5e8"))
        canvas.setLineWidth(3)
        canvas.line(14, page_height - 25, 75, page_height - 25)
        canvas.line(page_width - 75, 25, page_width - 14, 25)
        canvas.setFillColor(colors.HexColor("#526b8d"))
        canvas.setFont("Helvetica", 7)
        canvas.drawCentredString(page_width / 2, 20, "Abhishek Santra English Guidance")
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, rightMargin=25*mm, leftMargin=25*mm,
        topMargin=12*mm, bottomMargin=13*mm
    )
    styles = getSampleStyleSheet()
    brand_style = ParagraphStyle(
        "RankingBrand", parent=styles["Title"], alignment=TA_CENTER,
        textColor=navy, fontName="Helvetica-Bold", fontSize=20, leading=23,
        spaceAfter=2
    )
    title_style = ParagraphStyle(
        "RankingHeading", parent=styles["Title"], alignment=TA_CENTER,
        textColor=colors.white, backColor=blue, fontName="Helvetica-Bold",
        fontSize=17, leading=22, borderRadius=18, borderPadding=(4, 20, 4, 20),
        spaceBefore=3, spaceAfter=12
    )
    exam_style = ParagraphStyle(
        "ExamHeading", parent=styles["Normal"], alignment=TA_CENTER,
        textColor=navy, fontName="Helvetica-Bold", fontSize=10, leading=13,
        spaceAfter=7
    )
    story = []
    grouped = {}
    for row in records:
        grouped.setdefault(str(row["exam_id"]), []).append(row)

    if not grouped:
        story.extend([
            Paragraph("Abhishek Santra English Guidance", brand_style),
            Spacer(1, 8),
            Paragraph("Exam Ranking", title_style),
            Paragraph("No submitted student results are available yet.", exam_style)
        ])

    for group_index, (exam_id, rows) in enumerate(grouped.items()):
        if group_index:
            story.append(PageBreak())
        first = rows[0]
        display_exam_title = pdf_text(first["exam_title"] or "")
        target_class = str(first.get("target_class") or "").strip()
        if target_class:
            for separator in (" — ", " – ", " - "):
                suffix = separator + target_class
                if display_exam_title.endswith(suffix):
                    display_exam_title = display_exam_title[:-len(suffix)].rstrip()
                    break

        story.extend([
            Paragraph("Abhishek Santra English Guidance", brand_style),
            Paragraph("Exam Ranking", title_style),
            Paragraph(escape(display_exam_title), exam_style)
        ])

        table_rows = [[
            Paragraph("<b>Rank</b>", styles["Normal"]),
            Paragraph("<b>Name</b>", styles["Normal"]),
            Paragraph("<b>Class</b>", styles["Normal"]),
            Paragraph("<b>Obtained / Total</b>", styles["Normal"]),
            Paragraph("<b>Submission Time</b>", styles["Normal"])
        ]]
        for rank, row in enumerate(rows, 1):
            obtained = float(row["obtained_marks"] or 0)
            total = float(row["total_marks"] or 0)
            submitted = row["submitted_at"]
            if submitted:
                if submitted.tzinfo is None:
                    submitted = submitted.replace(tzinfo=timezone.utc)
                submitted_text = submitted.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%d %b %Y, %I:%M %p")
            else:
                submitted_text = ""
            table_rows.append([
                str(rank),
                Paragraph(escape(pdf_text(row["student_name"])), styles["Normal"]),
                escape(pdf_text(row["student_class"])),
                Paragraph(f"<b>{obtained:g}</b> / {total:g}", styles["Normal"]),
                pdf_text(submitted_text)
            ])

        table = Table(
            table_rows, repeatRows=1,
            colWidths=[19*mm, 48*mm, 19*mm, 38*mm, 51*mm],
            rowHeights=[24] + [19.5] * len(rows)
        )
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), pale_blue),
            ("TEXTCOLOR", (0, 0), (-1, 0), navy),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.6),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#101828")),
            ("GRID", (0, 0), (-1, -1), 0.45, line_blue),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")]),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
            ("ALIGN", (3, 0), (3, -1), "CENTER"),
            ("ALIGN", (4, 0), (4, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3)
        ]
        # Highlight the leading three ranks with the reference's gold, silver and bronze tones.
        medal_backgrounds = [
            colors.HexColor("#fff0bd"),
            colors.HexColor("#e8ebf0"),
            colors.HexColor("#f8ddca")
        ]
        for medal_index, medal_color in enumerate(medal_backgrounds, 1):
            if medal_index <= len(rows):
                style_commands.append(("BACKGROUND", (0, medal_index), (-1, medal_index), medal_color))
                style_commands.append(("FONTNAME", (0, medal_index), (0, medal_index), "Helvetica-Bold"))
        table.setStyle(TableStyle(style_commands))
        story.append(table)

    doc.build(
        story, onFirstPage=add_pdf_branding, onLaterPages=add_pdf_branding,
        canvasmaker=RankingWatermarkCanvas
    )
    buffer.seek(0)
    response = send_file(
        buffer, mimetype="application/pdf", as_attachment=True,
        download_name="student_rankings.pdf"
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response

@app.errorhandler(404)
def not_found(_):
    return error("Route not found", 404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))