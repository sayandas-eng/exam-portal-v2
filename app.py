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
    """Archive expired exams without deleting student attempts, answers or results."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            UPDATE portal_v2_exams
            SET status='archived'
            WHERE status='live'
              AND available_until IS NOT NULL
              AND available_until <= now()
        """)


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


def admin_required():
    supplied = request.headers.get("X-Admin-Key", "")
    valid_admin = bool(ADMIN_API_KEY and supplied and hmac.compare_digest(supplied, ADMIN_API_KEY))
    mcp_token = os.getenv("MCP_API_TOKEN", "")
    valid_mcp = bool(mcp_token and supplied and hmac.compare_digest(supplied, mcp_token))
    return valid_admin or valid_mcp or bool(session.get("admin_authenticated"))


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
    return jsonify({"ok": True, "csrf_token": session["admin_csrf_token"]})


@app.get("/api/admin/session")
def admin_session_status():
    return jsonify({"ok": bool(session.get("admin_authenticated")), "csrf_token": session.get("admin_csrf_token", "")})


@app.post("/api/admin/session/logout")
def admin_session_logout():
    session.clear()
    return jsonify({"ok": True})



def student_required():
    return bool(session.get("student_name") and session.get("student_class"))


def normalize_student_class(value):
    value = str(value).strip()
    match = __import__("re").fullmatch(r"(?:class\s*)?(\d+)", value, flags=__import__("re").IGNORECASE)
    return f"Class {match.group(1)}" if match else value


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
    with db() as conn, conn.cursor() as cur:
        # A student may sign in only while an exam for their class is live.
        # This check is independent of prior attempts so students can still
        # access their history/results while another eligible exam is live.
        cur.execute("""
            SELECT e.id
            FROM portal_v2_exams e
            WHERE e.status='live'
              AND e.available_from <= now()
              AND e.available_until > now()
              AND (e.target_class IS NULL OR lower(trim(e.target_class)) = lower(%s))
            ORDER BY e.published_at DESC NULLS LAST
            LIMIT 1
        """, (student_class,))
        active_exam = cur.fetchone()
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM portal_v2_attempts a
                WHERE lower(trim(a.student_name)) = lower(trim(%s))
                  AND lower(trim(a.student_class)) = lower(trim(%s))
            ) AS has_history
        """, (name, student_class))
        has_history = cur.fetchone()["has_history"]
        if not active_exam and not has_history:
            return error("No examination is live for your class, and no previous examination record was found. Please try again when your teacher publishes an exam.", 403)

        cur.execute("""
            SELECT e.id
            FROM portal_v2_exams e
            WHERE e.status='live'
              AND e.available_from <= now()
              AND e.available_until > now()
              AND (e.target_class IS NULL OR lower(trim(e.target_class)) = lower(%s))
              AND NOT EXISTS (
                SELECT 1 FROM portal_v2_attempts a
                WHERE a.exam_id=e.id AND a.student_name=%s AND a.student_class=%s
              )
            ORDER BY e.published_at DESC NULLS LAST
            LIMIT 1
        """, (student_class, name, student_class))
        matched_exam = cur.fetchone()
    session.clear()
    session["student_name"] = name
    session["student_class"] = student_class
    session["authorized_exam_id"] = str(matched_exam["id"]) if matched_exam else None
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
            SELECT id, title, subject, NULL::text AS target_class, topic, difficulty,
                   duration_minutes, review_minutes, total_marks, published_at,
                   available_from, available_until, true AS has_password
            FROM portal_v2_exams
            WHERE status = 'live' AND available_from <= now() AND available_until > now()
              AND NOT EXISTS (
                SELECT 1 FROM portal_v2_attempts a
                WHERE a.exam_id=portal_v2_exams.id
                  AND a.student_name=%s AND a.student_class=%s
              )
            ORDER BY published_at DESC NULLS LAST
        """, (session["student_name"], session["student_class"]))
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
                if qtype not in ("mcq", "saq", "laq"):
                    raise ValueError("question_type must be mcq, saq, or laq")
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
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM portal_v2_attempts
                WHERE exam_id=%s AND status='in_progress'
            ) AS has_active_attempt
        """, (exam_id,))
        if cur.fetchone()["has_active_attempt"]:
            return error("This exam has students with an attempt in progress. Wait until they submit or their attempts expire before deleting it.", 409)
        cur.execute("""
            UPDATE portal_v2_exams
            SET status='deleted'
            WHERE id=%s AND status NOT IN ('archived','deleted')
            RETURNING id
        """, (exam_id,))
        if not cur.fetchone():
            return error("Exam not found or already removed", 404)
        cur.execute("""
            INSERT INTO portal_v2_audit_log (actor, action, entity_type, entity_id)
            VALUES ('admin', 'exam_deleted', 'exam', %s)
        """, (exam_id,))
    return jsonify({"ok": True, "exam_id": exam_id, "status": "deleted",
                    "records_preserved": True})


@app.post("/api/exams/<exam_id>/start")
def start_exam(exam_id):
    if not student_required():
        return error("Please sign in first", 401)
    data = request.get_json(silent=True) or {}
    with db() as conn, conn.cursor() as cur:
        name, student_class = session["student_name"], session["student_class"]
        # Serialize starts for the same exam/student pair so two simultaneous requests
        # cannot create duplicate attempts.
        lock_key = f"{exam_id}:{name.casefold()}:{student_class.casefold()}"
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_key,))
        cur.execute("""
            SELECT id, status, exam_deadline, review_deadline
            FROM portal_v2_attempts
            WHERE exam_id=%s AND student_name=%s AND student_class=%s
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
            SELECT id, target_class, exam_password_hash, duration_minutes, review_minutes, available_from, available_until
            FROM portal_v2_exams WHERE id=%s AND status='live' AND available_from <= now() AND available_until > now()
        """, (exam_id,))
        exam = cur.fetchone()
        if not exam:
            return error("Exam not found or not currently live", 404)
        if exam["available_until"] <= datetime.now(timezone.utc):
            return error("This examination's availability window has closed.", 403)
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        exam_deadline = min(now + timedelta(minutes=exam["duration_minutes"]), exam["available_until"])
        review_deadline = min(exam_deadline + timedelta(minutes=exam["review_minutes"]), exam["available_until"])
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
            WHERE a.id=%s AND a.student_name=%s AND a.student_class=%s
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
            SELECT a.status, a.review_deadline, q.id, e.available_from, e.available_until, e.status AS exam_status
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
        if row["exam_status"] != "live" or datetime.now(timezone.utc) < row["available_from"] or datetime.now(timezone.utc) >= row["available_until"]:
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
    return re.sub(r"\\s+", " ", re.sub(r"[^\\w\\s]", " ", str(value or "").lower())).strip()


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
            return float(maximum_marks), "Automatically marked: the answer matches the expected answer."
        return 0.0, "Automatically marked: the answer did not match the expected answer."
    return 0.0, "Automatically marked 0: no answer key or marking criteria were supplied."


@app.post("/api/attempts/<attempt_id>/submit")
def submit_attempt(attempt_id):
    if not student_required():
        return error("Student sign-in required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.status, a.review_deadline, e.available_from, e.available_until, e.status AS exam_status
            FROM portal_v2_attempts a JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE a.id=%s AND a.student_name=%s AND a.student_class=%s FOR UPDATE OF a
        """, (attempt_id, session["student_name"], session["student_class"]))
        row = cur.fetchone()
        if not row:
            return error("Attempt not found", 404)
        if row["status"] != "in_progress":
            return error("Attempt already submitted", 409)
        expired = (datetime.now(timezone.utc) < row["available_from"] or datetime.now(timezone.utc) >= row["available_until"] or row["exam_status"] != "live" or datetime.now(timezone.utc) > row["review_deadline"])
        cur.execute("""
            UPDATE portal_v2_attempts SET status='submitted', submitted_at=now()
            WHERE id=%s AND student_name=%s AND student_class=%s AND status='in_progress'
        """, (attempt_id, session["student_name"], session["student_class"]))
        cur.execute("UPDATE portal_v2_answers SET is_final=true WHERE attempt_id=%s", (attempt_id,))
        # Automatically grade MCQs and rubric-backed SAQs. LAQs always remain for teacher review.
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
                marked = _auto_mark_saq(q["answer_text"], q["expected_answer"], scheme, q["marks"])
                if marked is not None:
                    auto_marks, feedback = marked
            if auto_marks is not None:
                cur.execute("""
                    INSERT INTO portal_v2_evaluations
                    (attempt_id, question_id, ai_marks, final_marks, ai_feedback,
                     reviewed_by, reviewed_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, 'AutoMark', now(), now())
                    ON CONFLICT (attempt_id, question_id) DO NOTHING
                """, (attempt_id, q["question_id"], auto_marks, auto_marks, feedback))
    return jsonify({"ok": True, "status": "submitted", "auto_submitted": expired})


@app.get("/api/attempts/<attempt_id>/result")
def attempt_result(attempt_id):
    if not student_required():
        return error("Student sign-in required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.id, a.student_name, a.student_class, a.status,
                   a.started_at, a.submitted_at, a.evaluated_at,
                   e.title, e.subject, e.total_marks
            FROM portal_v2_attempts a JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE a.id=%s AND a.student_name=%s AND a.student_class=%s
        """, (attempt_id, session["student_name"], session["student_class"]))
        result = cur.fetchone()
        if not result:
            return error("Attempt not found", 404)
        if result["status"] != "evaluated":
            return jsonify({"ok": True, "result": result, "message": "Evaluation is not complete yet"})
        cur.execute("""
            SELECT q.position, q.prompt, q.marks AS maximum_marks,
                   ans.answer_text, ans.selected_option,
                   ev.final_marks, ev.ai_feedback, ev.teacher_feedback
            FROM portal_v2_questions q
            JOIN portal_v2_attempts a ON a.exam_id=q.exam_id
            LEFT JOIN portal_v2_answers ans ON ans.question_id=q.id AND ans.attempt_id=a.id
            LEFT JOIN portal_v2_evaluations ev ON ev.question_id=q.id AND ev.attempt_id=a.id
            WHERE a.id=%s ORDER BY q.position
        """, (attempt_id,))
        result["answers"] = cur.fetchall()
        result["obtained_marks"] = sum(float(x["final_marks"] or 0) for x in result["answers"])
        return jsonify({"ok": True, "result": result})





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
            WHERE a.student_name=%s AND a.student_class=%s
            ORDER BY a.started_at DESC
        """, (session["student_name"], session["student_class"]))
        return jsonify({"ok": True, "attempts": cur.fetchall()})


@app.get("/teacher")
def teacher_portal():
    return render_template("teacher.html")


@app.get("/api/admin/attempts")
def admin_list_attempts():
    if not admin_required():
        return error("Admin authentication required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.id, a.student_name, a.student_class, a.status,
                   a.started_at, a.submitted_at, e.id AS exam_id,
                   e.title AS exam_title, e.subject, e.total_marks,
                   COALESCE(SUM(ev.final_marks), 0)::float AS obtained_marks
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            LEFT JOIN portal_v2_evaluations ev ON ev.attempt_id=a.id
            GROUP BY a.id, e.id
            ORDER BY a.submitted_at DESC NULLS LAST, a.started_at DESC
        """)
        return jsonify({"ok": True, "attempts": cur.fetchall()})


@app.get("/api/admin/attempts/<attempt_id>")
def admin_attempt_detail(attempt_id):
    if not admin_required():
        return error("Admin authentication required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.id, a.student_name, a.student_class, a.status,
                   a.started_at, a.submitted_at, e.title AS exam_title,
                   e.subject, e.total_marks
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE a.id=%s
        """, (attempt_id,))
        attempt = cur.fetchone()
        if not attempt:
            return error("Attempt not found", 404)
        cur.execute("""
            SELECT q.id AS question_id, q.position, q.question_type,
                   q.prompt, q.options, q.correct_option, q.expected_answer,
                   q.marking_scheme, q.marks AS maximum_marks,
                   ans.answer_text, ans.selected_option,
                   ev.ai_marks, ev.final_marks, ev.teacher_feedback, ev.reviewed_by
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
    if not admin_required():
        return error("Admin authentication required", 401)
    data = request.get_json(silent=True) or {}
    evaluations = data.get("evaluations")
    reviewer = str(data.get("reviewer", "Teacher")).strip()[:120] or "Teacher"
    if not isinstance(evaluations, list):
        return error("Evaluations must be provided as a list")
    try:
        with db() as conn, conn.cursor() as cur:
            cur.execute("SELECT status FROM portal_v2_attempts WHERE id=%s FOR UPDATE", (attempt_id,))
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
                if question_type != "laq":
                    return error("Only LAQ answers can be manually marked. MCQs and SAQs are auto-marked.")
                seen.add(qid)
                marks = float(item.get("final_marks", 0))
                if marks < 0 or marks > maxima[qid]:
                    return error("Marks must be between zero and the question maximum")
                feedback = str(item.get("teacher_feedback", ""))[:4000]
                cur.execute("""
                    INSERT INTO portal_v2_evaluations
                    (attempt_id, question_id, ai_marks, final_marks, teacher_feedback,
                     reviewed_by, reviewed_at, updated_at)
                    VALUES (%s, %s, 0, %s, %s, %s, now(), now())
                    ON CONFLICT (attempt_id, question_id) DO UPDATE SET
                      final_marks=EXCLUDED.final_marks,
                      teacher_feedback=EXCLUDED.teacher_feedback,
                      reviewed_by=EXCLUDED.reviewed_by,
                      reviewed_at=now(), updated_at=now()
                """, (attempt_id, qid, marks, feedback, reviewer))
            cur.execute("SELECT COUNT(*) AS n FROM portal_v2_questions q JOIN portal_v2_attempts a ON a.exam_id=q.exam_id WHERE a.id=%s AND q.question_type='laq'", (attempt_id,))
            total_manual = cur.fetchone()["n"]
            cur.execute("""
                SELECT COUNT(*) AS n FROM portal_v2_evaluations ev
                JOIN portal_v2_questions q ON q.id=ev.question_id
                WHERE ev.attempt_id=%s AND q.question_type='laq'
            """, (attempt_id,))
            reviewed = cur.fetchone()["n"]
            if reviewed < total_manual:
                return error("Save marks for every LAQ before finalising the result")
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
    if not admin_required():
        return error("Admin authentication required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.id, a.student_name, a.student_class, a.status,
                   a.submitted_at, e.total_marks
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            WHERE a.id=%s
        """, (attempt_id,))
        result = cur.fetchone()
        if not result:
            return error("Attempt not found", 404)
        if result["status"] != "evaluated":
            return error("The result PDF is available after the teacher finalises the marks.", 409)
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

    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    submitted = result["submitted_at"]
    if submitted:
        if submitted.tzinfo is None:
            submitted = submitted.replace(tzinfo=timezone.utc)
        submitted_text = submitted.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%d %B %Y, %I:%M %p IST")
    else:
        submitted_text = "Not available"

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=64, leftMargin=64, topMargin=90, bottomMargin=72)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CompactResultTitle", parent=styles["Title"], alignment=TA_CENTER,
        textColor=colors.HexColor("#172554"), fontSize=20, leading=26, spaceAfter=8
    )
    subtitle_style = ParagraphStyle(
        "CompactResultSubtitle", parent=styles["Normal"], alignment=TA_CENTER,
        textColor=colors.HexColor("#64748b"), fontSize=9, spaceAfter=28
    )
    rows = [
        ["Student name", str(result["student_name"])],
        ["Class", str(result["student_class"])],
        ["Marks obtained", f'{float(marks["obtained_marks"]):g}'],
        ["Total marks", f'{float(marks["total_marks"]):g}'],
        ["Date & time", submitted_text],
    ]
    table = Table(rows, colWidths=[150, 310], hAlign="CENTER")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#172033")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 12),
        ("LEADING", (0, 0), (-1, -1), 18),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#d8deeb")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    story = [
        Paragraph("EXAMINATION RESULT", title_style),
        Paragraph("Official student marks summary", subtitle_style),
        table,
    ]
    doc.build(story)
    buffer.seek(0)
    safe_name = "".join(ch for ch in str(result["student_name"]) if ch.isalnum() or ch in (" ", "-", "_")).strip().replace(" ", "_") or "student"
    return send_file(buffer, mimetype="application/pdf", as_attachment=True,
                     download_name=f"{safe_name}_result.pdf")

@app.errorhandler(404)
def not_found(_):
    return error("Route not found", 404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))