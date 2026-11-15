import os
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row
from flask import Flask, jsonify, request, render_template, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=timedelta(days=7))
DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")


def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def admin_required():
    supplied = request.headers.get("X-Admin-Key", "")
    return bool(ADMIN_API_KEY and supplied and supplied == ADMIN_API_KEY)


def error(message, status=400):
    return jsonify({"ok": False, "error": message}), status


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/student")
def student_portal():
    return render_template("student.html")



def student_required():
    return bool(session.get("student_name") and session.get("student_class"))


@app.post("/api/student/login")
def student_login():
    data = request.get_json(silent=True) or {}
    name = str(data.get("full_name", "")).strip()
    student_class = str(data.get("student_class", "")).strip()
    password = str(data.get("password", ""))
    common_password = os.getenv("STUDENT_COMMON_PASSWORD", "")
    if not common_password:
        app.logger.error("STUDENT_COMMON_PASSWORD is not configured")
        return error("Student sign-in is temporarily unavailable. Please contact the administrator.", 503)
    if not name or not student_class or len(name) > 120 or len(student_class) > 60:
        return error("Enter your student name and class")
    if not __import__("hmac").compare_digest(password, common_password):
        return error("Incorrect student details or common password", 401)
    session.clear()
    session["student_name"] = name
    session["student_class"] = student_class
    session.permanent = True
    return jsonify({"ok": True, "student": {"full_name": name, "student_class": student_class}})


@app.get("/api/student/me")
def student_me():
    if not student_required():
        return error("Student sign-in required", 401)
    return jsonify({"ok": True, "student": {
        "full_name": session["student_name"],
        "student_class": session["student_class"]
    }})


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
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT id, title, subject, target_class, topic, difficulty,
                   duration_minutes, review_minutes, total_marks, published_at,
                   (exam_password_hash IS NOT NULL) AS has_password
            FROM portal_v2_exams
            WHERE status = 'live'
            ORDER BY published_at DESC NULLS LAST
        """)
        return jsonify({"ok": True, "exams": cur.fetchall()})


@app.get("/api/admin/exams")
def admin_list_exams():
    if not admin_required():
        return error("Admin authentication required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT e.id, e.title, e.subject, e.target_class, e.topic,
                   e.difficulty, e.status, e.duration_minutes, e.review_minutes,
                   e.total_marks, e.created_at, e.published_at,
                   COUNT(q.id)::int AS question_count
            FROM portal_v2_exams e
            LEFT JOIN portal_v2_questions q ON q.exam_id=e.id
            GROUP BY e.id
            ORDER BY e.created_at DESC
        """)
        return jsonify({"ok": True, "exams": cur.fetchall()})


@app.post("/api/admin/exams")
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
        password_hash = generate_password_hash(data["exam_password"]) if data.get("exam_password") else None
        with db() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO portal_v2_exams
                (id, title, subject, target_class, topic, difficulty, status,
                 exam_password_hash, duration_minutes, review_minutes, total_marks)
                VALUES (%s, %s, %s, %s, %s, %s, 'draft', %s, %s, %s, %s)
            """, (exam_id, data["title"], data["subject"], data.get("target_class"),
                  data["topic"], data.get("difficulty", "moderate"), password_hash,
                  duration, review, total))
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
                      q.get("correct_option"), q.get("expected_answer", ""),
                      __import__("json").dumps(q.get("marking_scheme", {})),
                      float(q.get("marks", 1))))
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
def publish_exam(exam_id):
    if not admin_required():
        return error("Admin authentication required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM portal_v2_questions WHERE exam_id=%s", (exam_id,))
        if cur.fetchone()["n"] == 0:
            return error("An exam must contain questions before publishing")
        cur.execute("""
            UPDATE portal_v2_exams SET status='live', published_at=now()
            WHERE id=%s AND status IN ('draft','paused') RETURNING id
        """, (exam_id,))
        if not cur.fetchone():
            return error("Exam not found or cannot be published", 404)
        cur.execute("""
            INSERT INTO portal_v2_audit_log (actor, action, entity_type, entity_id)
            VALUES ('admin', 'exam_published', 'exam', %s)
        """, (exam_id,))
    return jsonify({"ok": True, "exam_id": exam_id, "status": "live"})


@app.post("/api/exams/<exam_id>/start")
def start_exam(exam_id):
    if not student_required():
        return error("Please sign in with your student account first", 401)
    data = request.get_json(silent=True) or {}
    with db() as conn, conn.cursor() as cur:
        name, student_class = session["student_name"], session["student_class"]
        cur.execute("""
            SELECT id, target_class, exam_password_hash, duration_minutes, review_minutes
            FROM portal_v2_exams WHERE id=%s AND status='live'
        """, (exam_id,))
        exam = cur.fetchone()
        if not exam:
            return error("Exam not found or not currently live", 404)
        if exam["target_class"] and exam["target_class"].strip().lower() != student_class.lower():
            return error("This exam is not assigned to the supplied class", 403)
        if exam["exam_password_hash"] and not check_password_hash(
            exam["exam_password_hash"], str(data.get("exam_password", ""))
        ):
            return error("Incorrect exam password", 403)
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        exam_deadline = now + timedelta(minutes=exam["duration_minutes"])
        review_deadline = exam_deadline + timedelta(minutes=exam["review_minutes"])
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
                   e.id AS exam_id, e.title, e.subject, e.topic
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
            SELECT a.status, a.review_deadline, q.id
            FROM portal_v2_attempts a
            JOIN portal_v2_questions q ON q.exam_id=a.exam_id
            WHERE a.id=%s AND q.id=%s AND a.student_name=%s AND a.student_class=%s
            FOR UPDATE OF a
        """, (attempt_id, question_id, session["student_name"], session["student_class"]))
        row = cur.fetchone()
        if not row:
            return error("Attempt or question not found", 404)
        if row["status"] != "in_progress":
            return error("The answer window has closed", 409)
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


@app.post("/api/attempts/<attempt_id>/submit")
def submit_attempt(attempt_id):
    if not student_required():
        return error("Student sign-in required", 401)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT status, review_deadline FROM portal_v2_attempts
            WHERE id=%s AND student_name=%s AND student_class=%s FOR UPDATE
        """, (attempt_id, session["student_name"], session["student_class"]))
        row = cur.fetchone()
        if not row:
            return error("Attempt not found", 404)
        if row["status"] != "in_progress":
            return error("Attempt already submitted", 409)
        expired = datetime.now(timezone.utc) > row["review_deadline"]
        cur.execute("""
            UPDATE portal_v2_attempts SET status='submitted', submitted_at=now()
            WHERE id=%s AND student_name=%s AND student_class=%s AND status='in_progress'
        """, (attempt_id, session["student_name"], session["student_class"]))
        cur.execute("UPDATE portal_v2_answers SET is_final=true WHERE attempt_id=%s", (attempt_id,))
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
                   e.title AS exam_title, e.subject,
                   COUNT(ans.id)::int AS answered_count
            FROM portal_v2_attempts a
            JOIN portal_v2_exams e ON e.id=a.exam_id
            LEFT JOIN portal_v2_answers ans ON ans.attempt_id=a.id
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
                   ev.final_marks, ev.teacher_feedback
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
def evaluate_attempt(attempt_id):
    if not admin_required():
        return error("Admin authentication required", 401)
    data = request.get_json(silent=True) or {}
    evaluations = data.get("evaluations")
    reviewer = str(data.get("reviewer", "Teacher")).strip()[:120] or "Teacher"
    if not isinstance(evaluations, list) or not evaluations:
        return error("At least one evaluation is required")
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
            cur.execute("SELECT COUNT(*) AS n FROM portal_v2_questions q JOIN portal_v2_attempts a ON a.exam_id=q.exam_id WHERE a.id=%s", (attempt_id,))
            total_questions = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM portal_v2_evaluations WHERE attempt_id=%s", (attempt_id,))
            reviewed = cur.fetchone()["n"]
            if reviewed < total_questions:
                return error("Save marks for every question before finalising the result")
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


@app.errorhandler(404)
def not_found(_):
    return error("Route not found", 404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
