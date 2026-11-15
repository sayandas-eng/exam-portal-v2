# Exam Portal V2

A separate Flask API for the V2 examination portal. It uses the isolated `portal_v2_*` PostgreSQL tables and does not modify the existing portal or Gemini MCP service.

## Deploy on Render

- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`
- Set environment variables:
  - `DATABASE_URL`: Neon connection string for the V2 test branch
  - `ADMIN_API_KEY`: long random secret used in the `X-Admin-Key` request header
  - `SECRET_KEY`: long random Flask session-signing secret

Each published examination must have its own Gemini-generated common password. Gemini passes that password in `exam_password` when creating the draft; the portal stores only a password hash. Students sign in with their name, class and that exam password, which unlocks only the matching live exam. The raw password is not retrievable from the portal after creation, so Gemini returns it to the teacher for distribution. No global student password environment variable is used.\n\nStudent login is limited to 8 attempts per minute per source IP. Admin write endpoints are limited to 60 requests per minute. Rate-limit counters use process memory and reset when the service restarts; use a shared Redis-backed store before scaling to multiple instances.

## API

- `GET /health`
- `GET /api/exams`
- `POST /api/admin/exams` (admin key required; creates a draft exam)
- `POST /api/admin/exams/{exam_id}/publish` (admin key required)
- `POST /api/exams/{exam_id}/start`
- `PUT /api/attempts/{attempt_id}/answers/{question_id}`
- `POST /api/attempts/{attempt_id}/submit`
- `GET /api/attempts/{attempt_id}/result`

This is the first API foundation, not a finished production exam platform. Teacher review, AI evaluation, secure student session ownership, and the full browser UI still need to be implemented and tested before real student use.


## Gemini exam-creation workflow

1. Gemini generates the question paper and a strong, unique common password for that exam.
2. Gemini calls `POST /api/admin/exams` with the full question payload and `exam_password` set to that generated password, using the admin key in `X-Admin-Key`.
3. Gemini calls `POST /api/admin/exams/{exam_id}/publish`.
4. Gemini tells the teacher the generated password so it can be distributed to the target class.
5. Students sign in at `/student` using their name, class and the password for that examination. The portal matches the password against live exams for that class and exposes only the matching exam.

The existing Gemini MCP service and the original exam portal are not modified by this V2 change. The MCP integration must pass Gemini's generated `exam_password` field through to the V2 create-exam API; if its current create-exam tool does not forward that field or target V2, it will need a separate V2 tool/connection configuration.

## Dedicated Gemini MCP service (V2)

- Service URL: `https://exam-portal-v2-gemini-mcp.onrender.com/mcp`
- Health: `https://exam-portal-v2-gemini-mcp.onrender.com/health`
- Start command: `python mcp_v2.py`
- Required service environment: `MCP_API_TOKEN`, `MCP_LOGIN_USERNAME`, `MCP_LOGIN_PASSWORD`, `MCP_PUBLIC_URL`, `PORTAL_BASE_URL`, and the V2 `DATABASE_URL`.
- OAuth client registrations are persisted in the V2 Neon database so Gemini's dynamic client registration survives service restarts.
- Tools: `create_and_publish_exam` and `list_examinations`.
- The MCP service authenticates to V2 using its dedicated `MCP_API_TOKEN`; it does not reuse or modify the V1 Gemini MCP service.

