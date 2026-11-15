# Exam Portal V2

A separate Flask API for the V2 examination portal. It uses the isolated `portal_v2_*` PostgreSQL tables and does not modify the existing portal or Gemini MCP service.

## Deploy on Render

- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`
- Set environment variables:
  - `DATABASE_URL`: Neon connection string for the V2 test branch
  - `ADMIN_API_KEY`: long random secret used in the `X-Admin-Key` request header

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
