# Product — VERITAS Phase 1

## Purpose

VERITAS Phase 1 delivers secure account access and administrator-managed user lifecycle for a college infosec platform. Later phases add scanning, deployment, and reporting — those are out of scope until Phase 1 identity is stable.

## In scope

- Signup with Argon2 password hashing
- Email verification (Resend in production; queued locally without API key)
- Administrator approval gate before first login
- Session cookie auth (`veritas_session`, HTTP-only)
- Password reset with session revocation
- Profile: display name, username, DiceBear avatar seed
- Admin user directory, role/status transitions, audit events
- Identity overview dashboards (`/admin/` metrics + approval queue; `/user/` account home)
- Separate UI surfaces: public auth, `/admin/`, `/user/`

See also [product-phase-2.md](product-phase-2.md) for workspace projects, stub scans, and Connect GitHub.

## Out of scope (do not implement in Phase 1)

- Vulnerability scanning engines
- Deployment pipelines
- Security/reporting dashboards beyond identity metrics and audit logs
- Shared frontend component libraries between admin and user areas
- Mobile apps

## Primary user journeys

1. **New user:** signup → verify email → wait for admin approve → login → `/user/` home → `/user/profile`
2. **Admin:** login → `/admin/` overview → `/admin/directory` approve/reject/deactivate → optional audit review
3. **Recovery:** forgot password → email token → reset → sessions revoked → login again

## Success criteria

- Auth lifecycle works end-to-end against SQLite (dev) and PostgreSQL (prod-ready config)
- Tests in `backend/tests/` cover signup → verify → approve → login → deactivate
- Clean URLs without `.html` for primary surfaces
- Agentic docs stay accurate after structural changes
