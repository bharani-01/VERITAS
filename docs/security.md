# Security

## Password and tokens

- Passwords hashed with Argon2 (`argon2-cffi`)
- Session and one-time tokens stored as SHA-256 hashes only
- Reset / verify tokens expire (~30 minutes) and are single-use
- Password reset revokes all active sessions for that user

## Sessions

- Cookie name: `veritas_session`
- Flags: `HttpOnly`, `SameSite=Lax`, `Secure` when `SESSION_COOKIE_SECURE=true` or production
- TTL from `SESSION_TTL_HOURS` (default 24)

## Authorization

- Active status required for any authenticated API
- Admin routes require `role == admin`
- Workspace routes (`/workspace/*`) require the authenticated user to own the project/scan
- GitHub repo attach: server re-fetches the repo and requires `owner` to match the connected GitHub account
- Cannot demote or deactivate the last active administrator
- Admins cannot change their own role

## Account lifecycle status

`pending_verification` → `pending_approval` → `active` | `rejected` | `deactivated`

Login is blocked unless status is `active`.

## Audit log

- Server-side `audit_events` table; append-only (no update/delete API)
- Written after security-relevant actions: auth (login success/fail/block, logout, signup, verify, reset), **admin lifecycle** (approve/reject/deactivate/profile), workspace (project CRUD, scan start, GitHub connect/disconnect/failures, foreign-repo reject)
- Each event stores a rich `context_json` answering who / what / when / where / how (including HTTP `status_code` such as 200 / 401 / 429)
- API derives a display `severity` (`info`–`critical`) from action + status for the admin Audit UI
- Where: IP + multi-provider geolocation consensus (`ip-api`, `ipwho.is`, `ipapi.co`), cached per process; private/localhost IPs skipped
- Rate-limit blocks (`429`) are audited as `rate_limited`
- Does **not** log every HTTP request or every SQL query into `audit_events` (noise, PII risk, performance)
- Admin UI: `/admin/audit` via `GET /admin/audit-events` (filters including severity, infinite scroll, response code column)

## HTTP telemetry (Security dashboard)

- Separate `http_request_events` table for **metadata-only** live collection of application API routes (`/auth`, `/admin`, `/workspace`, `/webhooks`, `/health`)
- Middleware classifies path/query heuristics for SQLi / XSS / CSRF / auth anomalies; never stores bodies, cookies, passwords, or tokens (query secret params redacted)
- Admin APIs: `GET /admin/http-requests`, `GET /admin/security-overview` (Safe / Warning / Critical + volume buckets + countermeasure tips)
- Admin UI: `/admin/security` with ApexCharts live graphs; retention capped (~7 days / 50k rows)
- Detection only — does not block requests (not a WAF)

## Rate limiting

In-memory limiter on signup, login, verify, reset, and profile update endpoints. Exceeded limits return `429` and write an audit event. Suitable for single-process local/dev; replace with shared store before multi-instance production scale-out.

## Secrets

- Never commit `backend/.env`
- Bootstrap admin credentials required for empty production DB
- Resend API key optional locally (emails stay `queued`)
- GitHub OAuth client secret and access tokens never returned to the client; tokens encrypted at rest (`TOKEN_ENCRYPTION_SECRET`)
- Optional `OPENROUTER_API_KEY` for Rules+AI code review; optional `GROQ_API_KEY` for final report/remediations; scans fail-open (engines still complete) when unset or provider errors
- Never commit API keys; rotate any key pasted in chat before production
- Scan create quotas: `SCAN_RATE_LIMIT` / `SCAN_CONCURRENT_LIMIT` (429 when exceeded)
- Finding status/suppress and compare APIs enforce project ownership via scan→project
- `fail_severity` policy is evaluated server-side after engines merge
- GitHub API **401** (or decrypt failure) marks connection `needs_reauth`; **403** rate limits do not
- Push webhooks at `/webhooks/github` require valid `X-Hub-Signature-256` per project secret
- Repo clones for scans use short-lived workdirs under a server temp path and are deleted after the job

## Agent rules

- Do not weaken cookie flags, hashing, or approval gates for convenience
- Do not log plaintext passwords or raw tokens
- Prefer fail-closed auth errors with generic client messages where enumeration matters (signup/reset already use opaque success messages)
