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

## Rate limiting

In-memory limiter on signup, login, verify, reset, and profile update endpoints. Suitable for single-process local/dev; replace with shared store before multi-instance production scale-out.

## Secrets

- Never commit `backend/.env`
- Bootstrap admin credentials required for empty production DB
- Resend API key optional locally (emails stay `queued`)
- GitHub OAuth client secret and access tokens never returned to the client; tokens encrypted at rest (`TOKEN_ENCRYPTION_SECRET`)

## Agent rules

- Do not weaken cookie flags, hashing, or approval gates for convenience
- Do not log plaintext passwords or raw tokens
- Prefer fail-closed auth errors with generic client messages where enumeration matters (signup/reset already use opaque success messages)
