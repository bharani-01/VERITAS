# Product — VERITAS Phase 4 (findings, AI, scan controls)

## Purpose

Operational controls on top of Phase 3 engines: finding workflow, real Groq triage, cancel, branch/diff targeting, suppressions, compare, scan quotas, and GitHub token hygiene.

## Finding status

Allowed: `open` | `triage` | `fixed` | `false_positive`.

- `PATCH /workspace/findings/{id}` (owner-only)
- Report UI: filter + status select in the finding drawer

## Finding drawer + GitHub blob links

Click a finding → side drawer (severity, engine, snippet, AI fields, status). Blob URL:

`https://github.com/{repo}/blob/{sha}/{path}#L{line}`

Shared reports open the same drawer read-only.

## Groq AI triage

`backend/app/services/ai_triage.py` — batch high/critical (cap 25), fail-open. Set `GROQ_API_KEY` / optional `GROQ_MODEL` in `backend/.env` only (never commit).

## Cancel

- `cancel_requested` on scans; `POST /workspace/scans/{id}/cancel`
- Worker checks between engine phases → `status=cancelled`

## Branch / tag + changed-files scope

- `GET /workspace/projects/{id}/git-refs`
- Create scan: `ref`, `scan_scope: full | changed`
- Changed mode: Semgrep limited to `git diff` paths vs default branch

## Suppressions

Fingerprint `hash(engine|rule_id|file_path|line_start|title)`. Table `finding_suppressions`. New findings auto-marked `false_positive` when suppressed. Drawer: “Suppress in future scans”.

## Compare

`GET /workspace/projects/{id}/scans/compare?a=&b=` → added / removed / unchanged by fingerprint.

## Quotas

Env: `SCAN_RATE_LIMIT` (default 10/hour), `SCAN_CONCURRENT_LIMIT` (default 2). Enforced on create (429).

## GitHub hygiene

`needs_reauth` on connection after 401/403. Project + Integrations banners with Reconnect CTA.

## Out of scope

DAST, VS Code extension, admin org-wide scan console, Redis OAuth state.
