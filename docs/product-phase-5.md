# Product — VERITAS Phase 5 (auto-scan on push)

## Purpose

Scan on GitHub push (Render/Vercel-style) plus fix false GitHub “Reconnect” banners.

## GitHub disconnect root cause

`needs_reauth` was incorrectly set on **HTTP 403** (rate limits / temporary denials) from git-refs. Only **401** and decrypt failures mark reauth now. Successful API calls clear a stale flag.

## Auto-scan on push

- Per-project toggle `auto_scan_on_push` (default off).
- On enable: register a repo webhook → `{PUBLIC_APP_URL}/webhooks/github` with a per-project HMAC secret.
- Trigger: `push` to the project **default branch** only.
- Scan `source=github_push`; deduped by `commit_sha`; respects scan quotas (skipped quietly when over limit).

## Security

- Webhook verifies `X-Hub-Signature-256` against the encrypted project secret.
- No session cookie on `/webhooks/github`.
- Repo ownership still validated when linking; webhook only fires for configured repos.
