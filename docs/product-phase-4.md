# Product — VERITAS Phase 4 (findings, AI, scan controls)

## Purpose

Operational controls on top of Phase 3 engines: finding workflow, cancel, branch/diff targeting, suppressions, compare, scan quotas, GitHub token hygiene, and scan-quality controls (depth, engines, path policy, SARIF).

## Finding status

Allowed: `open` | `triage` | `fixed` | `false_positive`.

- `PATCH /workspace/findings/{id}` (owner-only)
- Report UI: filter + status select in the finding drawer

## Finding drawer + GitHub blob links

Click a finding → side drawer (severity, engine, snippet, remediations, status). Blob URL:

`https://github.com/{repo}/blob/{sha}/{path}#L{line}`

Shared reports open the same drawer read-only.

## AI pipeline (Rules + AI scan mode)

No separate “finding triage” stage. When `scan_mode=rules_plus_ai` (or `code_review=true`):

1. **Engines** — Gitleaks / OSV / Semgrep (selectable)
2. **OpenRouter code review** — `ai_code_review.py` sends capped hot files; model returns structured JSON (score / category / risk) → findings with `engine: openrouter_review`. Skip if no `OPENROUTER_API_KEY` (fail-open).
3. **Groq final report** — `ai_report.py` writes markdown summary + countermeasures → `summary.ai_report` + per-finding remediations. Skip if no `GROQ_API_KEY` (fail-open).

Env (server `.env` only — never commit):

- `OPENROUTER_API_KEY` / optional `OPENROUTER_REVIEW_MODEL`
- `GROQ_API_KEY` / optional `GROQ_MODEL` / `GROQ_REPORT_MODEL`

Legacy `ai_triage.py` remains in tree but is **not** used in the active pipeline.

## Scan controls

Create scan (`POST /workspace/projects/{id}/scans`) accepts:

| Field | Values |
|-------|--------|
| `security_level` | `basic` \| `standard` \| `strict` (Semgrep packs) |
| `engines` | subset of `gitleaks`, `osv`, `semgrep`, `trufflehog`, `detect_secrets`, `trivy`, `pip_audit`, `checkov`, `bandit`, `njsscan`, `hadolint`, `shellcheck` (defaults: gitleaks/osv/semgrep) |
| `path_excludes` | glob-like patterns (capped) for SAST / AI review |
| `fail_severity` | `off` \| `critical` \| `high` \| `medium` — mark scan `failed` if open finding ≥ gate |
| `code_review` | enable OpenRouter review when not already Rules + AI |
| `scan_mode` / `scan_scope` / `ref` | as Phase 3/4 |

Project Advanced UI exposes depth, engines, excludes, severity gate, and Compare latest.

## Coverage + exports

Scan summary includes `by_severity`, `by_family`, `engines` meta, `ai_report`, `policy_failed`. Report UI shows coverage bars and AI report. Client exports: Markdown, JSON, CSV, HTML, **SARIF 2.1.0**.

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

`GET /workspace/projects/{id}/scans/compare?a=&b=` → added / removed / unchanged by fingerprint. Accepts `completed` or policy-`failed` scans.

## Quotas

Env: `SCAN_RATE_LIMIT` (default 10/hour), `SCAN_CONCURRENT_LIMIT` (default 2). Enforced on create (429).

## GitHub hygiene

`needs_reauth` on connection after 401/403. Project + Integrations banners with Reconnect CTA.

## Out of scope

DAST, VS Code extension, admin org-wide scan console, Redis OAuth state, TypeSafe API, separate finding-triage AI pass.
