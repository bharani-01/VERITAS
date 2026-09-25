# Architecture

## Repository layout

```text
VERITAS-Infosec/
├── AGENTS.md
├── README.md
├── .cursor/rules/
├── docs/
├── frontend/                      # React (Vite) source — single-server UI
│   └── src/
│       ├── admin/                 # Admin shell, nav, dashboard, directory, profile
│       ├── user/                  # User shell, home, projects, new-project, scans, profile
│       ├── pages/                 # Public auth screens
│       ├── components/            # Auth-only UI (AuthShell)
│       └── lib/                   # api client, avatars, workspace types
└── backend/
    ├── requirements.txt
    ├── pytest.ini
    ├── tests/
    └── app/
        ├── main.py
        ├── core/ models/ schemas/ services/ api/
        └── web/
            ├── routes.py          # SPA + legacy HTML fallback
            └── static/
                ├── spa/           # npm run build output (served in prod)
                ├── auth/          # legacy fallback HTML
                ├── admin/
                └── user/
```

## Single-server request flow

1. Browser hits FastAPI on one origin (e.g. `:8000`).
2. Page routes (`/`, `/admin/`, `/admin/directory`, `/admin/audit`, `/admin/security`, `/user/projects`, …) return the React `index.html`.
3. JS/CSS load from `/assets/*` (Vite build hashed files).
4. React calls `/auth/*`, `/admin/*`, and `/workspace/*` JSON APIs with same-origin cookies.
   - New project Advanced loads branches via `GET /workspace/github/repos/{repo_id}/refs` (ownership re-checked server-side before listing refs).
5. Services persist via SQLAlchemy.

**Path rule:** never use the same path for SPA HTML and JSON. Example: users UI is `/admin/directory`; users API remains `/admin/users`.

No separate frontend host is required in production.

## Email

Transactional HTML lives in `backend/app/services/email_templates.py` (shared layout + builders). Copy is short and plain: product mark, one headline, one or two sentences, optional CTA, no gradients/emojis/marketing filler. Delivered via Resend (`email.py`); without an API key, deliveries stay `queued`.

| Table | Role |
|-------|------|
| `users` | Identity, role, status, profile |
| `auth_sessions` | Hashed session tokens |
| `one_time_tokens` | Email verify / password reset (hashed) |
| `audit_events` | Admin/user action trail |
| `http_request_events` | Metadata-only HTTP telemetry (method/path/status/classification/severity; no bodies) |
| `email_deliveries` | Outbound email status |
| `projects` | User-owned workspace projects (Phase 2) + auto_scan_on_push / auto_scan_branch / webhook fields (Phase 5) |
| `scans` | Scan records + Phase 3/4 async engines (progress, ETA, scope, cancel) |
| `findings` | Normalized engine findings per scan (status, fingerprint, AI fields) |
| `finding_suppressions` | Project-scoped fingerprints suppressed across re-scans |
| `app_notifications` | In-app scan completion notices |
| `github_connections` | Encrypted GitHub OAuth tokens + `needs_reauth` |

SQLite is default for local development. Production expects PostgreSQL.

**Timestamps:** stored as UTC. API JSON always emits ISO-8601 with a `Z` suffix (`to_iso_utc`) so browsers do not mis-parse SQLite’s naive datetimes as local time. The SPA parses API times via `lib/time.ts` (`parseUtc`) and displays them in the user’s locale.

## Lifespan

On startup (`main.lifespan`):

1. `Base.metadata.create_all`
2. `ensure_schema()` — additive migrations for profile columns
3. `bootstrap_admin()` — creates first admin from env when DB is empty

## Frontend build

```bash
cd frontend && npm run build
```

Output lands in `backend/app/web/static/spa` and is what uvicorn serves.

## Scan pipeline (Phase 4 quality pack)

1. Clone linked repo (short-lived workdir)
2. Selected engines (soft-skip if missing): Gitleaks → TruffleHog → detect-secrets → OSV → pip-audit → Trivy → Checkov → Semgrep → Bandit → njsscan → Hadolint → ShellCheck

3. Optional OpenRouter structured code review (`services/ai_code_review.py`)
4. Merge findings → optional Groq final report (`services/ai_report.py`)
5. Severity policy gate → persist summary (`by_severity`, `ai_report`, engine meta)
