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
│       ├── user/                  # User shell, home, projects, scans, integrations, profile
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
2. Page routes (`/`, `/admin/`, `/admin/directory`, `/admin/audit`, `/user/projects`, …) return the React `index.html`.
3. JS/CSS load from `/assets/*` (Vite build hashed files).
4. React calls `/auth/*`, `/admin/*`, and `/workspace/*` JSON APIs with same-origin cookies.
5. Services persist via SQLAlchemy.

**Path rule:** never use the same path for SPA HTML and JSON. Example: users UI is `/admin/directory`; users API remains `/admin/users`.

No separate frontend host is required in production.

## Persistence

| Table | Role |
|-------|------|
| `users` | Identity, role, status, profile |
| `auth_sessions` | Hashed session tokens |
| `one_time_tokens` | Email verify / password reset (hashed) |
| `audit_events` | Admin/user action trail |
| `email_deliveries` | Outbound email status |
| `projects` | User-owned workspace projects (Phase 2) |
| `scans` | Scan records + Phase 3 async engines (progress, ETA, summary) |
| `findings` | Normalized engine findings per scan |
| `app_notifications` | In-app scan completion notices |
| `github_connections` | Encrypted GitHub OAuth tokens (Phase 2) |

SQLite is default for local development. Production expects PostgreSQL.

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
