# VERITAS

Phase 1: secure account access and user management.  
Phase 2: user workspace (projects, stub scans) and Connect GitHub.  
Scanning engines, deployment, and full reporting are Phase 3+.

## Architecture

Single-server: FastAPI serves the API and the React SPA from the same origin.

- Source UI: `frontend/` (Vite + React)
- Built assets: `backend/app/web/static/spa/` (served by FastAPI)
- Backend packages: `backend/app/{core,models,schemas,services,api,web}`

See [AGENTS.md](AGENTS.md), [docs/architecture.md](docs/architecture.md), and [docs/product-phase-2.md](docs/product-phase-2.md).

## Run locally

1. Create a virtual environment and install `backend/requirements.txt`.
2. Copy `backend/.env.example` to `backend/.env` and set values.
3. Set the three `VERITAS_BOOTSTRAP_ADMIN_*` variables before first startup.
4. Optional Phase 2 GitHub: set `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI`.
5. Build the frontend (required once, and after UI changes):

```bash
cd frontend
npm install
npm run build
```

6. Start the server:

```bash
uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

Open `http://localhost:8000`. Admins land on `/admin/`; users land on `/user/`.

Optional UI-only hot reload (still needs the API on 8000):

```bash
cd frontend
npm run dev
```

## Tests

```bash
pytest -c backend/pytest.ini
```

## Production notes

Set `APP_ENV=production`, use PostgreSQL through `DATABASE_URL`, enable `SESSION_COOKIE_SECURE=true`, configure Resend, set `TOKEN_ENCRYPTION_SECRET`, configure GitHub OAuth if used, and ship a fresh `npm run build` before deploy.
