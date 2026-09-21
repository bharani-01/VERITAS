# Frontend agent

## Owns

- `frontend/src/admin/` — admin shell, nav, dashboard, directory, profile
- `frontend/src/user/` — user shell, nav, home, projects, scans, integrations, profile
- `frontend/src/pages/` — public auth screens only
- `backend/app/web/routes.py` (SPA serving)
- `docs/design.md`

## Rules

- Single-server: build into `backend/app/web/static/spa`; FastAPI serves it
- **Never share React pages/components between admin and user**
- Admins: `/admin/`, `/admin/directory`, `/admin/profile` (not `/admin/users` — that is the JSON API)
- Users: `/user/`, `/user/projects`, `/user/scans`, `/user/integrations`, `/user/profile`
- Collapse keys stay per-area
- Follow Inter + slate/blue visual language in `docs/design.md`
- Do not trust client-side checks for GitHub repo ownership — server re-verifies

## Commands

```bash
cd frontend
npm install
npm run build
npm run dev
```

## Checklist before done

- [ ] `npm run build` succeeds
- [ ] Admin cannot land on `/user/`; user cannot use admin UI
- [ ] No imports from `admin/*` into `user/*` or the reverse
- [ ] Docs updated if routes changed
