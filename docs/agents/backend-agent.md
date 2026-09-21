# Backend agent

## Owns

- `backend/app/core/`
- `backend/app/models/`
- `backend/app/schemas/`
- `backend/app/services/`
- `backend/app/api/`
- `backend/tests/`

## Rules

- Keep `main.py` thin: lifespan + router includes only
- Put validation in schemas; orchestration in services; HTTP in `api/`
- Use `from app.core import database as db` when code must see a rebinding of `engine`/`SessionLocal` (tests)
- Preserve Argon2 hashing and hashed token storage
- Workspace (`/workspace/*`) ownership and GitHub repo checks must be server-side
- Add/adjust tests in `backend/tests/test_identity.py` and `test_workspace.py`

## Commands

```bash
uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
pytest -c backend/pytest.ini
```

## Checklist before done

- [ ] Imports use `app.*` (not `backend.app.*` inside the package)
- [ ] No secrets in code
- [ ] Admin/user authorization still enforced
- [ ] Tests pass for touched identity and workspace flows
