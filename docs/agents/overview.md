# Agents overview

Use the narrowest agent persona for the task. Prefer reading the matching playbook before editing.

| Persona | Use when | Playbook |
|---------|----------|----------|
| Backend | API, models, services, auth logic, tests | [backend-agent.md](backend-agent.md) |
| Frontend | HTML/CSS/JS in `web/static` | [frontend-agent.md](frontend-agent.md) |
| Security | Auth, sessions, permissions, threat model | [security-agent.md](security-agent.md) |
| Docs | Product/architecture/design/agent guides | Update `docs/` + `AGENTS.md` together |

## Workflow

1. Confirm scope in `docs/product.md`, `docs/product-phase-2.md`, and `docs/product-phase-3.md` as needed
2. Locate the owning package from `docs/architecture.md`
3. Implement the smallest coherent change
4. Run relevant tests / smoke the affected routes
5. Update docs if structure or contracts changed

## Anti-patterns

- Putting business logic back into `main.py`
- Sharing admin/user nav components
- Adding Phase 3 engines on unrelated Phase 1 tickets (see [product-phase-3.md](../product-phase-3.md))
- Trusting client-side GitHub repo selection without server re-check
- Editing `.env` secrets into the repo
