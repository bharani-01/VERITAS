# VERITAS Agent Guide

This repository is optimized for agentic development. Read these files before changing code.

## Start here

1. [docs/product.md](docs/product.md) — Phase 1 identity scope
2. [docs/product-phase-2.md](docs/product-phase-2.md) — Phase 2 workspace + GitHub
3. [docs/product-phase-3.md](docs/product-phase-3.md) — Phase 3 real scans (Semgrep stack + optional AI)
4. [docs/product-phase-4.md](docs/product-phase-4.md) — Phase 4 findings, Groq, cancel, scope, quotas
5. [docs/product-phase-5.md](docs/product-phase-5.md) — Phase 5 auto-scan on push + GitHub reauth fix
6. [docs/architecture.md](docs/architecture.md) — package layout and request flow
7. [docs/design.md](docs/design.md) — UI system and frontend boundaries
8. [docs/security.md](docs/security.md) — auth, sessions, and hard constraints
9. [docs/agents/overview.md](docs/agents/overview.md) — which agent persona to use

## Non-negotiables

- Phase 1 = identity and user management; Phase 2 = projects, stub scans, Connect GitHub; Phase 3 = real engines (secrets/SCA/SAST), optional Groq AI triage (no local LLM required on EC2); Phase 4 = finding workflow, cancel, branch/diff scope, suppressions, compare, scan quotas, GitHub reauth; Phase 5 = auto-scan on push webhooks.
- Keep admin (`/admin/`) and user (`/user/`) frontends separate — no shared nav components.
- Prefer the smallest coherent change that preserves production security posture.
- Never commit secrets (`.env`, credentials, session tokens, GitHub tokens).
- Server-side validation only for authz and GitHub repo ownership.
- Update docs when architecture, design, or agent workflows change.
- After meaningful finished work: commit, `git push`, and AWS deploy to EC2 (`veritas.trackifyapp.co.in`) — see `.cursor/rules/ship-aws-git.mdc`. Never overwrite remote `backend/.env`.

## Runtime

```bash
cd frontend && npm run build
uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

Tests (from repo root):

```bash
pytest -c backend/pytest.ini
```
