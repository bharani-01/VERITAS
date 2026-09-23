# Product — VERITAS Phase 2

## Purpose

Phase 2 adds a user **workspace**: projects, scan records (stub lifecycle), and **Connect GitHub** (OAuth link + owned-repo attach). Vulnerability engines and reporting remain Phase 3+.

## In scope

- User-owned projects (CRUD)
- Scans tied to projects with stub status `queued` → `running` → `completed` (zero findings)
- Connect GitHub OAuth; list and attach **only repos owned by the connected GitHub user**
- Server-side re-verification of repo ownership on every attach
- User UI: Home, Projects (incl. New project + GitHub connect), Scans, Profile
- Admin dashboard footnote totals for projects / scans / GitHub links
- Encrypted GitHub tokens at rest; tokens never returned to the client

## Out of scope (Phase 3+)

- Real vulnerability scanners / exploit tooling — **delivered in Phase 3** (see [product-phase-3.md](product-phase-3.md))
- Org GitHub Apps, webhooks, CI-driven scans
- Deployment pipelines and full reporting exports

## Hard security rules

- All authorization and validation run in FastAPI/services (UI is not trusted)
- Foreign / forged `github_repo_id` values are rejected after a live GitHub API ownership check
- SPA paths (`/user/projects`, `/admin/directory`) never collide with JSON APIs (`/workspace/*`, `/admin/users`)
- GitHub OAuth returns to `/user/projects/new` (Integrations page removed; connect happens in the create flow)

## Primary journeys

1. User connects GitHub → selects an owned repo → creates project → starts stub scan → sees it on Home / Scans
2. User creates a manual project (no GitHub) → starts stub scan with an explicit target
3. Disconnect GitHub → `/workspace/github/repos` fails until reconnect
