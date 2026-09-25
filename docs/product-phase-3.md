# Product — VERITAS Phase 3 (scanning)

## Purpose

Replace Phase 2 stub scans with real linked-repo analysis: secrets (Gitleaks), SCA (OSV-Scanner), SAST (Semgrep), optional AI triage (Groq API — not local LLM on EC2), progress/ETA, notifications, and finding reports.

## Scan modes

- **rules_only** — deterministic engines only
- **rules_plus_ai** — same engines + Groq second-pass (`ai_triage.py`; fail-open if key missing/errors)

See also [product-phase-4.md](product-phase-4.md) for finding status, cancel, branch/diff scope, suppressions, compare, and quotas.

## Notifications

Per scan: in-app (`app_notifications`) and/or email (Resend) to the project owner.
Ops alerts: when an enabled engine is **missing** on the host, or a scan **fails** for an app-side reason (clone/runtime), VERITAS emails `OPS_ALERT_EMAIL` (default `bharanisri73@gmail.com`). Expected soft-skips (disabled engines, no Dockerfiles, etc.) and user severity-policy failures do not trigger ops mail.

## Host requirements

- `git`
- **Semgrep** via `pip install semgrep` on **Linux/macOS** (in `requirements.txt` with platform marker; runner prefers `python -m semgrep`). Windows local installs skip Semgrep — run real SAST on EC2.
- `gitleaks`, `osv-scanner` (optional binaries; skipped if missing)
- Deep engines (optional; skipped if missing): **TruffleHog**, **Trivy**, **Bandit**, **detect-secrets**, **pip-audit**, **Checkov**, **njsscan**, **Hadolint**, **ShellCheck**. Default path excludes always include `.git`, `node_modules`, venvs, caches, and built SPA assets. Bandit skips test trees + B101/B404/B603; detect-secrets disables KeywordDetector and excludes tests/`.git`.
- Strict Semgrep uses expanded language + IaC packs (`p/python`…`p/rust`, `p/docker`, `p/kubernetes`, `p/terraform`, `p/nginx`)

## UX / reporting

- Progress/ETA with friendly labels (not engine names like Semgrep)
- Engines run in deep coverage mode by default (broader Semgrep packs, git-history secrets, recursive SCA)
- Report popup with risk-sorted findings, multi-format export (md/json/csv/html), and shareable public links (`/report/{token}`, no login)

## Out of scope (later)

- Full DAST / HTTP corpus (Module 2/4)
- Local Ollama on t3.medium
- AWS Bedrock (account model access blocked)
- VS Code SecureCoder extension
