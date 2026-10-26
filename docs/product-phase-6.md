# Product — VERITAS Phase 6 (Enterprise Intelligence & Active Defense)

## Purpose

Deliver end-to-end multi-engine vulnerability correlation, real-time threat intelligence enrichment, compliance governance, live dynamic application security testing (DAST), automated pull request remediations, and active intrusion prevention system (IPS) quarantine.

---

## Phase 6A: Enterprise Intelligence & Correlation

- **Cross-Engine Vulnerability Correlation**: Deduplication and fingerprinting across SAST, Secrets, SCA, and Trivy SBOM.
- **Threat Intelligence Feeds**: CISA KEV (Known Exploited Vulnerabilities) and FIRST EPSS (Exploit Prediction Scoring System) live cache and enrichment.
- **CycloneDX SBOM Generation**: Automated software bill of materials extraction with copyleft license policy checks (GPL, AGPL, LGPL).

---

## Phase 6B: Enterprise Governance & Compliance

- **Project RBAC**: 4 granular project-level roles (`admin`, `lead`, `developer`, `auditor`).
- **Two-Person Suppression Governance**: Optional project setting requiring lead approval for finding suppressions, with automatic SLA-based expiration and reopening.
- **Compliance Posture Reports**: Framework mapping for OWASP Top 10 (2021), SOC 2 Type II, and ISO/IEC 27001 with exportable verification certificates.

---

## Phase 6C: Live DAST, Active IPS & Remediation Engine

### 1. Live Web App DAST Probe Engine (`dast_probe.py`)
- Target URL validation with anti-SSRF protections against private, loopback, link-local, multicast, and cloud metadata ranges (AWS `169.254.169.254`, GCP metadata).
- Target TLS/SSL certificate health and validity inspection.
- Security headers audit: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
- Cookie security audit: `Secure`, `HttpOnly`, and `SameSite` compliance.
- CORS misconfiguration probe: Reflection of arbitrary `Origin: https://evil-attacker.example` with `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true`.
- Sensitive file exposure probes: Signature-verified checks for `/.env`, `/.git/HEAD`, `/.git/config`, `/openapi.json`, `/swagger.json`.

### 2. Automated Fix PR / Remediation Generator (`remediation.py`)
- Deterministic unified diff generation for common vulnerability patterns (SQLi parameterized queries, innerHTML XSS sanitization, path traversal normalization, security headers).
- Optional Groq LLM refinement with fallback to deterministic templates.
- Markdown Pull Request plan generation including branch name, commit message, PR title, body, and test checklists.
- Endpoint: `POST /workspace/findings/{finding_id}/fix-plan`.

### 3. Active IPS Auto-Quarantine & Pre-Routing Block
- Automated IPS quarantine: When an IP triggers $\ge 5$ attack signals within 60 seconds, it is quarantined for 60 minutes in `blocked_ips` and in-memory TTL cache.
- Pre-routing ASGI middleware enforcement: Returns HTTP 403 Forbidden with `{"detail": "IP address temporarily quarantined by VERITAS Active IPS"}`.
- Admin management endpoints:
  - `GET /admin/security/blocked-ips`: List all quarantined and expired IPs.
  - `POST /admin/security/blocked-ips`: Manually quarantine an IP address.
  - `DELETE /admin/security/blocked-ips/{ip_address}`: 1-click unblock and eviction from active cache.

### 4. Interactive 5x5 Risk Matrix & UI Controls
- `RiskMatrixCard.tsx`: Interactive $5 \times 5$ Likelihood $\times$ Impact risk heatmap with severity counts and 1-click cell filtering.
- `ScanReportModal.tsx`: Visual matrix filter state and unified diff / PR fix plan modal display.
- `UserProjectDetailPage.tsx`: DAST live base URL configuration, two-person suppression checkbox, SLA day counters, and team access governance.
- `AdminSecurityPage.tsx`: Live Quarantined IPs (Active IPS) card with manual block and 1-click unblock.
