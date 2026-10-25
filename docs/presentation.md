# VERITAS — Capstone Presentation & Defense Guide
**Course:** Information Security (Semester 5)  
**Project:** VERITAS: Automated DevSecOps Vulnerability Intelligence & Multi-Engine Repository Security Platform  
**Target Deployment:** `veritas.trackifyapp.co.in`  
**PowerPoint File:** [`VERITAS_Security_Platform_Presentation.pptx`](../VERITAS_Security_Platform_Presentation.pptx)  
**Browser Slide Deck:** [`docs/presentation.html`](presentation.html)  
**Theme:** Minimal Executive / Academic Light Theme (Pure White / Off-White, Crisp Slate Typography, Structured Flow Diagrams, Zero Emojis)

---

## Slide Deck Architecture (15 Slides)

| # | Slide Title | Category | Primary Visual Representation |
|---|-------------|----------|-------------------------------|
| **1** | **VERITAS Platform Cover** | Title & Identity | Minimal Left Navy Accent Bar + Structured Metadata Grid |
| **2** | **Problem Statement** | Industry Motivation | 2x2 Problem Matrix (Secrets, SCA, Fatigue, Tool Silos) |
| **3** | **Scope & Delivery Matrix** | Scope Boundaries | 5-Phase Technical Roadmap Table (Phases 1 Through 5) |
| **4** | **System Architecture** | Architecture | 3-Tier Layered Box Schematic (Presentation, Middleware, Engine Runner) |
| **5** | **Zero-Trust IAM & Governance** | Security Pillar 1 | 5-Step Account State Machine Flow + 3 Control Cards |
| **6** | **12-Engine Static Analysis Suite** | Security Pillar 2 | Comprehensive Scanner Comparison Matrix Table |
| **7** | **Hybrid AI Reasoning Pipeline** | Security Pillar 3 | 3-Stage Process Pipeline (Deterministic &rarr; OpenRouter &rarr; Groq) |
| **8** | **GitHub Integration & Push CI/CD** | Security Pillar 4 | Continuous Push CI/CD Sequence Flow + Security Cards |
| **9** | **Operational Controls & UX** | Operations | 2x2 Triage Grid (Lifecycle, Suppressions, Diff, Quotas) |
| **10** | **Runtime Defense & HTTP Telemetry** | Runtime | Data Flow Cards (Classifier, Dashboard, AI Security Analyst) |
| **11** | **Compliance & Reporting** | Compliance | 2x2 Export Grid (SARIF 2.1.0, Public Links, Multi-Format, AI Summary) |
| **12** | **Platform Defensive Hardening** | System Hardening | Defense-in-Depth Security Controls Table |
| **13** | **Live Demonstration Workflow** | Demo Sequence | 4-Stage Step-by-Step Validation Sequence |
| **14** | **Technical Stack & Metrics** | Engineering | Full-Stack Implementation & Key Performance Metrics Table |
| **15** | **Conclusion & Academic Defense** | Conclusion | Summary of Contributions & Oral Defense Notice |

---

## Detailed Slide Content & Speaking Scripts

### Slide 1: Platform Cover & Scope
- **Visuals:** Pure white background, deep navy left accent bar, formal typography, structured candidate metadata table.
- **Talking Points:**
  > "Respected evaluators, today I am presenting VERITAS, an automated DevSecOps vulnerability intelligence platform built for our Information Security capstone.
  > Modern software development ships rapidly, but security testing is frequently deferred until post-deployment. VERITAS implements true Shift-Left security: evaluating repositories at the code and commit level, identifying hardcoded credentials, scanning third-party dependency vulnerabilities, executing multi-language static analysis, and synthesizing actionable remediations."

---

### Slide 2: Problem Statement
- **Visuals:** 2x2 structured problem matrix with subtle category borders.
- **Key Cards:**
  1. *Hardcoded Secrets in Git Trees:* API keys, private keys, and cloud credentials accidentally committed to git history remain permanently in commit trees.
  2. *Software Supply Chain Risks (SCA):* 85–90% of modern software consists of open-source packages containing nested, unpatched CVEs.
  3. *Developer Alert Fatigue:* Traditional scanners dump hundreds of unranked warnings with high false-positive rates and zero code fixes.
  4. *Tool Fragmentation & Runtime Blindness:* Teams juggle disjointed CLI scripts with no centralized audit logging, while running servers remain blind to active HTTP attacks.
- **Talking Points:**
  > "Why did we build VERITAS? We analyzed the pain points in modern software engineering. First, credentials frequently leak into git history, where attackers easily harvest them. Second, supply chain attacks proved that third-party packages are an enterprise's biggest liability. Third, traditional scanners cause extreme developer fatigue by reporting hundreds of false positives without providing fixes. Finally, existing scanners evaluate code strictly at rest, leaving the running web service completely oblivious to live reconnaissance."

---

### Slide 3: Scope & Delivery Matrix (Phases 1-5)
- **Visuals:** Formatted table mapping Phases 1 through 5 with functional scope and verified status.
- **Table Data:**
  - *Phase 1 (IAM):* Argon2 hashing, HttpOnly session cookies, Admin approval gate, Geolocation audit trail.
  - *Phase 2 (Workspace):* User-owned workspaces, GitHub OAuth integration, Server-side repo ownership re-verification.
  - *Phase 3 (Engines):* Gitleaks, TruffleHog, Semgrep (9 languages), OSV-Scanner, pip-audit, Trivy, Bandit, Checkov.
  - *Phase 4 (Triage & AI):* OpenRouter code review, Groq Llama-3 synthesis, Fingerprint suppressions, Scan diff, SARIF 2.1.0.
  - *Phase 5 (Push CI/CD):* Render-style auto-scan on push, HMAC SHA-256 signature verification, 7-char short SHA tracking.
- **Talking Points:**
  > "This table delineates our project scope across five coherent phases: Phase 1 delivered zero-trust identity with Argon2 and mandatory admin approval gating. Phase 2 introduced workspaces and GitHub OAuth with strict server-side repo ownership verification. Phase 3 integrated our 12 deterministic static analysis engines. Phase 4 delivered operational controls, suppression fingerprinting, and dual-tier LLM remediation. Phase 5 completed the DevSecOps loop with automated push webhooks verified via HMAC SHA-256 signatures."

---

### Slide 4: System Architecture
- **Visuals:** 3-tier layered architecture diagram detailing Presentation Layer, API Gateway & Security Middleware, and Async Engine Pipeline.
- **Key Architectural Highlights:**
  - *Single-Origin Deployment:* FastAPI serves both JSON REST APIs and the compiled React SPA from the same port, eliminating CORS attack vectors.
  - *Path Separation Principle:* SPA user-interface routes (`/admin/directory`) are strictly separated from API endpoints (`/admin/users`).
  - *Isolated Frontend Shells:* Completely separated shells for `/admin/` and `/user/` with zero shared navigation components.
  - *Ephemeral Sandboxing:* Short-lived scan workdirs (`/tmp/veritas-scans`) automatically destroyed post-scan.
- **Talking Points:**
  > "Let's examine the system architecture. VERITAS utilizes a single-origin deployment where FastAPI serves both our backend APIs and the compiled React SPA. This is a deliberate security decision: it completely eliminates Cross-Origin Resource Sharing (CORS) vulnerabilities and allows HttpOnly session cookies to work natively without cross-domain leakage. The admin and user frontend areas are strictly isolated with independent routing. On the backend, asynchronous workers isolate repository checkouts into ephemeral sandboxes and purge them immediately upon job completion."

---

### Slide 5: Zero-Trust IAM & Governance
- **Visuals:** 5-step horizontal account state machine diagram + 3 structured cards.
- **State Machine Flow:**
  `[ 01: Signup ] -> [ 02: Verification ] -> [ 03: Admin Gate ] -> [ 04: Active Session ] -> [ 05: Geo Audit ]`
- **Technical Safeguards:**
  - `Argon2-cffi` password hashing with memory-hard parameters.
  - SHA-256 database token hashing (no plaintext tokens or session secrets).
  - Fernet encryption (AES-128-CBC + HMAC) for GitHub OAuth secrets.
  - Administrator approval gate: Email verification alone is insufficient to log in; an administrator must approve the account.
  - Multi-provider geolocation consensus (`ip-api`, `ipwho.is`, `ipapi.co`) logged in immutable `audit_events`.
- **Talking Points:**
  > "Identity is our first line of defense. VERITAS adheres to zero-trust principles. Passwords use Argon2, resistant to GPU and ASIC brute-forcing. All database tokens are stored exclusively as SHA-256 hashes. Furthermore, we designed a 5-stage account state machine: verifying email does not allow immediate access; an administrator must explicitly approve the account. Every authentication attempt, admin approval, and project modification is recorded in an immutable audit table enriched with multi-provider IP geolocation consensus."

---

### Slide 6: 12-Engine Static Analysis Suite
- **Visuals:** Comprehensive scanner comparison matrix table.
- **Engine Breakdown:**
  1. *Secrets Detection:* Gitleaks (git commit history), TruffleHog (deep entropy scanning), detect-secrets (heuristic baseline).
  2. *Software Composition (SCA):* Google OSV-Scanner (open-source CVE database), pip-audit (PyPI advisories), Trivy (container & dependency vulnerabilities).
  3. *Static Application Testing (SAST):* Semgrep (polyglot semantic packs across Python, JS/TS, Go, Java, Rust), Bandit (Python AST analysis), njsscan (Node.js vulnerabilities).
  4. *IaC & Linting Security:* Checkov (Terraform & Kubernetes policy-as-code), Hadolint (Dockerfile linter), ShellCheck (shell script static analysis).
- **Talking Points:**
  > "Here is our 12-engine scanning suite. Rather than relying on a single engine, VERITAS orchestrates 12 best-in-class security tools across Secrets, Dependencies, Source Code, and Infrastructure-as-Code. All raw outputs are parsed by our normalization engine into a single unified finding schema containing severity, CWE identifiers, file path, start line, code snippet, and a cryptographic fingerprint."

---

### Slide 7: Hybrid AI Reasoning Pipeline
- **Visuals:** 3-stage sequential flowcards showing Deterministic Execution &rarr; OpenRouter Code Review &rarr; Groq LLM Synthesis.
- **Key Concepts:**
  - *Stage 1 (Deterministic):* Exact rule matches, line numbers, and CWE references without AI hallucination.
  - *Stage 2 (OpenRouter Code Review):* Contextual semantic review of hot files to detect authorization flaws and business logic bugs that regex misses.
  - *Stage 3 (Groq LLM Synthesis):* Rapid inference producing an executive posture report and copy-paste remediation patches.
  - *Fail-Open Architecture:* If external AI services error or keys are missing, deterministic scans complete normally without failing the user.
- **Talking Points:**
  > "A major innovation in VERITAS is our hybrid AI architecture. Scanners alone lack business context; LLMs alone hallucinate. We combine them: Stage 1 runs deterministic engines for exact syntax matches. Stage 2 passes high-risk hot files to OpenRouter for deep semantic review of business logic flaws. Stage 3 uses Groq's high-speed Llama-3 to generate an executive risk posture summary and context-specific code patches. If API keys are not provided, the system fails open—the deterministic scan completes without hindrance."

---

### Slide 8: GitHub Push CI/CD & Ephemeral Sandboxing
- **Visuals:** Sequence flow line + 3 structured cards.
- **Sequence:**
  `[ 1: Git Push ] -> [ 2: Webhook Delivered ] -> [ 3: HMAC Verification ] -> [ 4: Ephemeral Clone ] -> [ 5: Scan & Cleanup ]`
- **Key Features:**
  - Strict Server-Side Repo Ownership Re-verification (blocks forged `github_repo_id` injection attacks).
  - Render/Vercel-style `auto_scan_on_push` per project.
  - Cryptographic `X-Hub-Signature-256` HMAC validation per project secret.
  - Short 7-character commit SHA tracking.
  - Ephemeral sandbox cloning under `/tmp/veritas-scans` with instant teardown.
  - `scan_scope: changed` diff mode for rapid pull-request feedback.
- **Talking Points:**
  > "To make security seamless for developers, Phase 5 introduced Render-style auto-scan on push. A developer links their GitHub account, selects their repository, and turns on auto-scan. VERITAS registers a repository webhook verified with HMAC SHA-256 signatures. Every push to the watched branch triggers an automated scan. We track the 7-character commit SHA, clone the repository into an isolated ephemeral sandbox, execute the engines, and wipe the disk immediately afterward. Importantly, we strictly verify repo ownership server-side to prevent foreign repository attachment attacks."

---

### Slide 9: Operational DevSecOps Controls
- **Visuals:** 2x2 grid covering Finding Lifecycle, Fingerprint Suppressions, Scan Compare Diffing, and Quotas.
- **Key Points:**
  - Finding Lifecycle: `open` &rarr; `triage` &rarr; `fixed` &rarr; `false_positive`.
  - Direct GitHub Blob links: `github.com/{repo}/blob/{sha}/{path}#L{line}`.
  - Suppression Fingerprint: `SHA-256(engine|rule_id|file_path|line_start|title)` ensures suppressed false positives are permanently remembered across future scans.
  - Scan Compare: Tri-state diffing between two commit SHAs (Added, Resolved, Unchanged).
  - Quotas: `SCAN_RATE_LIMIT` and `SCAN_CONCURRENT_LIMIT` enforce compute stability.
- **Talking Points:**
  > "Scanning is only half the battle; managing vulnerabilities at scale is where security succeeds or fails. VERITAS includes comprehensive operational controls: a finding lifecycle with direct links to GitHub blob lines; suppression fingerprinting using SHA-256 hashes to permanently silence approved false positives across re-scans; scan comparison to show managers exactly what vulnerabilities were introduced or resolved between two commits; and compute quotas and cooperative cancellation to prevent denial of service."

---

### Slide 10: Runtime HTTP Telemetry & AI Analyst
- **Visuals:** 3 structured cards (Passive Classifier, Admin Dashboard, AI Security Analyst).
- **Heuristic Attacks Detected:**
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Remote/Local Command Injection
  - Server-Side Request Forgery (SSRF)
  - Path Traversal & Local File Inclusion (LFI)
  - Server-Side Template Injection (SSTI)
  - Authentication anomaly & Brute Force spikes
- **AI Analyst:**
  - Evaluates recent telemetry heuristics.
  - Recommends tailored Nginx or AWS WAF mitigation rules.
- **Talking Points:**
  > "One unique feature that sets VERITAS apart is our Runtime Defense module. Static code scanning protects repositories at rest, but what about the running application? VERITAS includes lightweight HTTP telemetry middleware that passively analyzes live API requests for SQL injection, XSS, SSRF, command injection, and path traversal heuristics. On the Admin Security page, live ApexCharts visualize attack volume, and an AI Security Analyst agent synthesizes recent incidents into actionable WAF rules and countermeasures."

---

### Slide 11: Enterprise Compliance & Multi-Format Exports
- **Visuals:** 2x2 export matrix (SARIF 2.1.0, Public Tokenized Links, Multi-Format Files, AI Executive Summary).
- **Supported Formats:**
  - *SARIF 2.1.0:* OASIS standard, natively ingested by GitHub Advanced Security and IDEs.
  - *Public Tokenized Links:* `/report/{token}` allows clients or external auditors to view read-only finding drawers without login credentials.
  - *Markdown, CSV, JSON, and standalone HTML.*
- **Talking Points:**
  > "Reporting is essential for enterprise compliance. VERITAS exports full SARIF 2.1.0—the OASIS industry standard format. This allows our scan results to be uploaded directly into GitHub Security or enterprise CI/CD systems. Additionally, we provide tokenized public report links so engineers can securely share a read-only report with clients or auditors without creating platform accounts, alongside Markdown, CSV, JSON, and HTML exports."

---

### Slide 12: Platform Defensive Hardening
- **Visuals:** Defense-in-depth security controls table.
- **Platform Safeguards:**
  - Cookies: `HttpOnly`, `SameSite=Lax`, `Secure`.
  - Session tokens stored as SHA-256 hashes; instant revocation upon password reset.
  - Fail-closed API authorization checks.
  - Protection against deactivating or demoting the last active administrator.
  - Admins cannot edit their own roles to prevent privilege escalation.
  - `/admin/files` explorer restricts system trees (`/proc`, `/sys`, `/dev`, `/etc/shadow`) and secrets.
- **Talking Points:**
  > "As a cybersecurity project, VERITAS must be thoroughly hardened itself. We followed defense-in-depth principles: all cookies use HttpOnly and SameSite flags; all tokens in the database are hashed; and our authorization model is strictly fail-closed. We prevent privilege escalation by disallowing admins from changing their own roles, and ensure the system always has at least one active administrator. Even our host filesystem browser restricts access to system directories and secrets."

---

### Slide 13: Live Demonstration Workflow
- **Visuals:** 4-stage chronological validation cards with inputs and outputs.
- **Demo Sequence:**
  1. *User Onboarding:* Signup with Argon2 &rarr; Email token verification &rarr; Admin reviews audit log & approves in `/admin/directory`.
  2. *Connect GitHub:* OAuth link &rarr; Select owned repository &rarr; Enable `auto_scan_on_push`.
  3. *Push & Scan:* Push a commit to GitHub &rarr; Webhook HMAC verified &rarr; Ephemeral clone & 12-engine scan &rarr; AI report generation.
  4. *Triage & Remediate:* Open finding drawer &rarr; Review AI code patch &rarr; Click GitHub line link &rarr; Suppress false positive &rarr; Export SARIF.
- **Talking Points:**
  > "Here is our live demonstration walkthrough: 1) The user signs up and verifies their email, and lands in pending approval. The administrator logs in, inspects the audit trail, and approves the account. 2) The user connects GitHub and enables auto-scan on push. 3) A git push occurs; VERITAS receives the webhook, verifies the HMAC signature, and launches the scan pipeline. 4) The scan completes; the user views the finding drawer, inspects AI remediation patches, jumps to the GitHub blob, and exports the SARIF report."

---

### Slide 14: Technical Stack & Metrics
- **Visuals:** Full-stack implementation table and verified performance metrics.
- **Talking Points:**
  > "Here is the technical stack powering VERITAS. The backend is built with asynchronous FastAPI and SQLAlchemy, utilizing Argon2 and Fernet cryptography. The frontend is built with React 18, Vite, and TypeScript with responsive CSS and interactive ApexCharts. We integrate 12 scanning tools with OpenRouter and Groq LLMs. Everything was engineered with strict server-side validation and automated CI/CD push capabilities."

---

### Slide 15: Conclusion & Q&A Defense Strategy
- **Visuals:** 2 structured cards (Summary of Contributions, Future Scope) + formal oral defense banner.
- **Talking Points:**
  > "In conclusion, VERITAS proves that robust application security does not have to slow developers down. By uniting multi-engine static analysis, dual-tier AI remediation, zero-trust governance, and live runtime threat telemetry, VERITAS provides an end-to-end security fabric for modern engineering organizations. Thank you very much. I am now open to your questions and feedback."

---

## Academic Viva / Evaluation Q&A Defense

### Q1: Why did you choose Argon2 over BCrypt or PBKDF2?
**Model Answer:**
> "Argon2 (specifically Argon2id) won the Password Hashing Competition (PHC) and is the current standard recommended by OWASP. Unlike BCrypt or PBKDF2, which are purely CPU-bound, Argon2 is a memory-hard function. This makes it resistant to massively parallel offline brute-force attacks running on specialized GPUs or ASIC rigs."

### Q2: How do you prevent attackers from spoofing GitHub Push Webhooks?
**Model Answer:**
> "Every project with auto-scan enabled is provisioned with a cryptographically generated HMAC secret stored in encrypted format. When GitHub delivers a webhook, it sends the `X-Hub-Signature-256` header containing the HMAC-SHA256 signature of the payload body. Our endpoint at `/webhooks/github` computes the HMAC signature using the project's secret and performs a constant-time comparison before executing any scan."

### Q3: What is the risk of using an LLM in security scanning, and how does VERITAS mitigate it?
**Model Answer:**
> "The primary risk of LLMs in security is hallucination—either inventing vulnerabilities that do not exist or missing actual syntax flaws. VERITAS solves this by enforcing a hybrid pipeline: our deterministic engines (Semgrep, OSV, Gitleaks) establish ground truth for line numbers, rule IDs, and CVEs. The LLM is used strictly in a secondary role for contextual semantic review and generating remediation code. Additionally, the system is fail-open: if the LLM is unavailable, deterministic results are delivered unimpeded."

### Q4: How does VERITAS prevent a malicious user from scanning repositories they do not own?
**Model Answer:**
> "We implement strict server-side validation. During GitHub OAuth linking, VERITAS retrieves the authenticated GitHub user profile. When the user attaches a repository ID, the backend re-queries the GitHub API using the user's encrypted access token and verifies that the user is the explicit owner of that repository. Client-submitted IDs are never trusted blindly."

### Q5: What happens if two scans are triggered simultaneously for the same project or server?
**Model Answer:**
> "We enforce both concurrency limits (`SCAN_CONCURRENT_LIMIT=2`) and rate limits (`SCAN_RATE_LIMIT=10/hr`) on scan creation. If a user exceeds their quota, the API responds with HTTP 429 (Too Many Requests) and logs a rate-limited security audit event. Furthermore, each scan executes in an isolated, timestamped ephemeral workdir under `/tmp/veritas-scans`, preventing directory contention."

### Q6: What is SARIF 2.1.0 and why is it important for DevSecOps?
**Model Answer:**
> "SARIF (Static Analysis Results Interchange Format) is an OASIS standard JSON schema designed to normalize output from static analysis tools. By emitting valid SARIF 2.1.0, VERITAS scan results can be ingested directly into the GitHub Advanced Security Code Scanning tab, GitLab Security dashboards, SonarQube, or VS Code SARIF viewers without any custom transformation scripts."

### Q7: Why do you store session tokens as SHA-256 hashes instead of raw tokens?
**Model Answer:**
> "If an attacker performs an SQL injection or acquires a database backup, having raw session tokens would allow them to hijack all active user sessions instantly. By storing only the SHA-256 hash of the session token in the database, the stored hash cannot be used to forge the cookie. The server hashes the incoming cookie token and compares it to the database hash."

### Q8: What prevents an administrator from performing privilege escalation or locking themselves out?
**Model Answer:**
> "In `backend/app/services/auth.py`, we implement two hard fail-closed rules:
> 1. An administrator is strictly prohibited from altering their own role (preventing self-elevation or accidental demotion).
> 2. The platform queries the database to ensure that the count of active administrators is greater than one before permitting any deactivation or demotion of an admin. This ensures the system cannot be orphaned without an active administrator."

### Q9: How does suppression fingerprinting work across git commits?
**Model Answer:**
> "Line numbers frequently shift when code is edited. If a suppression was based solely on line number, adding a single line at the top of a file would unsuppress the false positive. Our fingerprint formula combines `SHA-256(engine|rule_id|file_path|line_start|title)`. If the finding fingerprint matches an existing entry in `finding_suppressions`, the finding is automatically marked as `false_positive` on all future scans."

### Q10: How does the HTTP classifier detect attacks without violating user privacy or PII?
**Model Answer:**
> "Our `http_classifier.py` and middleware operate strictly on metadata: request HTTP method, URL path, query parameter keys/values, and specific attack headers. It uses regex and heuristic pattern matching for common attack strings (e.g. `' OR 1=1`, `<script>`, `../..`, `{{7*7}}`). It explicitly never logs or stores request body payloads, user passwords, or session cookies, ensuring full compliance with data privacy standards."

---

## Keyboard Shortcuts in `docs/presentation.html`

- **`Right Arrow` / `Space` / `L` / `K`**: Next Slide
- **`Left Arrow` / `H` / `J`**: Previous Slide
- **`O`**: Open Slide Overview Grid
- **`N`**: Toggle Speaker Notes Drawer
- **`F`**: Toggle Fullscreen Mode
- **`P`**: Print to PDF / Open Print Dialog
- **`Home` / `End`**: Jump to First / Last Slide
