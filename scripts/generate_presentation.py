"""
Generate a professional, minimalist, light-themed PowerPoint presentation for VERITAS.
Design guidelines:
- Strict Light Theme (pure white/off-white background, high-contrast dark slate text).
- Zero "AI-slop" aesthetics: NO emojis, NO neon glows, NO dark cyberpunk schemes, NO gradient fluffs.
- Professional, corporate/academic layout: clean structured cards, system flow diagrams, data tables, and metrics.
- Standard typography: Segoe UI / Arial / Calibri.
- Comprehensive speaker notes on every slide for formal academic defense.
"""

import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.dml.color import RGBColor

# ---------------------------------------------------------
# PALETTE DEFINITION (Professional Executive / Academic Light Theme)
# ---------------------------------------------------------
BG_COLOR = RGBColor(255, 255, 255)         # Pure White
BG_PAGE = RGBColor(248, 250, 252)          # #F8FAFC Off-White / Light Slate
CARD_BG = RGBColor(255, 255, 255)          # Card White
CARD_HEADER_BG = RGBColor(241, 245, 249)   # #F1F5F9 Subtle Table/Header Fill
BORDER_COLOR = RGBColor(203, 213, 225)     # #CBD5E1 Clean Border
BORDER_SUBTLE = RGBColor(226, 232, 240)    # #E2E8F0 Table Grid Lines

# Typography Colors
TEXT_PRIMARY = RGBColor(15, 23, 42)        # #0F172A Deep Charcoal/Black
TEXT_SECONDARY = RGBColor(51, 65, 85)      # #334155 Slate Body
TEXT_MUTED = RGBColor(100, 116, 139)       # #64748B Secondary / Metadata

# Restrained, Professional Accents (No Neons)
ACCENT_PRIMARY = RGBColor(30, 58, 138)     # #1E3A8A Corporate Deep Navy
ACCENT_BLUE = RGBColor(2, 132, 199)        # #0284C7 Steel Blue
ACCENT_CRIMSON = RGBColor(185, 28, 28)     # #B91C1C Security/Critical Alert
ACCENT_AMBER = RGBColor(180, 83, 9)        # #B45309 Warning/Audit Alert
ACCENT_GREEN = RGBColor(21, 128, 61)       # #15803D Success/Resolved

FONT_HEADING = "Segoe UI"
FONT_BODY = "Segoe UI"

def set_slide_background(slide):
    """Sets a clean, light off-white background."""
    bg_shape = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5)
    )
    bg_shape.fill.solid()
    bg_shape.fill.fore_color.rgb = BG_PAGE
    bg_shape.line.fill.background()
    return bg_shape

def add_header(slide, section_tag, title_text, subtitle_text=""):
    """Creates a standard minimalist header."""
    header_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.45), Inches(11.733), Inches(1.2))
    tf = header_box.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    # Section Tag (uppercase, muted navy)
    p0 = tf.paragraphs[0]
    p0.text = section_tag.upper()
    p0.font.name = FONT_HEADING
    p0.font.size = Pt(9.5)
    p0.font.bold = True
    p0.font.color.rgb = ACCENT_PRIMARY
    p0.space_after = Pt(3)

    # Title
    p1 = tf.add_paragraph()
    p1.text = title_text
    p1.font.name = FONT_HEADING
    p1.font.size = Pt(21)
    p1.font.bold = True
    p1.font.color.rgb = TEXT_PRIMARY

    # Subtitle
    if subtitle_text:
        p1.space_after = Pt(2)
        p2 = tf.add_paragraph()
        p2.text = subtitle_text
        p2.font.name = FONT_BODY
        p2.font.size = Pt(10.5)
        p2.font.color.rgb = TEXT_MUTED

    # Subtle bottom divider line
    div = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.68), Inches(11.733), Inches(0.015)
    )
    div.fill.solid()
    div.fill.fore_color.rgb = BORDER_COLOR
    div.line.fill.background()

def add_card(slide, left, top, width, height, title="", title_color=TEXT_PRIMARY, border_color=BORDER_COLOR, bg_color=CARD_BG):
    """Creates a clean, minimal bordered card container."""
    card = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = bg_color
    card.line.color.rgb = border_color
    card.line.width = Pt(1)

    if title:
        tf = card.text_frame
        tf.word_wrap = True
        tf.margin_left = Inches(0.25)
        tf.margin_right = Inches(0.25)
        tf.margin_top = Inches(0.18)
        tf.margin_bottom = Inches(0.08)
        p = tf.paragraphs[0]
        p.text = title
        p.font.name = FONT_HEADING
        p.font.size = Pt(11.5)
        p.font.bold = True
        p.font.color.rgb = title_color
        p.alignment = PP_ALIGN.LEFT
    return card

def add_table(slide, left, top, width, height, rows, cols, col_widths=None):
    """Adds a clean, professionally formatted table."""
    table_shape = slide.shapes.add_table(rows, cols, left, top, width, height)
    table = table_shape.table
    if col_widths:
        for idx, w in enumerate(col_widths):
            table.columns[idx].width = w
    return table

def format_table_header_cell(cell, text):
    """Formats header cells with subtle gray fill and bold text."""
    cell.fill.solid()
    cell.fill.fore_color.rgb = CARD_HEADER_BG
    tf = cell.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.12)
    tf.margin_right = Inches(0.12)
    tf.margin_top = Inches(0.08)
    tf.margin_bottom = Inches(0.08)
    p = tf.paragraphs[0]
    p.text = text
    p.font.name = FONT_HEADING
    p.font.size = Pt(9.5)
    p.font.bold = True
    p.font.color.rgb = TEXT_PRIMARY

def format_table_data_cell(cell, text, bold=False, text_color=TEXT_SECONDARY, font_size=9):
    """Formats standard table data cells."""
    cell.fill.solid()
    cell.fill.fore_color.rgb = RGBColor(255, 255, 255)
    tf = cell.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.12)
    tf.margin_right = Inches(0.12)
    tf.margin_top = Inches(0.08)
    tf.margin_bottom = Inches(0.08)
    p = tf.paragraphs[0]
    p.text = text
    p.font.name = FONT_BODY
    p.font.size = Pt(font_size)
    p.font.bold = bold
    p.font.color.rgb = text_color

def add_speaker_notes(slide, notes_text):
    """Appends verbatim speaker notes for academic presentation."""
    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = notes_text

# =========================================================
# MAIN PRESENTATION BUILDER
# =========================================================
def create_presentation():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # -----------------------------------------------------
    # SLIDE 1: Title Slide (Minimal, Formal Academic)
    # -----------------------------------------------------
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Clean left border accent (Deep Navy)
    bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.8), Inches(0.08), Inches(3.6))
    bar.fill.solid()
    bar.fill.fore_color.rgb = ACCENT_PRIMARY
    bar.line.fill.background()

    # Title text box
    tbox = s1.shapes.add_textbox(Inches(1.1), Inches(1.8), Inches(11.2), Inches(3.6))
    tf1 = tbox.text_frame
    tf1.word_wrap = True
    tf1.margin_left = tf1.margin_top = tf1.margin_right = tf1.margin_bottom = 0

    p_badge = tf1.paragraphs[0]
    p_badge.text = "INFORMATION SECURITY  |  SEMESTER 5 CAPSTONE PROJECT"
    p_badge.font.name = FONT_HEADING
    p_badge.font.size = Pt(11)
    p_badge.font.bold = True
    p_badge.font.color.rgb = ACCENT_PRIMARY
    p_badge.space_after = Pt(12)

    p_main = tf1.add_paragraph()
    p_main.text = "VERITAS"
    p_main.font.name = FONT_HEADING
    p_main.font.size = Pt(44)
    p_main.font.bold = True
    p_main.font.color.rgb = TEXT_PRIMARY
    p_main.space_after = Pt(8)

    p_sub = tf1.add_paragraph()
    p_sub.text = "Automated DevSecOps Vulnerability Intelligence & Multi-Engine Repository Security Platform"
    p_sub.font.name = FONT_BODY
    p_sub.font.size = Pt(15)
    p_sub.font.bold = True
    p_sub.font.color.rgb = ACCENT_BLUE
    p_sub.space_after = Pt(14)

    p_desc = tf1.add_paragraph()
    p_desc.text = "A zero-trust repository security platform orchestrating 12 deterministic analysis engines, dual-tier LLM triage and remediation, automated GitHub push CI/CD webhooks, and live HTTP intrusion telemetry."
    p_desc.font.name = FONT_BODY
    p_desc.font.size = Pt(11)
    p_desc.font.color.rgb = TEXT_SECONDARY

    # Footer Metadata Table
    foot_table = add_table(s1, Inches(0.8), Inches(5.7), Inches(11.733), Inches(0.9), 1, 4, 
                           [Inches(2.8), Inches(2.8), Inches(3.1), Inches(3.033)])
    format_table_data_cell(foot_table.cell(0, 0), "Candidate: Bharani Sri", bold=True, text_color=TEXT_PRIMARY, font_size=9.5)
    format_table_data_cell(foot_table.cell(0, 1), "Course: Information Security", bold=False, text_color=TEXT_SECONDARY, font_size=9.5)
    format_table_data_cell(foot_table.cell(0, 2), "Architecture: FastAPI + React SPA", bold=False, text_color=TEXT_SECONDARY, font_size=9.5)
    format_table_data_cell(foot_table.cell(0, 3), "Target: veritas.trackifyapp.co.in", bold=True, text_color=ACCENT_PRIMARY, font_size=9.5)

    add_speaker_notes(s1,
        "Good morning/afternoon respected evaluators. Today I am presenting VERITAS, a comprehensive DevSecOps vulnerability intelligence platform.\n"
        "Modern application development moves at high speed, but security testing is frequently deferred until post-deployment. "
        "VERITAS implements true Shift-Left security: inspecting repositories at the code and commit level, identifying hardcoded credentials, "
        "scanning third-party dependency vulnerabilities, executing multi-language static analysis, and synthesizing actionable remediations."
    )

    # -----------------------------------------------------
    # SLIDE 2: Problem Statement (Minimal Grid)
    # -----------------------------------------------------
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "Problem Statement", "Security Gaps in the Modern Software Development Life Cycle",
               "Analysis of systemic vulnerabilities and developer workflow friction")

    problems = [
        ("1. Hardcoded Secret Leaks in Git History", ACCENT_CRIMSON,
         "• Accidental Credential Commits: Developers push private keys, API tokens, and database passwords directly into source code repositories.\n"
         "• Persistent Commit Tree: Deleting a secret in a follow-up commit does not purge it from git history; attackers easily extract historical objects.\n"
         "• Impact: Unauthorized cloud infrastructure takeovers and compromised third-party integrations."),

        ("2. Software Supply Chain Vulnerabilities (SCA)", ACCENT_AMBER,
         "• Open-Source Reliance: 85-90% of modern software consists of third-party open-source libraries and package ecosystems.\n"
         "• Nested Transitive Dependencies: Deep dependency trees mask known CVEs (e.g., Log4Shell, event-stream, prototype pollution).\n"
         "• Impact: Attackers compromise applications through unpatched upstream components."),

        ("3. Alert Fatigue & Lack of Remediation", ACCENT_PRIMARY,
         "• High False Positive Volume: Traditional static analysis engines dump hundreds of unprioritized, contextless warnings.\n"
         "• Absence of Code Fixes: Legacy tools state that a vulnerability exists, but do not provide contextual, copy-paste remediation code.\n"
         "• Impact: Engineering teams ignore security reports to preserve release velocity."),

        ("4. Fragmented Point Solutions & Runtime Blindness", ACCENT_BLUE,
         "• Tooling Silos: Teams run disjointed CLI tools with no centralized identity, access governance, or persistent audit trail.\n"
         "• Blind at Runtime: Static code analysis evaluates code strictly at rest, leaving running applications oblivious to active HTTP attacks.\n"
         "• Impact: Complete loss of audit accountability and delayed threat response.")
    ]

    for i, (title, color, text) in enumerate(problems):
        col = i % 2
        row = i // 2
        left = Inches(0.8 + col * 6.0)
        top = Inches(1.9 + row * 2.55)
        card = add_card(s2, left, top, Inches(5.7), Inches(2.35), title, color)
        
        tb = s2.shapes.add_textbox(left + Inches(0.25), top + Inches(0.52), Inches(5.2), Inches(1.7))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = text
        p.font.name = FONT_BODY
        p.font.size = Pt(9.2)
        p.font.color.rgb = TEXT_SECONDARY

    add_speaker_notes(s2,
        "Here is the core problem statement: First, credentials leak into git history, where attackers easily harvest them. "
        "Second, 90% of modern applications rely on open-source packages containing nested, unpatched CVEs. "
        "Third, existing scanners produce severe alert fatigue by outputting hundreds of unranked warnings without actionable code fixes. "
        "Finally, fragmented tooling leaves security teams without centralized audit trails, and static tools remain blind to active HTTP attacks. "
        "VERITAS was engineered specifically to solve these four operational failures."
    )

    # -----------------------------------------------------
    # SLIDE 3: Architectural Scope & Phase Breakdown (Structured Matrix)
    # -----------------------------------------------------
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "Scope & Implementation", "System Delivery Matrix: Phases 1 Through 5",
               "Architectural scope boundaries and verified functional implementations")

    scope_table = add_table(s3, Inches(0.8), Inches(1.9), Inches(11.733), Inches(4.7), 6, 4,
                            [Inches(1.8), Inches(3.2), Inches(4.3), Inches(2.433)])
    
    headers = ["Phase", "Core Functional Scope", "Security & Technical Controls", "Status"]
    for c_idx, h in enumerate(headers):
        format_table_header_cell(scope_table.cell(0, c_idx), h)

    phases_data = [
        ("Phase 1: IAM", "Identity & User Management", "Argon2 hashing, HttpOnly session cookies, Admin approval gate, Geolocation audit trail", "Verified Production"),
        ("Phase 2: Workspace", "Projects & GitHub OAuth", "User-owned workspaces, GitHub OAuth link, Server-side repo ownership re-verification", "Verified Production"),
        ("Phase 3: Scanning", "12-Engine Static Suite", "Gitleaks, TruffleHog, Semgrep (9 langs), OSV-Scanner, pip-audit, Trivy, Bandit, Checkov", "Verified Production"),
        ("Phase 4: Triage & AI", "Operational Controls & AI", "OpenRouter code review, Groq Llama-3 synthesis, Fingerprint suppressions, Scan diff, SARIF", "Verified Production"),
        ("Phase 5: Push CI/CD", "Automated Push Webhooks", "Render-style auto-scan on push, HMAC SHA-256 signature verification, 7-char SHA tracking", "Verified Production")
    ]

    for r_idx, row in enumerate(phases_data, start=1):
        for c_idx, val in enumerate(row):
            is_bold = (c_idx == 0 or c_idx == 3)
            col_color = ACCENT_PRIMARY if c_idx == 0 else (ACCENT_GREEN if c_idx == 3 else TEXT_SECONDARY)
            format_table_data_cell(scope_table.cell(r_idx, c_idx), val, bold=is_bold, text_color=col_color, font_size=9)

    add_speaker_notes(s3,
        "This table delineates our project scope across five coherent phases: "
        "Phase 1 delivered zero-trust identity with Argon2 and mandatory admin approval gating. "
        "Phase 2 introduced workspaces and GitHub OAuth with strict server-side repo ownership verification. "
        "Phase 3 integrated our 12 deterministic static analysis engines. "
        "Phase 4 delivered operational controls, suppression fingerprinting, and dual-tier LLM remediation. "
        "Phase 5 completed the DevSecOps loop with automated push webhooks verified via HMAC SHA-256 signatures."
    )

    # -----------------------------------------------------
    # SLIDE 4: System Architecture (Clean 3-Tier Layered Diagram)
    # -----------------------------------------------------
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "System Architecture", "Single-Origin FastAPI & React SPA Request Architecture",
               "Eliminating cross-origin vulnerabilities while maintaining strict boundary separation")

    arch_layers = [
        ("Tier 1: Presentation Layer (Vite + React 18 SPA)", ACCENT_PRIMARY, Inches(0.8), Inches(1.9), Inches(11.733), Inches(1.35),
         "• Strict Shell Isolation: Independent routing shells for /admin/ (Directory, Audit, Security Dashboard, Filesystem) and /user/ (Workspace, Projects, Scans).\n"
         "• Path Routing Principle: UI page routes (/admin/directory) strictly decoupled from JSON API endpoints (/admin/users).\n"
         "• Real-Time Visualizations: ApexCharts threat graphs, slide-out finding drawers, and live scan progress indicators."),

        ("Tier 2: API Gateway & Security Middleware (FastAPI)", ACCENT_BLUE, Inches(0.8), Inches(3.45), Inches(11.733), Inches(1.5),
         "• Single-Origin Architecture: FastAPI serves both the JSON API routes and the compiled React SPA assets, eliminating CORS attack surfaces.\n"
         "• Auth & Session Guard: Enforces veritas_session cookie verification, role-based access control (RBAC), and in-memory rate limiting (429).\n"
         "• Passive HTTP Classifier: Middleware inspects paths, query parameters, and headers for SQLi, XSS, SSRF heuristics (zero body/PII logging).\n"
         "• Webhook Gateway: Validates X-Hub-Signature-256 HMAC signatures on incoming GitHub push notifications."),

        ("Tier 3: Asynchronous Engine Pipeline & Persistence (SQLAlchemy 2.0)", ACCENT_PRIMARY, Inches(0.8), Inches(5.15), Inches(11.733), Inches(1.55),
         "• Ephemeral Sandboxes: Clones target repositories into short-lived directories (/tmp/veritas-scans), purged immediately post-scan.\n"
         "• Multi-Engine Dispatcher: Orchestrates 12 CLI security engines with normalized finding outputs (severity, CWE, file, line, fingerprint).\n"
         "• Dual AI Reasoning: OpenRouter hot-file code review + Groq Llama-3 executive risk report synthesis with fail-open fallback.\n"
         "• Persistence: SQLite in local development, PostgreSQL in production. SHA-256 hashed tokens and Fernet-encrypted GitHub secrets.")
    ]

    for title, color, left, top, width, height, text in arch_layers:
        card = add_card(s4, left, top, width, height, title, color)
        tb = s4.shapes.add_textbox(left + Inches(0.25), top + Inches(0.42), width - Inches(0.5), height - Inches(0.5))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = text
        p.font.name = FONT_BODY
        p.font.size = Pt(8.8)
        p.font.color.rgb = TEXT_SECONDARY

    add_speaker_notes(s4,
        "Here is the system architecture. Notice our single-origin deployment: FastAPI serves both backend APIs and the compiled React SPA. "
        "This is an intentional security design: it eliminates CORS vulnerabilities and allows HttpOnly session cookies to operate natively. "
        "Admin and User interfaces have completely separated routing boundaries. "
        "In Tier 3, our asynchronous scan runner clones repositories into isolated, short-lived sandboxes and purges them immediately upon completion."
    )

    # -----------------------------------------------------
    # SLIDE 5: Zero-Trust Identity & Access Management (State Machine & Controls)
    # -----------------------------------------------------
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "Security Pillar 1: IAM", "Zero-Trust Account Lifecycle & Geolocation Auditing",
               "Cryptographically hardened authentication, approval gating, and immutable event tracking")

    # State machine horizontal diagram
    sm_box = add_card(s5, Inches(0.8), Inches(1.9), Inches(11.733), Inches(1.1), "Account State Machine Transition Pipeline", ACCENT_PRIMARY)
    sm_tb = s5.shapes.add_textbox(Inches(1.0), Inches(2.35), Inches(11.3), Inches(0.5))
    sm_tf = sm_tb.text_frame
    sm_tf.margin_left = sm_tf.margin_top = sm_tf.margin_right = sm_tf.margin_bottom = 0
    p_sm = sm_tf.paragraphs[0]
    p_sm.text = "[ 01: Signup ]   -->   [ 02: Pending Verification ]   -->   [ 03: Pending Approval ]   -->   [ 04: Active ]  |  [ Rejected ]  |  [ Deactivated ]"
    p_sm.font.name = FONT_HEADING
    p_sm.font.size = Pt(9.5)
    p_sm.font.bold = True
    p_sm.font.color.rgb = ACCENT_PRIMARY

    # 3 Category cards
    iam_cols = [
        ("Cryptographic Safeguards", ACCENT_PRIMARY, [
            ("Argon2 Password Hashing: ", "Uses memory-hard argon2-cffi parameters to resist GPU/ASIC offline brute-force cracking."),
            ("SHA-256 Token Hashing: ", "Session tokens, verify tokens, and reset tokens are hashed before storage in the database."),
            ("Fernet Secret Encryption: ", "GitHub OAuth access tokens are encrypted at rest using AES-128-CBC with HMAC-SHA256 authentication.")
        ]),
        ("Authorization Guardrails", ACCENT_CRIMSON, [
            ("Mandatory Admin Approval: ", "Email verification alone is insufficient to log in; an administrator must approve the account."),
            ("Session Revocation: ", "Password resets instantly delete all active session rows across all user devices."),
            ("Fail-Closed Admin Protections: ", "System prohibits deactivating the last active administrator; admins cannot alter their own roles.")
        ]),
        ("Geolocation Audit Logging", ACCENT_BLUE, [
            ("Immutable Audit Trail: ", "audit_events records all authentication attempts, status transitions, and project actions."),
            ("Consensus Geolocation: ", "Cross-queries ip-api, ipwho.is, and ipapi.co to record client city, region, and country."),
            ("Contextual Metadata: ", "Logs rich JSON context including HTTP status codes (200, 401, 429) for forensic tracing.")
        ])
    ]

    for i, (title, color, bullets) in enumerate(iam_cols):
        left = Inches(0.8 + i * 4.0)
        top = Inches(3.2)
        card = add_card(s5, left, top, Inches(3.8), Inches(3.5), title, color)
        
        tb = s5.shapes.add_textbox(left + Inches(0.25), top + Inches(0.48), Inches(3.3), Inches(2.85))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        
        for idx, (b_title, b_desc) in enumerate(bullets):
            p = tf.paragraphs[0] if idx == 0 else tf.add_paragraph()
            p.text = f"• {b_title}"
            p.font.name = FONT_BODY
            p.font.size = Pt(9.5)
            p.font.bold = True
            p.font.color.rgb = TEXT_PRIMARY
            p.space_after = Pt(2)
            
            p2 = tf.add_paragraph()
            p2.text = b_desc
            p2.font.name = FONT_BODY
            p2.font.size = Pt(8.8)
            p2.font.color.rgb = TEXT_SECONDARY
            p2.space_after = Pt(8)

    add_speaker_notes(s5,
        "Identity is the security perimeter. VERITAS implements a zero-trust model: "
        "Passwords use Argon2, recommended by OWASP for its memory-hard properties. All tokens are stored as SHA-256 hashes. "
        "Notice our 5-stage lifecycle: even after email verification, users cannot access the platform until an administrator approves them. "
        "Every security event is logged in an immutable audit trail enriched with multi-provider IP geolocation consensus."
    )

    # -----------------------------------------------------
    # SLIDE 6: 12-Engine Static Analysis Suite (Data Matrix)
    # -----------------------------------------------------
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "Security Pillar 2: Scanning Engines", "12-Engine Static Analysis & Vulnerability Matrix",
               "Comprehensive deterministic coverage spanning Secrets, SCA, SAST, and IaC Linters")

    eng_table = add_table(s6, Inches(0.8), Inches(1.9), Inches(11.733), Inches(4.7), 5, 4,
                          [Inches(2.5), Inches(3.2), Inches(4.3), Inches(1.733)])
    
    eng_headers = ["Category", "Integrated Tooling", "Technical Scope & Methodology", "Output Target"]
    for c_idx, h in enumerate(eng_headers):
        format_table_header_cell(eng_table.cell(0, c_idx), h)

    eng_rows = [
        ("Secrets Detection", "Gitleaks, TruffleHog, detect-secrets", "Deep git commit history scanning, high-entropy token analysis, regex-based API key detection", "Normalized Findings"),
        ("Software Composition (SCA)", "Google OSV-Scanner, pip-audit, Trivy", "Lockfile & manifest matching against Google OSV database, PyPI security advisories, container CVEs", "Normalized Findings"),
        ("Static Application Testing (SAST)", "Semgrep (Basic/Standard/Strict), Bandit, njsscan", "Semantic polyglot AST rules across 9 languages (Python, JS/TS, Go, Java, Rust), Python OWASP analysis", "Normalized Findings"),
        ("IaC & Linting Security", "Checkov, Hadolint, ShellCheck", "Policy-as-code for Terraform & Kubernetes, Dockerfile container hygiene, bash injection analysis", "Normalized Findings")
    ]

    for r_idx, row in enumerate(eng_rows, start=1):
        for c_idx, val in enumerate(row):
            is_bold = (c_idx == 0)
            col_color = ACCENT_PRIMARY if c_idx == 0 else TEXT_SECONDARY
            format_table_data_cell(eng_table.cell(r_idx, c_idx), val, bold=is_bold, text_color=col_color, font_size=9)

    add_speaker_notes(s6,
        "Here is our 12-engine scanning suite. Rather than relying on a single engine, VERITAS orchestrates 12 best-in-class tools: "
        "Gitleaks and TruffleHog analyze commit history for secrets; OSV-Scanner and pip-audit track known CVEs in third-party packages; "
        "Semgrep, Bandit, and njsscan perform AST static code analysis; and Checkov, Hadolint, and ShellCheck ensure configuration safety. "
        "All outputs are normalized into a unified finding model."
    )

    # -----------------------------------------------------
    # SLIDE 7: Hybrid AI Pipeline (Process Flow)
    # -----------------------------------------------------
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "Security Pillar 3: AI Augmentation", "Deterministic Engines + Dual-Tier LLM Intelligence",
               "Combining exact syntax pattern matching with contextual reasoning and actionable code patches")

    ai_steps = [
        ("Stage 1: Deterministic Engine Execution", ACCENT_PRIMARY, Inches(0.8), Inches(1.9), Inches(3.7), Inches(4.7),
         "PRECISION SYNTAX SCANNING\n\n"
         "• Executes selected rule-based scanners (Semgrep, OSV, Gitleaks, etc.)\n"
         "• Generates exact line numbers, rule IDs, and CWE references\n"
         "• Zero risk of AI hallucination on baseline code patterns\n"
         "• Normalizes raw outputs and identifies candidate high-risk 'hot files'\n\n"
         "Output: Standardized finding objects + candidate files"),

        ("Stage 2: OpenRouter Semantic Code Review", ACCENT_BLUE, Inches(4.8), Inches(1.9), Inches(3.7), Inches(4.7),
         "CONTEXTUAL LOGIC ANALYSIS\n\n"
         "• Dispatches candidate hot-file code to LLM via OpenRouter API\n"
         "• Identifies complex authorization flaws and business logic bugs that regex misses\n"
         "• Evaluates multi-function data flow and insecure design patterns\n"
         "• Returns structured JSON finding objects (engine: openrouter_review)\n\n"
         "Output: Logic flaw findings added to scan pool"),

        ("Stage 3: Groq LLM Synthesis & Remediation", ACCENT_GREEN, Inches(8.8), Inches(1.9), Inches(3.7), Inches(4.7),
         "EXECUTIVE POSTURE & PATCHES\n\n"
         "• Ultra-low latency inference via Groq Llama-3 execution\n"
         "• Ingests all merged findings to synthesize an executive risk posture report\n"
         "• Generates tailored, copy-paste code patches for individual findings\n"
         "• Fail-Open Architecture: If API keys are missing or rate-limited, deterministic results deliver normally\n\n"
         "Output: Executive markdown summary + code patches")
    ]

    for title, color, left, top, width, height, text in ai_steps:
        card = add_card(s7, left, top, width, height, title, color)
        tb = s7.shapes.add_textbox(left + Inches(0.25), top + Inches(0.48), width - Inches(0.5), height - Inches(0.6))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = text
        p.font.name = FONT_BODY
        p.font.size = Pt(8.8)
        p.font.color.rgb = TEXT_SECONDARY

    add_speaker_notes(s7,
        "A key innovation in VERITAS is our hybrid AI architecture. Scanners alone lack business context; LLMs alone hallucinate. "
        "We unite them in a 3-stage pipeline: Stage 1 executes deterministic tools for exact syntax matches. "
        "Stage 2 sends high-risk hot files to OpenRouter for semantic review of business logic flaws. "
        "Stage 3 uses Groq's high-speed Llama-3 to generate an executive posture report and context-specific code patches. "
        "Importantly, the system is fail-open: scans succeed even without AI API keys."
    )

    # -----------------------------------------------------
    # SLIDE 8: CI/CD Push Webhooks & Ephemeral Sandboxing (Sequence Flow)
    # -----------------------------------------------------
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "Security Pillar 4: CI/CD Automation", "Render-Style GitHub Push Webhooks & Ephemeral Sandboxes",
               "Automated continuous security scanning without developer friction or credential exposure")

    flow_box = add_card(s8, Inches(0.8), Inches(1.9), Inches(11.733), Inches(1.1), "Continuous Push CI/CD Sequence Flow", ACCENT_PRIMARY)
    flow_tb = s8.shapes.add_textbox(Inches(1.0), Inches(2.35), Inches(11.3), Inches(0.5))
    flow_tf = flow_tb.text_frame
    flow_tf.margin_left = flow_tf.margin_top = flow_tf.margin_right = flow_tf.margin_bottom = 0
    p_flow = flow_tf.paragraphs[0]
    p_flow.text = "[ 1: Developer Git Push ]  -->  [ 2: GitHub Webhook Delivery ]  -->  [ 3: HMAC SHA-256 Check ]  -->  [ 4: Ephemeral Clone ]  -->  [ 5: Multi-Engine Scan ]  -->  [ 6: Workdir Purge ]"
    p_flow.font.name = FONT_HEADING
    p_flow.font.size = Pt(8.5)
    p_flow.font.bold = True
    p_flow.font.color.rgb = ACCENT_PRIMARY

    gh_pillars = [
        ("GitHub OAuth & Ownership Check", ACCENT_PRIMARY, [
            ("Strict Repo Ownership: ", "Users can attach only repositories verified as owned by their connected GitHub identity."),
            ("Server-Side Validation: ", "Prevents forged github_repo_id injection attacks by querying GitHub API directly upon attachment."),
            ("Encrypted Access Tokens: ", "Access tokens are encrypted at rest with Fernet and never sent back to the client browser.")
        ]),
        ("Automated Push Webhooks", ACCENT_BLUE, [
            ("Render/Vercel-Style CI/CD: ", "Per-project toggle (auto_scan_on_push) automatically provisions a GitHub repository webhook."),
            ("HMAC SHA-256 Verification: ", "Webhooks verify X-Hub-Signature-256 using an encrypted per-project secret to prevent spoofing."),
            ("Commit Tracking: ", "Scans triggered by push are tagged with 7-character short SHAs and commit messages.")
        ]),
        ("Ephemeral Sandboxing", ACCENT_GREEN, [
            ("Isolated Workspaces: ", "Repositories are cloned into short-lived sandboxes under VERITAS_SCAN_ROOT (/tmp/veritas-scans)."),
            ("Automatic Teardown: ", "Sandbox directories are deleted immediately upon completion or cancellation, preventing disk leaks."),
            ("Diff-Only Targeting: ", "scan_scope: changed limits Semgrep to git diff paths against default branch for fast PR scans.")
        ])
    ]

    for i, (title, color, bullets) in enumerate(gh_pillars):
        left = Inches(0.8 + i * 4.0)
        top = Inches(3.2)
        card = add_card(s8, left, top, Inches(3.8), Inches(3.5), title, color)
        
        tb = s8.shapes.add_textbox(left + Inches(0.25), top + Inches(0.48), Inches(3.3), Inches(2.85))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        
        for idx, (b_title, b_desc) in enumerate(bullets):
            p = tf.paragraphs[0] if idx == 0 else tf.add_paragraph()
            p.text = f"• {b_title}"
            p.font.name = FONT_BODY
            p.font.size = Pt(9.5)
            p.font.bold = True
            p.font.color.rgb = TEXT_PRIMARY
            p.space_after = Pt(2)
            
            p2 = tf.add_paragraph()
            p2.text = b_desc
            p2.font.name = FONT_BODY
            p2.font.size = Pt(8.8)
            p2.font.color.rgb = TEXT_SECONDARY
            p2.space_after = Pt(8)

    add_speaker_notes(s8,
        "In Phase 5, we introduced Render/Vercel-style auto-scan on push. "
        "A developer connects their GitHub account, selects their repository, and turns on auto-scan. "
        "VERITAS registers a repository webhook verified with HMAC SHA-256 signatures. "
        "Every push to the watched branch triggers an automated scan. We track the 7-character commit SHA, clone the repository into an ephemeral sandbox, "
        "execute the engines, and wipe the disk immediately afterward. "
        "Server-side repo ownership verification prevents foreign repository attachment attacks."
    )

    # -----------------------------------------------------
    # SLIDE 9: Operational Quality Controls (2x2 Matrix)
    # -----------------------------------------------------
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "Operational Controls", "Triage Workflow, Diff Scans, Suppressions & Quotas",
               "Giving developers granular control over scan execution, findings, and limits")

    ops_grid = [
        ("1. Finding Status Lifecycle & GitHub Blobs", ACCENT_PRIMARY,
         "• 4 Standard Statuses: open, triage, fixed, false_positive.\n"
         "• Interactive Drawer: Displays severity, engine source, code snippet, and remediations.\n"
         "• Direct GitHub Blob Links: One-click jump to exact blob line: github.com/{repo}/blob/{sha}/{path}#L{line}."),

        ("2. Cryptographic Suppression Fingerprints", ACCENT_AMBER,
         "• SHA-256 Fingerprint: hash(engine|rule_id|file_path|line_start|title).\n"
         "• Persistent Memory: Suppressed findings auto-transition to false_positive in future scans.\n"
         "• Eliminates Duplicate Fatigue: Developers never re-triage the same approved false positive twice."),

        ("3. Scan Diff & Compare Engine", ACCENT_GREEN,
         "• Side-by-Side Analysis: Compare Scan A vs. Scan B across any two branch commits.\n"
         "• Tri-State Categorization: Instantly categorizes findings into Newly Added, Resolved, and Unchanged.\n"
         "• Quality Gate Policy: Configurable fail_severity (critical, high, medium) auto-fails scans violating thresholds."),

        ("4. Compute Quotas & Cooperative Cancellation", ACCENT_CRIMSON,
         "• Compute Rate Limits: SCAN_RATE_LIMIT (10/hr) and SCAN_CONCURRENT_LIMIT (2) prevent server DoS.\n"
         "• Asynchronous Cancellation: Users can cancel running scans; workers check state between phases.\n"
         "• Multi-format Export: Markdown, JSON, CSV, HTML, and SARIF 2.1.0 with public link sharing.")
    ]

    for i, (title, color, text) in enumerate(ops_grid):
        col = i % 2
        row = i // 2
        left = Inches(0.8 + col * 6.0)
        top = Inches(1.9 + row * 2.55)
        card = add_card(s9, left, top, Inches(5.7), Inches(2.35), title, color)
        
        tb = s9.shapes.add_textbox(left + Inches(0.25), top + Inches(0.52), Inches(5.2), Inches(1.7))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = text
        p.font.name = FONT_BODY
        p.font.size = Pt(9.2)
        p.font.color.rgb = TEXT_SECONDARY

    add_speaker_notes(s9,
        "Vulnerability triage is where security succeeds or fails. VERITAS provides complete operational controls: "
        "First, a finding lifecycle with statuses and direct links to GitHub blob lines. "
        "Second, suppression fingerprinting using SHA-256 hashes to permanently silence approved false positives across re-scans. "
        "Third, scan comparison to show managers exactly what vulnerabilities were introduced or resolved between two commits. "
        "And fourth, compute quotas and cooperative cancellation to prevent denial of service."
    )

    # -----------------------------------------------------
    # SLIDE 10: Runtime HTTP Telemetry & AI Analyst (Data Flow)
    # -----------------------------------------------------
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "Runtime Defense", "Live HTTP Traffic Heuristics & AI Threat Intelligence",
               "Bridging static code analysis with real-time runtime intrusion detection")

    tel_cols = [
        ("Passive HTTP Classifier Middleware", ACCENT_CRIMSON, [
            ("Heuristic Classifier: ", "FastAPI middleware inspects incoming paths, query parameters, and headers on every request."),
            ("Detected Attack Vectors: ", "SQLi, XSS, Command Injection, SSRF, Path Traversal, SSTI, and auth anomaly spikes."),
            ("Zero Body/PII Storage: ", "Captures only metadata (method, route, classification, status, IP); never logs request bodies or passwords.")
        ]),
        ("Admin Security Dashboard", ACCENT_AMBER, [
            ("Real-Time Visualizations: ", "Live ApexCharts display request volume, severity tiers (Safe, Warning, Critical), and status distribution."),
            ("Attack Surface Filtering: ", "Filter telemetry by threat classification, HTTP status (401, 403, 429), and client IP."),
            ("Capped Retention: ", "Rolling retention window (~50,000 events / 7 days) ensures zero database performance degradation.")
        ]),
        ("AI Security Analyst Panel", ACCENT_PRIMARY, [
            ("On-Demand Intelligence: ", "Admins trigger AI analysis of recent telemetry via Groq (with OpenRouter fallback)."),
            ("Incident Explanation: ", "The AI analyzes attack patterns and explains observed anomalies in structured natural language."),
            ("Actionable Firewall Rules: ", "Outputs concrete Nginx or AWS WAF mitigation rules tailored to active attacks.")
        ])
    ]

    for i, (title, color, bullets) in enumerate(tel_cols):
        left = Inches(0.8 + i * 4.0)
        top = Inches(1.9)
        card = add_card(s10, left, top, Inches(3.8), Inches(4.7), title, color)
        
        tb = s10.shapes.add_textbox(left + Inches(0.25), top + Inches(0.55), Inches(3.3), Inches(3.9))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        
        for idx, (b_title, b_desc) in enumerate(bullets):
            p = tf.paragraphs[0] if idx == 0 else tf.add_paragraph()
            p.text = f"• {b_title}"
            p.font.name = FONT_BODY
            p.font.size = Pt(9.5)
            p.font.bold = True
            p.font.color.rgb = TEXT_PRIMARY
            p.space_after = Pt(2)
            
            p2 = tf.add_paragraph()
            p2.text = b_desc
            p2.font.name = FONT_BODY
            p2.font.size = Pt(8.8)
            p2.font.color.rgb = TEXT_SECONDARY
            p2.space_after = Pt(10)

    add_speaker_notes(s10,
        "Static code scanning protects repositories at rest, but what about the running application? "
        "VERITAS includes lightweight HTTP telemetry middleware that passively analyzes live API requests for "
        "SQL injection, XSS, SSRF, command injection, and path traversal heuristics. "
        "On the Admin Security page, live ApexCharts visualize attack volume, and an AI Security Analyst agent "
        "synthesizes recent incidents into actionable WAF rules and countermeasures."
    )

    # -----------------------------------------------------
    # SLIDE 11: Enterprise Compliance & Multi-Format Exports
    # -----------------------------------------------------
    s11 = prs.slides.add_slide(blank_layout)
    set_slide_background(s11)
    add_header(s11, "Compliance & Reporting", "Enterprise SARIF 2.1.0 & Multi-Format Reporting",
               "Delivering compliance-ready artifacts for developers, executives, and security auditors")

    rep_grid = [
        ("1. OASIS SARIF 2.1.0 Standard Export", ACCENT_PRIMARY,
         "• Industry Standard: Generates Static Analysis Results Interchange Format (SARIF 2.1.0).\n"
         "• Native GitHub Integration: Upload SARIF directly into GitHub Actions or GitLab Security Dashboards.\n"
         "• SIEM / IDE Ingestion: Directly importable into VS Code, SonarQube, and enterprise vulnerability management systems.\n"
         "• Full Traceability: Retains exact rule IDs, CWE mappings, physical code locations, and snippets."),

        ("2. Public Tokenized Report Links", ACCENT_GREEN,
         "• Shareable URL: /report/{token} allows external stakeholders to view findings without logging in.\n"
         "• Read-Only Finding Drawer: Auditors view code snippets, severity distribution, and remediations.\n"
         "• Cryptographic Isolation: Scoped strictly to that specific scan record; zero project data leakage.\n"
         "• High Utility: Ideal for client demonstrations, bug bounty triage, and third-party security audits."),

        ("3. Multi-Format Client Exports", ACCENT_BLUE,
         "• Markdown: Formatted GitHub-flavored markdown with summary badges for documentation.\n"
         "• JSON: Full structured schema containing engine metadata and raw tool outputs.\n"
         "• CSV: Spreadsheet-compatible tabular export for corporate audit compliance spreadsheets.\n"
         "• HTML: Standalone, portable self-contained interactive report file."),

        ("4. Executive AI Posture Summary", ACCENT_AMBER,
         "• Posture Scoring: Groq Llama-3 evaluates repository security posture for non-technical leadership.\n"
         "• Top Priority Vulnerabilities: Pinpoints the 3 highest-risk security vulnerabilities requiring immediate fixes.\n"
         "• Actionable Recommendations: Translates technical jargon into business risk impact and engineering next steps.")
    ]

    for i, (title, color, text) in enumerate(rep_grid):
        col = i % 2
        row = i // 2
        left = Inches(0.8 + col * 6.0)
        top = Inches(1.9 + row * 2.55)
        card = add_card(s11, left, top, Inches(5.7), Inches(2.35), title, color)
        
        tb = s11.shapes.add_textbox(left + Inches(0.25), top + Inches(0.52), Inches(5.2), Inches(1.7))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = text
        p.font.name = FONT_BODY
        p.font.size = Pt(9.2)
        p.font.color.rgb = TEXT_SECONDARY

    add_speaker_notes(s11,
        "Reporting is essential for enterprise compliance. "
        "VERITAS exports full SARIF 2.1.0—the OASIS industry standard format. This allows our scan results to be uploaded "
        "directly into GitHub Security or enterprise CI/CD systems. "
        "Additionally, we provide tokenized public report links so engineers can securely share a read-only report with clients "
        "or auditors without creating platform accounts, alongside Markdown, CSV, JSON, and HTML exports."
    )

    # -----------------------------------------------------
    # SLIDE 12: Platform Defensive Hardening (Defense-in-Depth Table)
    # -----------------------------------------------------
    s12 = prs.slides.add_slide(blank_layout)
    set_slide_background(s12)
    add_header(s12, "Defensive Engineering", "Platform Security Posture & Fail-Closed Safeguards",
               "Practicing what we preach: robust hardening of the VERITAS application itself")

    def_table = add_table(s12, Inches(0.8), Inches(1.9), Inches(11.733), Inches(4.7), 5, 3,
                          [Inches(2.5), Inches(4.8), Inches(4.433)])
    
    def_headers = ["Security Domain", "Implementation & Mechanism", "Defensive Value & Threat Mitigated"]
    for c_idx, h in enumerate(def_headers):
        format_table_header_cell(def_table.cell(0, c_idx), h)

    def_rows = [
        ("Session Security", "veritas_session with HttpOnly, SameSite=Lax, and Secure flags. SHA-256 hashed DB tokens.", "Prevents XSS session theft and eliminates exposure of valid sessions if DB is compromised."),
        ("Account Recovery", "Password resets immediately revoke all active session rows across all devices.", "Eliminates lingering sessions if an account was compromised prior to password reset."),
        ("Authorization Guardrails", "Fail-closed role checks. Blocks demoting last admin; admins cannot alter own role.", "Mitigates privilege escalation attacks and prevents accidental platform lockout."),
        ("Host Protection", "/admin/files restricts traversal; blocks /proc, /sys, /dev, /etc/shadow, and .env files.", "Prevents Local File Inclusion (LFI) and accidental disclosure of server credentials.")
    ]

    for r_idx, row in enumerate(def_rows, start=1):
        for c_idx, val in enumerate(row):
            is_bold = (c_idx == 0)
            col_color = ACCENT_PRIMARY if c_idx == 0 else TEXT_SECONDARY
            format_table_data_cell(def_table.cell(r_idx, c_idx), val, bold=is_bold, text_color=col_color, font_size=9)

    add_speaker_notes(s12,
        "As a cybersecurity project, VERITAS must be thoroughly hardened itself. "
        "We followed defense-in-depth principles: all cookies use HttpOnly and SameSite flags; all tokens in the database are hashed; "
        "and our authorization model is strictly fail-closed. "
        "We prevent privilege escalation by disallowing admins from changing their own roles, "
        "and ensure the system always has at least one active administrator. "
        "Even our host filesystem browser restricts access to system directories and secrets."
    )

    # -----------------------------------------------------
    # SLIDE 13: Live Demonstration Workflow (Step-by-Step Flow)
    # -----------------------------------------------------
    s13 = prs.slides.add_slide(blank_layout)
    set_slide_background(s13)
    add_header(s13, "Demonstration Flow", "End-to-End User & Security Operations Walkthrough",
               "Step-by-step verification of user onboarding, push scanning, and vulnerability triage")

    demo_steps = [
        ("Step 1: Onboarding & Approval", ACCENT_PRIMARY, Inches(0.8), Inches(1.9), Inches(2.85), Inches(4.7),
         "ACCOUNT LIFECYCLE\n\n"
         "1. User signs up via /auth/signup with Argon2.\n"
         "2. Verifies email token.\n"
         "3. Account enters pending_approval.\n"
         "4. Admin reviews audit log and approves account in /admin/directory.\n"
         "5. Multi-provider geolocation logs IP origin."),

        ("Step 2: GitHub Link & Push", ACCENT_BLUE, Inches(3.75), Inches(1.9), Inches(2.85), Inches(4.7),
         "CI/CD AUTOMATION\n\n"
         "1. User logs into /user/ and connects GitHub via OAuth.\n"
         "2. Selects owned repository; server verifies ownership.\n"
         "3. Enables auto_scan_on_push in project advanced settings.\n"
         "4. Webhook provisioned with HMAC SHA-256 secret.\n"
         "5. Developer pushes a git commit to the watched branch."),

        ("Step 3: Multi-Engine Scan", ACCENT_AMBER, Inches(6.7), Inches(1.9), Inches(2.85), Inches(4.7),
         "PIPELINE EXECUTION\n\n"
         "1. Webhook catches commit; verifies HMAC signature.\n"
         "2. Clones repo to ephemeral sandbox under /tmp/veritas-scans.\n"
         "3. Runs Semgrep, OSV, Gitleaks, Bandit.\n"
         "4. OpenRouter reviews hot files.\n"
         "5. Groq Llama-3 writes executive summary.\n"
         "6. Sandbox purged immediately."),

        ("Step 4: Triage & Remediate", ACCENT_GREEN, Inches(9.65), Inches(1.9), Inches(2.85), Inches(4.7),
         "FINDINGS & COMPLIANCE\n\n"
         "1. Opens finding slide-drawer.\n"
         "2. Inspects AI code patch and clicks direct GitHub blob link.\n"
         "3. Suppresses false positive with SHA-256 fingerprint.\n"
         "4. Compares scan against baseline.\n"
         "5. Exports report in SARIF 2.1.0.")
    ]

    for title, color, left, top, width, height, text in demo_steps:
        card = add_card(s13, left, top, width, height, title, color)
        tb = s13.shapes.add_textbox(left + Inches(0.2), top + Inches(0.48), width - Inches(0.4), height - Inches(0.6))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = text
        p.font.name = FONT_BODY
        p.font.size = Pt(8.8)
        p.font.color.rgb = TEXT_SECONDARY

    add_speaker_notes(s13,
        "Here is our live demonstration walkthrough: "
        "1) The user signs up and verifies their email, and lands in pending approval. The administrator logs in, inspects the audit trail, and approves the account. "
        "2) The user connects GitHub and enables auto-scan on push. "
        "3) A git push occurs; VERITAS receives the webhook, verifies the HMAC signature, and launches the scan pipeline. "
        "4) The scan completes; the user views the finding drawer, inspects AI remediation patches, jumps to the GitHub blob, and exports the SARIF report."
    )

    # -----------------------------------------------------
    # SLIDE 14: Technical Specifications & Metrics (Data Matrix)
    # -----------------------------------------------------
    s14 = prs.slides.add_slide(blank_layout)
    set_slide_background(s14)
    add_header(s14, "Implementation & Metrics", "Full-Stack Technology Suite & Engineering Metrics",
               "Engineered for performance, scalability, and clean modular maintainability")

    tech_table = add_table(s14, Inches(0.8), Inches(1.9), Inches(11.733), Inches(4.7), 6, 3,
                           [Inches(2.5), Inches(5.8), Inches(3.433)])
    
    tech_headers = ["Layer", "Technology / Stack Component", "Key Specification / Metric"]
    for c_idx, h in enumerate(tech_headers):
        format_table_header_cell(tech_table.cell(0, c_idx), h)

    tech_rows = [
        ("Backend Services", "FastAPI (Python 3.12 Asynchronous), SQLAlchemy 2.0 ORM", "Sub-millisecond route dispatch, pure async I/O"),
        ("Database Engine", "SQLite (Development) / PostgreSQL (Production)", "UTC ISO-8601 timestamps, additive schema migrations"),
        ("Cryptographic Suite", "Argon2-cffi, Fernet (AES-128-CBC + HMAC), SHA-256", "Zero plaintext secret or token storage in DB"),
        ("Frontend Architecture", "React 18, Vite, TypeScript, Custom Minimal CSS", "Zero CORS exposure, independent admin/user routing"),
        ("Security Engines", "12 Deterministic Tools + OpenRouter & Groq Llama-3", "Sub-minute diff scan execution, fail-open design")
    ]

    for r_idx, row in enumerate(tech_rows, start=1):
        for c_idx, val in enumerate(row):
            is_bold = (c_idx == 0)
            col_color = ACCENT_PRIMARY if c_idx == 0 else TEXT_SECONDARY
            format_table_data_cell(tech_table.cell(r_idx, c_idx), val, bold=is_bold, text_color=col_color, font_size=9)

    add_speaker_notes(s14,
        "Here is the technical stack powering VERITAS. "
        "The backend is built with asynchronous FastAPI and SQLAlchemy, using Argon2 and Fernet cryptography. "
        "The frontend is built with React 18, Vite, and TypeScript with responsive CSS and interactive ApexCharts. "
        "We integrate 12 scanning tools with OpenRouter and Groq LLMs. "
        "Everything was engineered with strict server-side validation and automated CI/CD push capabilities."
    )

    # -----------------------------------------------------
    # SLIDE 15: Conclusion & Q&A Defense Strategy
    # -----------------------------------------------------
    s15 = prs.slides.add_slide(blank_layout)
    set_slide_background(s15)
    add_header(s15, "Conclusion & Evaluation", "Summary of Contributions & Academic Defense",
               "Summarizing our contributions to automated application security")

    summary_cards = [
        ("Summary of Contributions", ACCENT_PRIMARY,
         "• Solved the developer alert-fatigue problem by merging 12 deterministic engines with dual-tier LLM triage.\n"
         "• Implemented zero-trust identity with Argon2, admin approval gating, and multi-provider geolocation audit logs.\n"
         "• Delivered Render/Vercel-style continuous security with HMAC-authenticated GitHub push webhooks.\n"
         "• Built a real-time HTTP attack classifier that monitors live web traffic for injection threats."),

        ("Future Enhancements", ACCENT_BLUE,
         "• Dynamic Application Security Testing (DAST): Automated HTTP fuzzing and crawler exploration.\n"
         "• IDE Extension: Real-time inline linting via a lightweight VS Code extension.\n"
         "• Automated PR Remediation: Auto-generating GitHub Pull Requests with LLM-crafted bug fixes.\n"
         "• Multi-tenant Team Workspaces: Role-based access control (RBAC) across development organizations.")
    ]

    for i, (title, color, text) in enumerate(summary_cards):
        left = Inches(0.8 + i * 6.0)
        top = Inches(1.9)
        card = add_card(s15, left, top, Inches(5.7), Inches(3.4), title, color)
        
        tb = s15.shapes.add_textbox(left + Inches(0.25), top + Inches(0.52), Inches(5.2), Inches(2.6))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = text
        p.font.name = FONT_BODY
        p.font.size = Pt(9.5)
        p.font.color.rgb = TEXT_SECONDARY

    # Bottom Q&A Box
    qa_card = add_card(s15, Inches(0.8), Inches(5.5), Inches(11.733), Inches(1.1), "Open for Questions & Evaluation", ACCENT_PRIMARY)
    qtf = qa_card.text_frame
    qtf.margin_top = Inches(0.18)
    qtf.margin_left = Inches(0.3)
    p_qa = qtf.paragraphs[0]
    p_qa.text = "Thank you for your time and guidance. We are ready to answer your questions regarding the architecture, security safeguards, engine pipeline, or live demonstration of VERITAS."
    p_qa.font.name = FONT_BODY
    p_qa.font.size = Pt(10)
    p_qa.font.color.rgb = TEXT_PRIMARY

    add_speaker_notes(s15,
        "In conclusion, VERITAS proves that robust application security does not have to slow developers down. "
        "By uniting multi-engine static analysis, dual-tier AI remediation, zero-trust governance, and live runtime threat telemetry, "
        "VERITAS provides an end-to-end security fabric for modern engineering organizations. "
        "Thank you very much. I am now open to your questions and feedback."
    )

    # Save presentation
    output_path = "VERITAS_Security_Platform_Presentation.pptx"
    prs.save(output_path)
    print(f"Successfully generated clean minimal Light Theme presentation: {output_path}")

if __name__ == "__main__":
    create_presentation()
