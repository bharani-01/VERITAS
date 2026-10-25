r"""
VERITAS: Automated DevSecOps Vulnerability Intelligence & Multi-Engine Repository Security Platform
Professional Executive Pitch Deck Presentation Generator for Information Security Project Review

Template source:
- D:/College/Sem-5/Computer Network/CN-Project/Report/NetGuard_Project_Presentation.pptx
- Same theme: Monochrome Pitch Deck Aesthetic (Strictly Black / Charcoal / Grayscale)
- Same format: Open canvas layout with generous whitespace (NO separate container boxes / rounded cards)
- 16:9 Widescreen (13.333 x 7.5 inches)
- Standard Segoe UI typography, hairline dividers, clean academic tables with black headers
"""

import os
import pptx
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# =============================================================================
# MONOCHROME PITCH DECK COLOR PALETTE (Strictly Black / Charcoal / Grayscale)
# =============================================================================
COLOR_WHITE        = RGBColor(255, 255, 255)
COLOR_BLACK        = RGBColor(0, 0, 0)          # Primary titles & numbers
COLOR_DARK         = RGBColor(25, 25, 25)       # Strong headings
COLOR_BODY         = RGBColor(50, 50, 50)       # Body text
COLOR_MUTED        = RGBColor(105, 105, 105)    # Captions, kickers, metadata
COLOR_HAIRLINE     = RGBColor(220, 220, 220)    # Subtle structural dividers
COLOR_ROW_ALT      = RGBColor(248, 248, 248)    # Light gray for table alternating rows
COLOR_TABLE_HEADER = RGBColor(0, 0, 0)          # Black table headers

# Professional Pitch Deck Typography
FONT_NAME = "Segoe UI"
FONT_MONO = "Consolas"

def append_run(p, text, font_name=FONT_NAME, size_pt=11, bold=False, italic=False, color_rgb=COLOR_BODY):
    r = p.add_run()
    r.text = text
    r.font.name = font_name
    r.font.size = Pt(size_pt)
    r.font.bold = bold
    r.font.italic = italic
    r.font.color.rgb = color_rgb
    return r

def add_speaker_notes(slide, notes_text):
    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = notes_text

def create_presentation():
    prs = pptx.Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6] # completely blank layout

    logo_path = r'd:\College\Sem-5\Computer Network\CN-Project\Report\media\college_logo.png'

    # Helper: Slide Header (Pitch deck format: Kicker, Title, Subtitle, Hairline divider)
    def add_slide_header(slide, title_text, kicker_text="VERITAS  |  INFORMATION SECURITY CAPSTONE", subtitle_text=None):
        header_h = 1.1 if subtitle_text else 0.85
        tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.733), Inches(header_h))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0

        # Kicker / Eyebrow
        p_kicker = tf.paragraphs[0]
        p_kicker.text = kicker_text.upper()
        p_kicker.font.name = FONT_NAME
        p_kicker.font.size = Pt(9.5)
        p_kicker.font.bold = True
        p_kicker.font.color.rgb = COLOR_MUTED
        p_kicker.space_after = Pt(2)

        # Main Title
        p_title = tf.add_paragraph()
        p_title.text = title_text
        p_title.font.name = FONT_NAME
        p_title.font.size = Pt(22)
        p_title.font.bold = True
        p_title.font.color.rgb = COLOR_BLACK

        # Subtitle / Takeaway (if provided)
        if subtitle_text:
            p_sub = tf.add_paragraph()
            p_sub.text = subtitle_text
            p_sub.font.name = FONT_NAME
            p_sub.font.size = Pt(11)
            p_sub.font.color.rgb = COLOR_MUTED
            p_sub.space_before = Pt(2)

        # Clean, subtle hairline horizontal divider
        line_top = 0.4 + header_h + 0.1
        line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(line_top), Inches(11.733), Inches(0.015))
        line.fill.solid()
        line.fill.fore_color.rgb = COLOR_HAIRLINE
        line.line.color.rgb = COLOR_HAIRLINE
        return line_top + 0.25  # Returns Y position for content start

    # Helper: Clean Minimalist Academic Table (Black headers, white text, alternating rows)
    def add_clean_table(slide, left, top, width, height, headers, data, col_widths=None):
        rows = len(data) + 1
        cols = len(headers)
        tbl_shape = slide.shapes.add_table(rows, cols, Inches(left), Inches(top), Inches(width), Inches(height))
        tbl = tbl_shape.table

        if col_widths:
            for idx, w in enumerate(col_widths):
                tbl.columns[idx].width = Inches(w)

        # Header Row
        for c_idx, h in enumerate(headers):
            cell = tbl.cell(0, c_idx)
            cell.text = h
            cell.fill.solid()
            cell.fill.fore_color.rgb = COLOR_TABLE_HEADER
            p = cell.text_frame.paragraphs[0]
            p.alignment = PP_ALIGN.CENTER
            p.font.name = FONT_NAME
            p.font.size = Pt(10)
            p.font.bold = True
            p.font.color.rgb = COLOR_WHITE

        # Data Rows
        for r_idx, row_vals in enumerate(data):
            for c_idx, val in enumerate(row_vals):
                cell = tbl.cell(r_idx + 1, c_idx)
                cell.text = str(val)
                cell.fill.solid()
                if r_idx % 2 == 0:
                    cell.fill.fore_color.rgb = COLOR_WHITE
                else:
                    cell.fill.fore_color.rgb = COLOR_ROW_ALT
                p = cell.text_frame.paragraphs[0]
                p.font.name = FONT_NAME
                p.font.size = Pt(9.5)
                p.font.color.rgb = COLOR_DARK
                if c_idx == 0 or len(str(val)) < 8:
                    p.alignment = PP_ALIGN.CENTER
                else:
                    p.alignment = PP_ALIGN.LEFT
        return tbl_shape

    # =========================================================================
    # SLIDE 1: TITLE SLIDE (Executive Pitch Deck Standard)
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)

    # University Logo
    if os.path.exists(logo_path):
        s1.shapes.add_picture(logo_path, Inches(0.8), Inches(0.8), height=Inches(1.15))

    # Eyebrow / Kicker
    tb_title = s1.shapes.add_textbox(Inches(0.8), Inches(2.2), Inches(11.733), Inches(2.4))
    tf_title = tb_title.text_frame
    tf_title.word_wrap = True
    tf_title.margin_left = tf_title.margin_right = tf_title.margin_top = tf_title.margin_bottom = 0

    p_k = tf_title.paragraphs[0]
    p_k.text = "INFORMATION SECURITY // 5TH SEMESTER (VERITAS-INFOSEC)"
    p_k.font.name = FONT_NAME
    p_k.font.size = Pt(10.5)
    p_k.font.bold = True
    p_k.font.color.rgb = COLOR_MUTED
    p_k.space_after = Pt(10)

    p_m = tf_title.add_paragraph()
    p_m.text = "VERITAS: Automated DevSecOps Vulnerability Intelligence\n& Multi-Engine Repository Security Platform"
    p_m.font.name = FONT_NAME
    p_m.font.size = Pt(28)
    p_m.font.bold = True
    p_m.font.color.rgb = COLOR_BLACK
    p_m.space_after = Pt(12)

    p_desc = tf_title.add_paragraph()
    p_desc.text = "A zero-trust repository security platform orchestrating 12 deterministic static analysis engines, dual-tier LLM triage and remediations, automated GitHub push CI/CD webhooks, and live HTTP intrusion telemetry."
    p_desc.font.name = FONT_NAME
    p_desc.font.size = Pt(13)
    p_desc.font.color.rgb = COLOR_BODY

    # Hairline divider
    div = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(4.9), Inches(11.733), Inches(0.015))
    div.fill.solid()
    div.fill.fore_color.rgb = COLOR_HAIRLINE
    div.line.color.rgb = COLOR_HAIRLINE

    # Metadata (Author, Institution, Target)
    tb_meta = s1.shapes.add_textbox(Inches(0.8), Inches(5.15), Inches(11.733), Inches(1.8))
    tf_meta = tb_meta.text_frame
    tf_meta.word_wrap = True
    tf_meta.margin_left = tf_meta.margin_right = tf_meta.margin_top = tf_meta.margin_bottom = 0

    p_t = tf_meta.paragraphs[0]
    p_t.text = "PROJECT CANDIDATE & REVIEW METADATA"
    p_t.font.name = FONT_NAME
    p_t.font.size = Pt(9.5)
    p_t.font.bold = True
    p_t.font.color.rgb = COLOR_MUTED
    p_t.space_after = Pt(4)

    p_names = tf_meta.add_paragraph()
    p_names.text = "Bharani KR (E0224035)      |      Department of Artificial Intelligence & Data Analytics (AIDA)"
    p_names.font.name = FONT_NAME
    p_names.font.size = Pt(13.5)
    p_names.font.bold = True
    p_names.font.color.rgb = COLOR_BLACK
    p_names.space_after = Pt(10)

    p_inst = tf_meta.add_paragraph()
    p_inst.text = "Sri Ramachandra Faculty of Engineering and Technology, SRIHER, Chennai   |   Academic Session: November 2026\nSystem Target: veritas.trackifyapp.co.in   |   Architecture: FastAPI Single-Origin + React 18 SPA + SQLAlchemy 2.0"
    p_inst.font.name = FONT_NAME
    p_inst.font.size = Pt(11)
    p_inst.font.color.rgb = COLOR_MUTED

    add_speaker_notes(s1,
        "Good morning/afternoon respected evaluators. Today I am presenting VERITAS, an automated DevSecOps vulnerability intelligence platform.\n"
        "Modern application development moves rapidly, but security testing is frequently deferred until post-deployment. "
        "VERITAS implements true Shift-Left security: inspecting repositories at the code and commit level, identifying hardcoded credentials, "
        "scanning third-party dependency vulnerabilities, executing multi-language static analysis, and synthesizing actionable remediations."
    )

    # =========================================================================
    # SLIDE 2: PROBLEM STATEMENT & INDUSTRY MOTIVATION
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s2, "Problem Statement & Industry Motivation", 
                             subtitle_text="Critical security failures in modern repository workflows, open-source supply chains, and legacy scanning tools")

    col_w = 3.65
    gap = 0.38

    cols_data = [
        ("01 / Hardcoded Secret Leaks in Git", [
            ("Accidental Commits: ", "Developers frequently push API tokens, database passwords, and cloud private keys directly into git repositories."),
            ("Persistent History: ", "Deleting a secret in a follow-up commit does not purge it from git history; attackers easily extract raw objects from commit graphs."),
            ("Infrastructure Risk: ", "Exposed credentials lead to immediate cloud resource compromise, data breaches, and unauthorized API exploitation.")
        ]),
        ("02 / Supply Chain Risks (SCA)", [
            ("Dependency Ingestion: ", "Over 85% to 90% of modern software consists of third-party open-source libraries and package ecosystems."),
            ("Transitive Vulnerabilities: ", "Deep dependency trees mask critical known CVEs (e.g. Log4Shell, event-stream, prototype pollution) without developer awareness."),
            ("Unmonitored Upgrades: ", "Automated package upgrades frequently introduce malicious or compromised upstream packages into production builds.")
        ]),
        ("03 / Alert Fatigue & Runtime Blindness", [
            ("High False Positives: ", "Legacy static analysis tools dump hundreds of unranked warnings lacking business context, causing developers to ignore security reports."),
            ("Missing Remediations: ", "Scanners state that a flaw exists, but fail to provide contextual, copy-paste code patches tailored to the codebase."),
            ("Runtime Blindness: ", "Static tools inspect code strictly at rest, leaving running servers completely blind to live HTTP injection reconnaissance.")
        ])
    ]

    for idx, (col_title, bullets) in enumerate(cols_data):
        x = 0.8 + idx * (col_w + gap)
        tb = s2.shapes.add_textbox(Inches(x), Inches(c_top), Inches(col_w), Inches(5.0))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0

        p = tf.paragraphs[0]
        p.text = col_title
        p.font.name = FONT_NAME
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = COLOR_BLACK
        p.space_after = Pt(12)

        for b_title, b_desc in bullets:
            p = tf.add_paragraph()
            p.space_after = Pt(10)
            append_run(p, b_title, size_pt=11, bold=True, color_rgb=COLOR_BLACK)
            append_run(p, b_desc, size_pt=10.5, bold=False, color_rgb=COLOR_BODY)

    add_speaker_notes(s2,
        "Here is the core problem statement: First, credentials leak into git history, where attackers easily harvest them. "
        "Second, 90% of modern applications rely on open-source packages containing nested, unpatched CVEs. "
        "Third, existing scanners produce severe alert fatigue by outputting hundreds of unranked warnings without actionable code fixes. "
        "Finally, fragmented tooling leaves security teams without centralized audit trails, and static tools remain blind to active HTTP attacks. "
        "VERITAS was engineered specifically to solve these operational failures."
    )

    # =========================================================================
    # SLIDE 3: PROPOSED SOLUTION - THE VERITAS PLATFORM
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s3, "Proposed Solution: The VERITAS DevSecOps Platform",
                             subtitle_text="A unified security fabric integrating deterministic engines, dual-tier LLM remediation, and push CI/CD automation")

    col_w = 5.65
    gap_x = 0.43
    h_row = 2.4

    features = [
        ("01 / Multi-Engine Static Analysis Suite",
         "Consolidates 12 deterministic security tools across Secrets (Gitleaks, TruffleHog, detect-secrets), SCA (OSV-Scanner, pip-audit, Trivy), SAST (Semgrep across 9 languages, Bandit, njsscan), and IaC (Checkov, Hadolint, ShellCheck) into one automated execution pipeline.",
         "Engines: 12 Scanners   |   Coverage: Secrets, SCA, SAST, IaC   |   Output: Normalized Schema"),
        
        ("02 / Dual-Tier Hybrid AI Reasoning Pipeline",
         "Combines deterministic rule precision with OpenRouter hot-file contextual code review and ultra-low latency Groq Llama-3 synthesis. Generates executive risk posture summaries and copy-paste code patches with fail-open resilience.",
         "Stage 1: Deterministic AST   |   Stage 2: OpenRouter Review   |   Stage 3: Groq Llama-3 Fixes"),
        
        ("03 / Zero-Trust Identity & Admin Governance",
         "Enforces Argon2 password hashing, HttpOnly session cookies, SHA-256 token hashing, a 5-stage account lifecycle with mandatory administrator approval gating, and multi-provider IP geolocation consensus in an immutable audit trail.",
         "Password: Argon2-cffi   |   Gate: Mandatory Admin Approval   |   Audit: Multi-Provider Geolocation"),
        
        ("04 / Continuous Push CI/CD & Runtime Telemetry",
         "Render-style automated scanning on git push via HMAC SHA-256 verified GitHub webhooks. Clones repositories into short-lived sandboxes (/tmp/veritas-scans), while passive HTTP middleware classifies live traffic for SQLi, XSS, and SSRF threats.",
         "CI/CD: GitHub Push Webhooks   |   Sandbox: Ephemeral Workdirs   |   Telemetry: Live HTTP Classifier")
    ]

    coords_4 = [(0.8, c_top), (0.8 + col_w + gap_x, c_top), (0.8, c_top + h_row + 0.3), (0.8 + col_w + gap_x, c_top + h_row + 0.3)]

    for idx, (f_title, f_desc, f_meta) in enumerate(features):
        x, y = coords_4[idx]
        tb = s3.shapes.add_textbox(Inches(x), Inches(y), Inches(col_w), Inches(h_row))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0

        p = tf.paragraphs[0]
        p.text = f_title
        p.font.name = FONT_NAME
        p.font.size = Pt(14.5)
        p.font.bold = True
        p.font.color.rgb = COLOR_BLACK
        p.space_after = Pt(6)

        p = tf.add_paragraph()
        p.text = f_desc
        p.font.name = FONT_NAME
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_BODY
        p.space_after = Pt(8)

        p = tf.add_paragraph()
        p.text = f_meta
        p.font.name = FONT_NAME
        p.font.size = Pt(9.5)
        p.font.bold = True
        p.font.color.rgb = COLOR_MUTED

    add_speaker_notes(s3,
        "Our core objective with VERITAS was to build an enterprise-ready platform. "
        "The four pillars are: 1) Orchestrating 12 deterministic engines; 2) Combining rule precision with dual-tier LLM triage; "
        "3) Enforcing zero-trust identity with admin approval gates; and 4) Delivering continuous CI/CD push automation with runtime threat telemetry."
    )

    # =========================================================================
    # SLIDE 4: SYSTEM ARCHITECTURE PIPELINE
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s4, "System Architecture: End-to-End Request Pipeline",
                             subtitle_text="Single-origin FastAPI and React SPA request flow, isolated route boundaries, and sandboxed execution")

    # Left Column: 3 Architectural Tiers
    col_w = 5.65
    ltb = s4.shapes.add_textbox(Inches(0.8), Inches(c_top), Inches(col_w), Inches(5.0))
    ltf = ltb.text_frame
    ltf.word_wrap = True
    ltf.margin_left = ltf.margin_right = ltf.margin_top = ltf.margin_bottom = 0

    p = ltf.paragraphs[0]
    p.text = "Architectural Tier Decomposition"
    p.font.name = FONT_NAME
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = COLOR_BLACK
    p.space_after = Pt(12)

    arch_tiers = [
        ("Tier 1 / Presentation Layer (React 18 + Vite)", "Independent routing shells for /admin/ (Directory, Audit, Security Dashboard, Filesystem) and /user/ (Workspace, Projects, Scans). Strict separation of UI routes from JSON APIs eliminates boundary collision."),
        ("Tier 2 / API Gateway & Security Middleware (FastAPI)", "FastAPI serves both JSON APIs and compiled React SPA assets on a single origin, completely eliminating CORS attack surfaces. Enforces HttpOnly session cookie guards, in-memory rate limits (429), and passive HTTP telemetry."),
        ("Tier 3 / Asynchronous Engine Pipeline (SQLAlchemy 2.0)", "Background runner clones target repositories into ephemeral sandboxes (/tmp/veritas-scans), executes multi-engine scans, invokes OpenRouter/Groq AI pipelines, and persists findings via SQLAlchemy on SQLite/PostgreSQL.")
    ]
    for t_title, t_desc in arch_tiers:
        p = ltf.add_paragraph()
        p.space_after = Pt(10)
        append_run(p, t_title + ": ", size_pt=11.5, bold=True, color_rgb=COLOR_BLACK)
        append_run(p, t_desc, size_pt=10.5, bold=False, color_rgb=COLOR_BODY)

    # Right Column: Processing Workflow Steps
    rtb = s4.shapes.add_textbox(Inches(7.0), Inches(c_top), Inches(5.533), Inches(5.0))
    rtf = rtb.text_frame
    rtf.word_wrap = True
    rtf.margin_left = rtf.margin_right = rtf.margin_top = rtf.margin_bottom = 0

    p = rtf.paragraphs[0]
    p.text = "Pipeline Execution Workflow"
    p.font.name = FONT_NAME
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = COLOR_BLACK
    p.space_after = Pt(12)

    pipe_steps = [
        ("Step 01 / Inbound Trigger Validation", "Scans are triggered manually or via GitHub push webhooks. Webhooks verify X-Hub-Signature-256 HMAC signatures using the project secret before dispatch."),
        ("Step 02 / Ephemeral Sandbox Workspace", "Repository is cloned into a short-lived directory under VERITAS_SCAN_ROOT. Branch references and changed-file diff lists are extracted for targeted analysis."),
        ("Step 03 / Multi-Engine Execution & Normalization", "12 CLI scanners execute in parallel/sequence. Raw outputs from Gitleaks, Semgrep, OSV, and Bandit are parsed into standardized finding schemas with SHA-256 fingerprints."),
        ("Step 04 / Dual AI Reasoning & SARIF Export", "OpenRouter evaluates hot-file business logic; Groq Llama-3 writes executive risk posture reports and code patches. Workdir is wiped and SARIF 2.1.0 report is persisted.")
    ]
    for st_title, st_desc in pipe_steps:
        p = rtf.add_paragraph()
        p.space_after = Pt(10)
        append_run(p, st_title + ": ", size_pt=11.5, bold=True, color_rgb=COLOR_BLACK)
        append_run(p, st_desc, size_pt=10.5, bold=False, color_rgb=COLOR_BODY)

    add_speaker_notes(s4,
        "Let's look at the software architecture. VERITAS employs a unified single-origin model: FastAPI serves both the backend APIs and the compiled React frontend. "
        "Hosting the SPA on the same origin completely eliminates CORS exposure and allows secure HttpOnly session cookies to work natively without cross-domain leakage. "
        "Notice the strict boundary: Admin routes and User routes have completely separate navigation trees. In the backend, our background runner executes scans inside temporary sandboxes and purges them immediately after completion."
    )

    # =========================================================================
    # SLIDE 5: ZERO-TRUST IDENTITY & ACCESS MANAGEMENT (IAM)
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s5, "Security Pillar 1: IAM & Zero-Trust Governance",
                             subtitle_text="Cryptographically hardened authentication, mandatory administrator approval gating, and immutable event tracking")

    # Top KPI Metrics Row
    kpis = [
        ("5 STATES", "Account Lifecycle", "pending_verify -> pending_approve -> active"),
        ("0 PLAINTEXT", "Database Tokens", "Argon2 passwords, SHA-256 hashed session tokens"),
        ("3 PROVIDERS", "Geolocation Consensus", "ip-api, ipwho.is, ipapi.co IP consensus"),
        ("FAIL-CLOSED", "Authorization Policy", "Last admin cannot be demoted; no self-role edits")
    ]
    col_w_kpi = 2.7
    gap_kpi = 0.31

    for idx, (m_num, m_lbl, m_sub) in enumerate(kpis):
        x = 0.8 + idx * (col_w_kpi + gap_kpi)
        tb = s5.shapes.add_textbox(Inches(x), Inches(c_top), Inches(col_w_kpi), Inches(1.2))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0

        p = tf.paragraphs[0]
        p.text = m_num
        p.font.name = FONT_NAME
        p.font.size = Pt(22)
        p.font.bold = True
        p.font.color.rgb = COLOR_BLACK

        p = tf.add_paragraph()
        p.text = m_lbl
        p.font.name = FONT_NAME
        p.font.size = Pt(11.5)
        p.font.bold = True
        p.font.color.rgb = COLOR_DARK

        p = tf.add_paragraph()
        p.text = m_sub
        p.font.name = FONT_NAME
        p.font.size = Pt(9.5)
        p.font.color.rgb = COLOR_MUTED

    # Academic Table
    iam_headers = ["SECURITY DOMAIN", "CRYPTOGRAPHIC MECHANISM", "SYSTEM IMPLEMENTATION", "DEFENSIVE GUARANTEE"]
    iam_data = [
        ["Password Security", "Argon2id (argon2-cffi)", "Memory-hard parameters with unique cryptographic salt per user", "Resistant to GPU/ASIC offline dictionary brute-force attacks."],
        ["Session Integrity", "SHA-256 Hash + HttpOnly", "veritas_session cookie; server stores only SHA-256 hash of tokens", "Mitigates XSS cookie theft; DB compromise does not expose active sessions."],
        ["Account Lifecycle", "5-State Gated Machine", "Mandatory admin approval gate in /admin/directory before first login", "Prevents unapproved user access even after email token verification."],
        ["Audit Trail", "Append-Only Event Store", "audit_events records all logins, failures, approvals, and IP geolocations", "Provides tamper-resistant forensic logging with zero PII body retention."]
    ]
    add_clean_table(s5, 0.8, c_top + 1.45, 11.733, 3.4, iam_headers, iam_data, col_widths=[2.0, 2.7, 3.5, 3.533])

    add_speaker_notes(s5,
        "Identity is our first line of defense. VERITAS adheres to zero-trust principles. Passwords use Argon2, resistant to GPU and ASIC brute-forcing. "
        "All database tokens are stored exclusively as SHA-256 hashes. Furthermore, we designed a 5-stage account state machine: verifying email does not allow immediate access; "
        "an administrator must explicitly approve the account. Every authentication attempt, admin approval, and project modification is recorded in an immutable audit table enriched with multi-provider IP geolocation consensus."
    )

    # =========================================================================
    # SLIDE 6: 12-ENGINE STATIC ANALYSIS SUITE MATRIX
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s6, "Security Pillar 2: 12-Engine Static Analysis Matrix",
                             subtitle_text="Deterministic depth across Secrets, Software Composition (SCA), SAST, and Infrastructure as Code")

    eng_headers = ["CATEGORY", "INTEGRATED TOOLING", "TECHNICAL METHODOLOGY & SCOPE", "OUTPUT SCHEMA"]
    eng_data = [
        ["Secrets Detection", "Gitleaks, TruffleHog, detect-secrets", "Analyzes git commit tree history, entropy-based token detection, and regex pattern matching for API credentials across branches.", "Normalized Finding"],
        ["SCA Dependencies", "Google OSV-Scanner, pip-audit, Trivy", "Matches package manifests and lockfiles against Google OSV CVE database, PyPI security advisories, and container packages.", "Normalized Finding"],
        ["Polyglot SAST", "Semgrep (Basic/Strict), Bandit, njsscan", "Semantic AST rules across 9 programming languages (Python, JS/TS, Go, Java, Rust), Python OWASP flaw detection, Node.js analysis.", "Normalized Finding"],
        ["IaC & Linters", "Checkov, Hadolint, ShellCheck", "Policy-as-code for Terraform and Kubernetes, Dockerfile container hygiene enforcement, bash injection flaw detection.", "Normalized Finding"]
    ]
    add_clean_table(s6, 0.8, c_top, 11.733, 3.3, eng_headers, eng_data, col_widths=[2.2, 3.0, 4.8, 1.733])

    # Bottom Strategy Note
    stb = s6.shapes.add_textbox(Inches(0.8), Inches(c_top + 3.6), Inches(11.733), Inches(1.5))
    stf = stb.text_frame
    stf.word_wrap = True
    stf.margin_left = stf.margin_right = stf.margin_top = stf.margin_bottom = 0

    p = stf.paragraphs[0]
    p.text = "Key Engine Strategy & Finding Normalization:"
    p.font.name = FONT_NAME
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = COLOR_BLACK
    p.space_after = Pt(4)

    p = stf.add_paragraph()
    p.text = "All 12 scanners operate in deep coverage mode by default (git-history secrets, recursive SCA, and expanded language packs). Raw outputs from disjointed tool formats (SARIF, JSON, line-reports) are mapped into a unified schema: severity (critical, high, medium, low), CWE identifier, file path, line numbers, code snippet, and deterministic SHA-256 fingerprint."
    p.font.name = FONT_NAME
    p.font.size = Pt(10.5)
    p.font.color.rgb = COLOR_BODY

    add_speaker_notes(s6,
        "Here is our 12-engine scanning suite. Rather than relying on a single engine, VERITAS orchestrates 12 best-in-class security tools across Secrets, Dependencies, Source Code, and Infrastructure-as-Code. "
        "All raw outputs are parsed by our normalization engine into a single unified finding schema containing severity, CWE identifiers, file path, start line, code snippet, and a cryptographic fingerprint."
    )

    # =========================================================================
    # SLIDE 7: HYBRID AI PIPELINE: OPENROUTER & GROQ
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s7, "Security Pillar 3: Deterministic Rules + Dual-Tier LLM Intelligence",
                             subtitle_text="Combining exact syntax pattern matching with contextual semantic reasoning and actionable code patches")

    col_w = 3.65
    gap = 0.38

    ai_steps = [
        ("Stage 01 / Deterministic AST Baseline", [
            ("Precision Rule Matching: ", "Executes rule-based scanners (Semgrep, OSV, Gitleaks) to detect exact pattern matches with zero risk of AI hallucination."),
            ("Exact Physical Locations: ", "Extracts precise line numbers, rule IDs, and CWE mappings from source files and manifests."),
            ("Hot-File Extraction: ", "Identifies candidate high-risk files containing multiple security findings for contextual AI inspection.")
        ]),
        ("Stage 02 / OpenRouter Semantic Review", [
            ("Contextual Logic Analysis: ", "Dispatches candidate hot-file code to advanced reasoning models via OpenRouter (ai_code_review.py)."),
            ("Business Logic Bugs: ", "Identifies complex multi-function authorization flaws and business logic bypasses that regex/AST checks miss."),
            ("Structured JSON Findings: ", "Emits normalized findings attributed to engine: openrouter_review with risk scores and categories.")
        ]),
        ("Stage 03 / Groq LLM Synthesis & Fixes", [
            ("Ultra-Low Latency Inference: ", "Executes high-speed Llama-3 inference via Groq (ai_report.py) to synthesize all merged findings."),
            ("Executive Posture Report: ", "Generates an executive risk posture report translating technical flaws into business impact analysis."),
            ("Actionable Code Patches: ", "Produces tailored, copy-paste remediation code patches for each verified finding. Scans fail-open if API keys are absent.")
        ])
    ]

    for idx, (col_title, bullets) in enumerate(ai_steps):
        x = 0.8 + idx * (col_w + gap)
        tb = s7.shapes.add_textbox(Inches(x), Inches(c_top), Inches(col_w), Inches(5.0))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0

        p = tf.paragraphs[0]
        p.text = col_title
        p.font.name = FONT_NAME
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = COLOR_BLACK
        p.space_after = Pt(12)

        for b_title, b_desc in bullets:
            p = tf.add_paragraph()
            p.space_after = Pt(10)
            append_run(p, b_title, size_pt=11, bold=True, color_rgb=COLOR_BLACK)
            append_run(p, b_desc, size_pt=10.5, bold=False, color_rgb=COLOR_BODY)

    add_speaker_notes(s7,
        "A major innovation in VERITAS is our hybrid AI architecture. Scanners alone lack business context; LLMs alone hallucinate. "
        "We combine them: Stage 1 runs deterministic engines for exact syntax matches. Stage 2 passes high-risk hot files to OpenRouter for deep semantic review of business logic flaws. "
        "Stage 3 uses Groq's high-speed Llama-3 to generate an executive risk posture summary and context-specific code patches. "
        "If API keys are not provided, the system fails open—the deterministic scan completes without hindrance."
    )

    # =========================================================================
    # SLIDE 8: CONTINUOUS PUSH CI/CD & EPHEMERAL SANDBOXING
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s8, "Security Pillar 4: Render-Style GitHub Push CI/CD & Sandboxing",
                             subtitle_text="Automated continuous repository scanning without developer friction, token leakage, or lingering files")

    # Left: Sequence Steps
    col_w = 5.65
    ltb = s8.shapes.add_textbox(Inches(0.8), Inches(c_top), Inches(col_w), Inches(5.0))
    ltf = ltb.text_frame
    ltf.word_wrap = True
    ltf.margin_left = ltf.margin_right = ltf.margin_top = ltf.margin_bottom = 0

    p = ltf.paragraphs[0]
    p.text = "Continuous Push CI/CD Sequence"
    p.font.name = FONT_NAME
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = COLOR_BLACK
    p.space_after = Pt(12)

    push_steps = [
        ("Step 01 / Git Push Event", "Developer pushes commits to the watched branch on GitHub. No CLI tool execution or manual intervention required."),
        ("Step 02 / Webhook HMAC SHA-256 Validation", "GitHub delivers push payload to /webhooks/github. VERITAS verifies X-Hub-Signature-256 using the per-project secret before processing."),
        ("Step 03 / Ephemeral Sandbox Workspace", "Repository is cloned into an isolated temporary workdir under /tmp/veritas-scans. Scans track the 7-character short commit SHA and commit message."),
        ("Step 04 / Multi-Engine Scan & Instant Teardown", "Engines and AI pipelines evaluate the checkout. Immediately upon completion or cancellation, the sandbox workdir is purged from disk.")
    ]
    for st_title, st_desc in push_steps:
        p = ltf.add_paragraph()
        p.space_after = Pt(10)
        append_run(p, st_title + ": ", size_pt=11.5, bold=True, color_rgb=COLOR_BLACK)
        append_run(p, st_desc, size_pt=10.5, bold=False, color_rgb=COLOR_BODY)

    # Right: Operational Safeguards
    rtb = s8.shapes.add_textbox(Inches(7.0), Inches(c_top), Inches(5.533), Inches(5.0))
    rtf = rtb.text_frame
    rtf.word_wrap = True
    rtf.margin_left = rtf.margin_right = rtf.margin_top = rtf.margin_bottom = 0

    p = rtf.paragraphs[0]
    p.text = "Operational CI/CD Safeguards"
    p.font.name = FONT_NAME
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = COLOR_BLACK
    p.space_after = Pt(12)

    safeguards = [
        ("Server-Side Repo Ownership Check", "User links GitHub via OAuth. VERITAS queries GitHub API on every attach to strictly verify that the connected user owns the repo, blocking forged ID injection."),
        ("Encrypted OAuth Tokens at Rest", "GitHub access tokens are encrypted using Fernet (AES-128-CBC + HMAC-SHA256). Tokens are never returned to client browsers."),
        ("Sub-Minute PR Diff Scans", "Using scan_scope: changed, Semgrep is restricted to files changed in git diff against default branch, delivering rapid feedback for pull requests."),
        ("Compute Quota Enforcement", "SCAN_RATE_LIMIT (10/hr) and SCAN_CONCURRENT_LIMIT (2) prevent host exhaustion during rapid multi-commit pushes.")
    ]
    for sg_title, sg_desc in safeguards:
        p = rtf.add_paragraph()
        p.space_after = Pt(10)
        append_run(p, sg_title + ": ", size_pt=11.5, bold=True, color_rgb=COLOR_BLACK)
        append_run(p, sg_desc, size_pt=10.5, bold=False, color_rgb=COLOR_BODY)

    add_speaker_notes(s8,
        "To make security seamless for developers, Phase 5 introduced Render-style auto-scan on push. A developer links their GitHub account, selects their repository, and turns on auto-scan. "
        "VERITAS registers a repository webhook verified with HMAC SHA-256 signatures. Every push to the watched branch triggers an automated scan. We track the 7-character commit SHA, clone the repository into an isolated ephemeral sandbox, "
        "execute the engines, and wipe the disk immediately afterward. Server-side repo ownership verification prevents foreign repository attachment attacks."
    )

    # =========================================================================
    # SLIDE 9: OPERATIONAL CONTROLS & TRIAGE
    # =========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s9, "Operational Controls: Triage, Diffing & Suppressions",
                             subtitle_text="Granular developer control to eliminate duplicate alert fatigue, compare releases, and enforce policy gates")

    col_w = 2.7
    gap_x = 0.31

    modules = [
        ("01 / Finding Lifecycle",
         "Interactive triage side-drawer:",
         [("4 Statuses: ", "open, triage, fixed, false_positive."),
          ("GitHub Blob Links: ", "Direct link: github.com/{repo}/blob/{sha}/{path}#L{line}."),
          ("Remediation View: ", "Inspects Groq AI code fix recommendations.")]),
        
        ("02 / SHA-256 Suppressions",
         "Cryptographic noise elimination:",
         [("Fingerprint Formula: ", "hash(engine|rule_id|file_path|line_start|title)."),
          ("Cross-Scan Memory: ", "Suppressed items auto-transition to false_positive in future scans."),
          ("Zero Duplicate Triage: ", "Developers never re-triage the same approved false positive.")]),
        
        ("03 / Scan Compare & Diff",
         "Side-by-side release auditing:",
         [("Tri-State Diffing: ", "Categorizes findings into Newly Added, Resolved, and Unchanged."),
          ("Branch Auditing: ", "Compare any two scan snapshots across branches or tags."),
          ("Severity Gates: ", "fail_severity auto-fails scans violating quality thresholds.")]),
        
        ("04 / Quotas & Cancel",
         "Resource stability enforcement:",
         [("Compute Rate Limits: ", "SCAN_RATE_LIMIT (10/hr) and SCAN_CONCURRENT_LIMIT (2)."),
          ("Cooperative Cancel: ", "Workers evaluate cancellation flags between engine stages."),
          ("Ops Alerts: ", "Automatic email alert to admins on engine binary failures.")])
    ]

    for idx, (title, sub, bullets) in enumerate(modules):
        x = 0.8 + idx * (col_w + gap_x)
        tb = s9.shapes.add_textbox(Inches(x), Inches(c_top), Inches(col_w), Inches(5.0))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0

        p = tf.paragraphs[0]
        p.text = title
        p.font.name = FONT_NAME
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = COLOR_BLACK
        p.space_after = Pt(4)

        p = tf.add_paragraph()
        p.text = sub
        p.font.name = FONT_NAME
        p.font.size = Pt(10)
        p.font.color.rgb = COLOR_MUTED
        p.space_after = Pt(10)

        for b_title, b_desc in bullets:
            p = tf.add_paragraph()
            p.space_after = Pt(8)
            append_run(p, b_title, size_pt=10.5, bold=True, color_rgb=COLOR_BLACK)
            append_run(p, b_desc, size_pt=10, bold=False, color_rgb=COLOR_BODY)

    add_speaker_notes(s9,
        "Scanning is only half the battle; managing vulnerabilities at scale is where security succeeds or fails. VERITAS provides complete operational governance: "
        "a finding lifecycle with direct links to GitHub blob lines; suppression fingerprinting using SHA-256 hashes to permanently silence approved false positives across re-scans; "
        "scan comparison to show managers exactly what vulnerabilities were introduced or resolved between two commits; and compute quotas and cooperative cancellation to prevent denial of service."
    )

    # =========================================================================
    # SLIDE 10: RUNTIME HTTP TELEMETRY & AI SECURITY ANALYST
    # =========================================================================
    s10 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s10, "Runtime Defense: Live HTTP Traffic Telemetry & AI Analyst",
                             subtitle_text="Passive middleware intrusion classification and on-demand AI mitigation rule synthesis")

    # Left: Heuristics Table
    tel_headers = ["ATTACK VECTOR", "HEURISTIC SIGNATURES DETECTED", "CLASSIFICATION LEVEL"]
    tel_data = [
        ["SQL Injection (SQLi)", "UNION SELECT, sleep(), boolean tautologies (' OR 1=1), stacked queries", "Critical Threat"],
        ["Cross-Site Scripting (XSS)", "<script>, javascript: URI, onerror= handlers, unencoded DOM payloads", "Critical Threat"],
        ["Path Traversal / LFI", "../.., /etc/passwd, \\..\\ windows paths, encoded null bytes (%00)", "Critical Threat"],
        ["Command Injection / SSRF", "; cat /etc/shadow, curl metadata endpoints (169.254.169.254), backticks", "Critical Threat"],
        ["Auth Anomaly Spikes", "Repeated 401/403 brute force bursts, scanner User-Agents (sqlmap, nikto)", "Warning Alert"]
    ]
    add_clean_table(s10, 0.8, c_top, 6.0, 3.4, tel_headers, tel_data, col_widths=[2.1, 2.7, 1.2])

    # Left Bottom Note
    ntb = s10.shapes.add_textbox(Inches(0.8), Inches(c_top + 3.6), Inches(6.0), Inches(1.5))
    ntf = ntb.text_frame
    ntf.word_wrap = True
    ntf.margin_left = ntf.margin_right = ntf.margin_top = ntf.margin_bottom = 0

    p = ntf.paragraphs[0]
    p.text = "Metadata-Only Passive Inspection:"
    p.font.name = FONT_NAME
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = COLOR_BLACK
    p.space_after = Pt(4)

    p = ntf.add_paragraph()
    p.text = "Operates strictly on HTTP paths, query parameters, and headers. Never stores or logs request bodies, user passwords, or tokens. Rolling retention window (~50k events / 7 days) ensures zero database bloat."
    p.font.name = FONT_NAME
    p.font.size = Pt(10)
    p.font.color.rgb = COLOR_BODY

    # Right: AI Security Analyst Panel
    atb = s10.shapes.add_textbox(Inches(7.1), Inches(c_top), Inches(5.433), Inches(5.0))
    atf = atb.text_frame
    atf.word_wrap = True
    atf.margin_left = atf.margin_right = atf.margin_top = atf.margin_bottom = 0

    p = atf.paragraphs[0]
    p.text = "AI Security Analyst Panel"
    p.font.name = FONT_NAME
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = COLOR_BLACK
    p.space_after = Pt(12)

    analyst_points = [
        ("Real-Time Telemetry Dashboard", "ApexCharts live graphs in /admin/security display request volume, HTTP status distribution (200, 401, 403, 429), and severity buckets (Safe, Warning, Critical)."),
        ("On-Demand AI Threat Synthesis", "Admins trigger an AI agent via POST /admin/security-analyze. The agent reviews recent HTTP heuristics and correlates threat classifications with client IPs."),
        ("Actionable Countermeasure Rules", "Translates raw attack patterns into concrete firewall rules (e.g. Nginx rate-limiting blocks, AWS WAF rules, and header security directives)."),
        ("Zero Overhead Runtime Guard", "Passive classification middleware adds <0.2ms latency per request; detection-only mode ensures valid business traffic is never accidentally blocked.")
    ]
    for an_title, an_desc in analyst_points:
        p = atf.add_paragraph()
        p.space_after = Pt(10)
        append_run(p, an_title + ": ", size_pt=11.5, bold=True, color_rgb=COLOR_BLACK)
        append_run(p, an_desc, size_pt=10.5, bold=False, color_rgb=COLOR_BODY)

    add_speaker_notes(s10,
        "Static code scanning protects repositories at rest, but what about the running application? VERITAS includes lightweight HTTP telemetry middleware that passively analyzes live API requests for "
        "SQL injection, XSS, SSRF, command injection, and path traversal heuristics. On the Admin Security page, live ApexCharts visualize attack volume, and an AI Security Analyst agent "
        "synthesizes recent incidents into actionable WAF rules and countermeasures."
    )

    # =========================================================================
    # SLIDE 11: COMPLIANCE & MULTI-FORMAT REPORTING
    # =========================================================================
    s11 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s11, "Compliance & Reporting: OASIS SARIF 2.1.0 & Exports",
                             subtitle_text="Delivering compliance-ready artifacts for developers, executives, and external security auditors")

    col_w = 3.65
    gap = 0.38

    rep_cols = [
        ("01 / OASIS SARIF 2.1.0 Standard", [
            ("Industry Interoperability: ", "Generates Static Analysis Results Interchange Format (SARIF 2.1.0) JSON schemas."),
            ("GitHub Security Ingestion: ", "Directly ingested by GitHub Advanced Security Code Scanning tabs and GitLab Security Dashboards."),
            ("SIEM & IDE Integration: ", "Importable into VS Code SARIF viewers, SonarQube, and enterprise vulnerability management systems.")
        ]),
        ("02 / Tokenized Public Reports", [
            ("No-Auth Review Link: ", "Shareable URL: /report/{token} allows external clients and stakeholders to inspect findings without platform accounts."),
            ("Read-Only Finding Drawer: ", "External auditors inspect code snippets, line numbers, severity distribution, and remediations."),
            ("Cryptographic Isolation: ", "Scoped strictly to that specific scan snapshot; zero access to user profile or project management APIs.")
        ]),
        ("03 / Multi-Format Exports & AI Summary", [
            ("Client Formats: ", "One-click export in Markdown (GFM), structured JSON, tabular CSV (for Excel compliance tracking), and standalone HTML."),
            ("Executive Risk Posture: ", "Groq Llama-3 evaluates repository security posture for non-technical executive leadership."),
            ("Top-3 Priority Countermeasures: ", "Pinpoints the three highest-impact vulnerabilities requiring immediate engineering remediation sprints.")
        ])
    ]

    for idx, (col_title, bullets) in enumerate(rep_cols):
        x = 0.8 + idx * (col_w + gap)
        tb = s11.shapes.add_textbox(Inches(x), Inches(c_top), Inches(col_w), Inches(5.0))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0

        p = tf.paragraphs[0]
        p.text = col_title
        p.font.name = FONT_NAME
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = COLOR_BLACK
        p.space_after = Pt(12)

        for b_title, b_desc in bullets:
            p = tf.add_paragraph()
            p.space_after = Pt(10)
            append_run(p, b_title, size_pt=11, bold=True, color_rgb=COLOR_BLACK)
            append_run(p, b_desc, size_pt=10.5, bold=False, color_rgb=COLOR_BODY)

    add_speaker_notes(s11,
        "Reporting is essential for enterprise compliance. VERITAS exports full SARIF 2.1.0—the OASIS industry standard format. This allows our scan results to be uploaded directly into GitHub Security or enterprise CI/CD systems. "
        "Additionally, we provide tokenized public report links so engineers can securely share a read-only report with clients or auditors without creating platform accounts, alongside Markdown, CSV, JSON, and HTML exports."
    )

    # =========================================================================
    # SLIDE 12: PLATFORM DEFENSIVE HARDENING
    # =========================================================================
    s12 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s12, "Defensive Engineering: Platform Security Posture",
                             subtitle_text="Practicing what we preach: robust architectural hardening and fail-closed safeguards across the platform")

    def_headers = ["SECURITY DOMAIN", "IMPLEMENTATION & MECHANISM", "THREAT MITIGATED & DEFENSIVE VALUE"]
    def_data = [
        ["Session Hardening", "veritas_session cookie with HttpOnly, SameSite=Lax, and Secure flags. SHA-256 hashed DB tokens.", "Mitigates XSS session theft and eliminates exposure of valid sessions if database backups are compromised."],
        ["Account Recovery", "Password resets immediately invalidate and delete all active session rows across all user devices.", "Eliminates lingering sessions if an account was compromised prior to password reset."],
        ["Authorization Guardrails", "Fail-closed role checks. Blocks deactivating the last active admin; admins cannot alter own role.", "Mitigates privilege escalation attacks and prevents accidental platform lockout."],
        ["Host Protection", "/admin/files restricts traversal; blocks /proc, /sys, /dev, /etc/shadow, and .env files.", "Prevents Local File Inclusion (LFI) and accidental disclosure of server credentials."]
    ]
    add_clean_table(s12, 0.8, c_top, 11.733, 4.7, def_headers, def_data, col_widths=[2.5, 4.8, 4.433])

    add_speaker_notes(s12,
        "As a cybersecurity platform, VERITAS must be thoroughly hardened itself. We followed defense-in-depth principles: "
        "all cookies use HttpOnly and SameSite flags; all tokens in the database are hashed; and our authorization model is strictly fail-closed. "
        "We prevent privilege escalation by disallowing admins from changing their own roles, and ensure the system always has at least one active administrator. "
        "Even our host filesystem browser restricts access to system directories and secrets."
    )

    # =========================================================================
    # SLIDE 13: LIVE DEMONSTRATION WORKFLOW
    # =========================================================================
    s13 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s13, "Demonstration Flow: End-to-End Operational Walkthrough",
                             subtitle_text="Step-by-step verification of user onboarding, push scanning, vulnerability triage, and SARIF export")

    col_w = 2.7
    gap_x = 0.31

    demo_steps = [
        ("Step 01 / Onboarding",
         "Identity lifecycle validation:",
         [("User Signup: ", "Registers via /auth/signup with Argon2."),
          ("Email Verification: ", "Verifies single-use token."),
          ("Approval Gate: ", "Account gated in pending_approval."),
          ("Admin Approval: ", "Admin reviews audit log and approves."),
          ("IP Telemetry: ", "Geolocation logs client origin.")]),
        
        ("Step 02 / GitHub Link",
         "CI/CD automation setup:",
         [("Connect OAuth: ", "Links verified GitHub identity."),
          ("Repo Attachment: ", "Server validates ownership."),
          ("Auto-Scan Enable: ", "Toggles auto_scan_on_push."),
          ("Webhook Provision: ", "HMAC secret configured."),
          ("Git Push: ", "Developer pushes test commit.")]),
        
        ("Step 03 / Scan Run",
         "Asynchronous execution:",
         [("HMAC Check: ", "Verifies X-Hub-Signature-256."),
          ("Sandbox Clone: ", "Clones to /tmp/veritas-scans."),
          ("12-Engine Run: ", "Executes Semgrep, OSV, Gitleaks."),
          ("OpenRouter Review: ", "Reviews high-risk hot files."),
          ("Groq Report: ", "Synthesizes fixes & purges disk.")]),
        
        ("Step 04 / Triage & Fix",
         "Remediation & compliance:",
         [("Finding Drawer: ", "Inspects line snippet and AI patch."),
          ("GitHub Blob Link: ", "Jumps to exact source line."),
          ("Suppression: ", "Silences false positive via SHA-256."),
          ("Compare Release: ", "Diffs against baseline scan."),
          ("Export SARIF: ", "Exports SARIF 2.1.0 for CI/CD.")])
    ]

    for idx, (title, sub, bullets) in enumerate(demo_steps):
        x = 0.8 + idx * (col_w + gap_x)
        tb = s13.shapes.add_textbox(Inches(x), Inches(c_top), Inches(col_w), Inches(5.0))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0

        p = tf.paragraphs[0]
        p.text = title
        p.font.name = FONT_NAME
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = COLOR_BLACK
        p.space_after = Pt(4)

        p = tf.add_paragraph()
        p.text = sub
        p.font.name = FONT_NAME
        p.font.size = Pt(10)
        p.font.color.rgb = COLOR_MUTED
        p.space_after = Pt(10)

        for b_title, b_desc in bullets:
            p = tf.add_paragraph()
            p.space_after = Pt(8)
            append_run(p, b_title, size_pt=10.5, bold=True, color_rgb=COLOR_BLACK)
            append_run(p, b_desc, size_pt=10, bold=False, color_rgb=COLOR_BODY)

    add_speaker_notes(s13,
        "Here is how we demonstrate the live platform during evaluation: "
        "1. We register a new user; they verify their email and get gated. The admin logs in, reviews the geocoded audit trail, and approves the account. "
        "2. The user connects their GitHub account and enables auto-scan on push. "
        "3. We make a git push containing a mock test commit. VERITAS catches the webhook and launches the scan pipeline automatically. "
        "4. When the scan finishes, the user inspects the finding drawer, reviews the AI remediation patch, clicks the GitHub line link, and exports the SARIF file."
    )

    # =========================================================================
    # SLIDE 14: CONCLUSION & FUTURE SCOPE
    # =========================================================================
    s14 = prs.slides.add_slide(blank_layout)
    c_top = add_slide_header(s14, "Conclusion & Future Engineering Scope",
                             subtitle_text="Summary of architectural contributions, enterprise scaling roadmap, and academic evaluation")

    col_w = 5.65
    gap_x = 0.43

    # Left Column: Key Contributions
    ctb = s14.shapes.add_textbox(Inches(0.8), Inches(c_top), Inches(col_w), Inches(3.6))
    ctf = ctb.text_frame
    ctf.word_wrap = True
    ctf.margin_left = ctf.margin_right = ctf.margin_top = ctf.margin_bottom = 0

    p = ctf.paragraphs[0]
    p.text = "Summary of Key Contributions"
    p.font.name = FONT_NAME
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = COLOR_BLACK
    p.space_after = Pt(12)

    concl_items = [
        ("Multi-Engine DevSecOps Orchestration: ", "Unified 12 deterministic security engines across Secrets, SCA, SAST, and IaC into a single automated pipeline."),
        ("Hybrid Deterministic + Dual-AI Pipeline: ", "Combined exact AST pattern matching with OpenRouter semantic code review and Groq Llama-3 code patches."),
        ("Zero-Trust IAM & Gated Lifecycle: ", "Enforced Argon2 hashing, mandatory admin approval gates, and multi-provider geolocation audit trails."),
        ("Continuous Push CI/CD & Runtime Defense: ", "Delivered Render-style auto-scan on push webhooks and live HTTP passive attack telemetry.")
    ]
    for c_title, c_desc in concl_items:
        p = ctf.add_paragraph()
        p.space_after = Pt(8)
        append_run(p, c_title, size_pt=11, bold=True, color_rgb=COLOR_BLACK)
        append_run(p, c_desc, size_pt=10.5, bold=False, color_rgb=COLOR_BODY)

    # Right Column: Future Scope
    ftb = s14.shapes.add_textbox(Inches(0.8 + col_w + gap_x), Inches(c_top), Inches(col_w), Inches(3.6))
    ftf = ftb.text_frame
    ftf.word_wrap = True
    ftf.margin_left = ftf.margin_right = ftf.margin_top = ftf.margin_bottom = 0

    p = ftf.paragraphs[0]
    p.text = "Future Research & Engineering Scope"
    p.font.name = FONT_NAME
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = COLOR_BLACK
    p.space_after = Pt(12)

    future_items = [
        ("Dynamic Application Security Testing (DAST): ", "Incorporate automated web application crawling and HTTP fuzzing engines to test running endpoints."),
        ("VS Code Real-Time Extension: ", "Deploy an inline developer linting extension powered by the VERITAS backend scanning rules for instant IDE feedback."),
        ("Automated Pull Request Remediation: ", "Generate automated GitHub Pull Requests containing LLM-crafted bug fixes and validated dependency upgrades."),
        ("Multi-Tenant Enterprise Workspaces: ", "Introduce organizational team hierarchies, role-based access control (RBAC), and centralized compliance audits.")
    ]
    for f_title, f_desc in future_items:
        p = ftf.add_paragraph()
        p.space_after = Pt(8)
        append_run(p, f_title, size_pt=11, bold=True, color_rgb=COLOR_BLACK)
        append_run(p, f_desc, size_pt=10.5, bold=False, color_rgb=COLOR_BODY)

    # Bottom Hairline Divider & Q&A Box
    div_bot = s14.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(5.6), Inches(11.733), Inches(0.015))
    div_bot.fill.solid()
    div_bot.fill.fore_color.rgb = COLOR_HAIRLINE
    div_bot.line.color.rgb = COLOR_HAIRLINE

    qtb = s14.shapes.add_textbox(Inches(0.8), Inches(5.8), Inches(11.733), Inches(1.2))
    qtf = qtb.text_frame
    qtf.word_wrap = True
    qtf.margin_left = qtf.margin_right = qtf.margin_top = qtf.margin_bottom = 0

    p = qtf.paragraphs[0]
    p.text = "THANK YOU FOR YOUR TIME AND GUIDANCE"
    p.font.name = FONT_NAME
    p.font.size = Pt(10.5)
    p.font.bold = True
    p.font.color.rgb = COLOR_MUTED
    p.space_after = Pt(4)

    p_qa = qtf.add_paragraph()
    p_qa.text = "We are open for questions and oral defense evaluation regarding the VERITAS architecture, cryptographic safeguards, scanning engines, or live demonstration."
    p_qa.font.name = FONT_NAME
    p_qa.font.size = Pt(11.5)
    p_qa.font.bold = True
    p_qa.font.color.rgb = COLOR_BLACK

    add_speaker_notes(s14,
        "In conclusion, VERITAS proves that robust application security does not have to slow developers down. By uniting multi-engine static analysis, dual-tier AI remediation, zero-trust governance, and live runtime threat telemetry, "
        "VERITAS provides an end-to-end security fabric for modern engineering organizations. Thank you very much. I am now open to your questions and feedback."
    )

    # Save Presentation
    out_ppt_path = "VERITAS_Security_Platform_Presentation.pptx"
    prs.save(out_ppt_path)
    print(f"Presentation generated successfully in exact NetGuard template theme: {out_ppt_path}")

if __name__ == '__main__':
    create_presentation()
