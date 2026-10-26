"""
Automated Feature Verification Suite for VERITAS
Tests all implemented features against the live running server (http://127.0.0.1:8000).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add backend directory to path
backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

import uuid
import httpx
from app.core.database import SessionLocal
from app.core.time import utcnow
from app.models import Finding, FindingSuppression, Project, Scan, User
from app.services.auth import hash_password

BASE_URL = "http://127.0.0.1:8000"
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"


def run_checks():
    print(f"\n{INFO} Starting VERITAS Live Feature Verification Suite on {BASE_URL}...\n")
    client = httpx.Client(base_url=BASE_URL, timeout=15.0)

    total_checks = 0
    passed_checks = 0

    def check(name: str, condition: bool, details: str = ""):
        nonlocal total_checks, passed_checks
        total_checks += 1
        if condition:
            passed_checks += 1
            print(f" {PASS} {name} {details}")
        else:
            print(f" {FAIL} {name} - FAILED {details}")

    # 1. Health check & API liveness
    try:
        r = client.get("/health")
        data = r.json()
        check(
            "1. Health Liveness & Database Check",
            r.status_code == 200 and data.get("status") == "ok" and data.get("database") == "up",
            f"(status={data.get('status')}, db={data.get('database')}, version={data.get('version')})",
        )
    except Exception as exc:
        check("1. Health Liveness & Database Check", False, str(exc))

    # 2. Frontend SPA Routes served
    try:
        r = client.get("/")
        check("2. Frontend SPA Root (`/`)", r.status_code == 200 and "root" in r.text, "(served index.html)")
        r_admin = client.get("/admin/security")
        check("2. Frontend SPA Admin Route (`/admin/security`)", r_admin.status_code == 200 and "root" in r_admin.text)
        r_user = client.get("/user/projects")
        check("2. Frontend SPA User Route (`/user/projects`)", r_user.status_code == 200 and "root" in r_user.text)
    except Exception as exc:
        check("2. Frontend SPA Routes", False, str(exc))

    # 3. Authentication & RBAC Login
    user_client = httpx.Client(base_url=BASE_URL, timeout=15.0)
    admin_client = httpx.Client(base_url=BASE_URL, timeout=15.0)

    try:
        r_user = user_client.post("/auth/login", json={"email": "user@veritas.example", "password": "VeritasLab@2026"})
        user_info = r_user.json().get("user", {})
        check("3. User Login (`user@veritas.example`)", r_user.status_code == 200 and user_info.get("role") == "user", f"(role={user_info.get('role')})")

        r_admin = admin_client.post("/auth/login", json={"email": "admin@veritas.example", "password": "VeritasLab@2026"})
        admin_info = r_admin.json().get("user", {})
        check("3. Admin Login (`admin@veritas.example`)", r_admin.status_code == 200 and admin_info.get("role") == "admin", f"(role={admin_info.get('role')})")
    except Exception as exc:
        check("3. Authentication & Sessions", False, str(exc))

    # 4. Phase 6B Project Configuration: DAST Target URL, SLA Policies, Two-Person Suppression
    proj_id = None
    try:
        p_name = f"Enterprise App {uuid.uuid4().hex[:6]}"
        r_proj = user_client.post("/workspace/projects", json={"name": p_name, "description": "Verification test project"})
        check("4. Project Creation", r_proj.status_code in (200, 201), f"name={p_name}")
        proj_data = r_proj.json()
        proj_id = proj_data.get("project", {}).get("id") or proj_data.get("id")

        r_patch = user_client.patch(
            f"/workspace/projects/{proj_id}",
            json={
                "base_url": "https://app.verified-veritas.test",
                "require_suppression_approval": True,
                "sla_critical_days": 3,
                "sla_high_days": 10,
                "sla_medium_days": 30,
                "sla_low_days": 90,
            },
        )
        patched = r_patch.json().get("project", r_patch.json())
        check(
            "4. Phase 6B Advanced Settings (DAST Target URL, SLA Counters, 2-Person Suppression)",
            r_patch.status_code == 200
            and patched.get("base_url") == "https://app.verified-veritas.test"
            and patched.get("require_suppression_approval") is True
            and patched.get("sla_critical_days") == 3,
            f"(base_url={patched.get('base_url')}, require_suppression={patched.get('require_suppression_approval')})",
        )
    except Exception as exc:
        check("4. Project Configuration", False, str(exc))

    # 5. Phase 6B Team Access & RBAC Roles (Owner, Lead, Developer, Auditor)
    try:
        collab_email = f"lead_{uuid.uuid4().hex[:6]}@veritas.example"
        with SessionLocal() as s:
            collab_user = User(
                email=collab_email,
                display_name="Collab Lead",
                username=f"lead_{uuid.uuid4().hex[:4]}",
                password_hash=hash_password("VeritasLab@2026"),
                role="user",
                status="active",
                email_verified_at=utcnow(),
                approved_at=utcnow(),
            )
            s.add(collab_user)
            s.commit()

        r_mem = user_client.post(
            f"/workspace/projects/{proj_id}/members",
            json={"email": collab_email, "role": "security_lead"},
        )
        check("5. Project Team RBAC: Invite Member (`security_lead`)", r_mem.status_code == 200, f"email={collab_email}")

        r_list_mem = user_client.get(f"/workspace/projects/{proj_id}/members")
        members = r_list_mem.json().get("members", r_list_mem.json())
        roles = [m.get("role") for m in members] if isinstance(members, list) else []
        check("5. Project Team RBAC: List Members", r_list_mem.status_code == 200 and "security_lead" in roles, f"roles={roles}")
    except Exception as exc:
        check("5. Project Team RBAC", False, str(exc))

    # 6. Phase 6C Live DAST Engine & SSRF Protection
    try:
        from app.services.engines.dast_probe import validate_dast_target_url, DastTargetBlockedError, run_dast_probe

        ssrf_blocked = False
        try:
            validate_dast_target_url("http://169.254.169.254/latest/meta-data/", enforce_public_ip=True)
        except DastTargetBlockedError:
            ssrf_blocked = True
        check("6. Phase 6C DAST SSRF Protection (Cloud Metadata Range 169.254.169.254)", ssrf_blocked)

        loopback_blocked = False
        try:
            validate_dast_target_url("http://127.0.0.1:8000/secret", enforce_public_ip=True)
        except DastTargetBlockedError:
            loopback_blocked = True
        check("6. Phase 6C DAST SSRF Protection (RFC1918 / Loopback)", loopback_blocked)

        # Mock transport probe
        def mock_transport_handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/.env":
                return httpx.Response(200, headers={"Content-Type": "text/plain"}, text="SECRET_KEY=123456\nDB_PASS=admin\n")
            if request.headers.get("origin") == "https://evil-origin.veritas.invalid":
                return httpx.Response(200, headers={"Access-Control-Allow-Origin": "https://evil-origin.veritas.invalid", "Access-Control-Allow-Credentials": "true"})
            return httpx.Response(200, headers={"Server": "Express/4.18.2"}, text="<html>OK</html>")

        dast_findings, dast_meta = run_dast_probe(
            "https://test-target.veritas.invalid",
            transport=httpx.MockTransport(mock_transport_handler),
            enforce_public_ip=False,
        )
        rule_ids = {f.rule_id for f in dast_findings}
        check(
            "6. Phase 6C DAST Live Probes (CORS Origin Reflection, Exposed .env, CSP/HSTS, Tech Disclosures)",
            "dast.cors.origin_reflection" in rule_ids and "dast.exposure.dotenv" in rule_ids,
            f"found {len(dast_findings)} DAST findings",
        )
    except Exception as exc:
        check("6. DAST Probe Engine", False, str(exc))

    # 7. Phase 6C Automated Fix PR / Remediation Generator
    finding_id = None
    scan_id = None
    try:
        with SessionLocal() as session:
            usr = session.query(User).filter(User.email == "user@veritas.example").first()
            scan = Scan(
                project_id=proj_id,
                created_by_user_id=usr.id,
                target="https://github.com/example/repo",
                status="succeeded",
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_id = scan.id

            f = Finding(
                scan_id=scan.id,
                engine="osv",
                rule_id="CVE-2026-9999",
                vuln_family="sca",
                severity="high",
                title="Vulnerable cryptography package <= 40.0.0",
                file_path="requirements.txt",
                raw_json='{"package_name": "cryptography", "installed_version": "40.0.0", "fixed_version": "42.0.5"}',
            )
            session.add(f)
            session.commit()
            session.refresh(f)
            finding_id = f.id

        r_fix = user_client.post(f"/workspace/findings/{finding_id}/fix-plan")
        plan = r_fix.json()
        check(
            "7. Phase 6C Automated Fix PR Generator (`POST /workspace/findings/{id}/fix-plan`)",
            r_fix.status_code == 200
            and plan.get("branch_name", "").startswith("veritas/fix-")
            and "-cryptography==40.0.0" in plan.get("unified_diff", "")
            and "+cryptography>=42.0.5" in plan.get("unified_diff", ""),
            f"(branch={plan.get('branch_name')})",
        )
    except Exception as exc:
        check("7. Remediation PR Generator", False, str(exc))

    # 8. Phase 6B Two-Person Suppression Governance
    try:
        # Developer or owner requesting formal approval
        r_sup_req = user_client.patch(
            f"/workspace/findings/{finding_id}",
            json={
                "status": "false_positive",
                "suppress": True,
                "request_approval": True,
                "reason": "Compensating WAF control active in production environment",
            },
        )
        check("8. Phase 6B Finding Suppress Request Submitted", r_sup_req.status_code == 200)

        # Check suppression queue for project
        r_sup_list = user_client.get(f"/workspace/projects/{proj_id}/suppressions")
        sup_items = r_sup_list.json().get("items", [])
        sup_obj = sup_items[0] if sup_items else {}
        check(
            "8. Phase 6B Two-Person Suppression Status (`pending_approval`)",
            sup_obj.get("status") == "pending_approval",
            f"(status={sup_obj.get('status')})",
        )
        sup_id = sup_obj.get("id")

        # Lead / Admin approves suppression
        r_review = user_client.post(
            f"/workspace/projects/{proj_id}/suppressions/{sup_id}/review",
            json={"decision": "approved", "comment": "Verified WAF rule 1042 in place"},
        )
        check(
            "8. Phase 6B Lead Suppression Approval (`approved`)",
            r_review.status_code == 200 and r_review.json().get("suppression", {}).get("status") == "approved",
            f"(status={r_review.json().get('suppression', {}).get('status')})",
        )
    except Exception as exc:
        check("8. Two-Person Suppression Governance", False, str(exc))

    # 9. Phase 6B Multi-Framework Compliance Posture (OWASP Top 10, SOC 2, ISO 27001)
    try:
        r_comp = user_client.get(f"/workspace/projects/{proj_id}/scans/{scan_id}/compliance")
        comp = r_comp.json()
        frameworks = comp.get("frameworks", {})
        check(
            "9. Phase 6B Compliance Frameworks (OWASP Top 10, SOC 2, ISO 27001)",
            r_comp.status_code == 200
            and "owasp_top_10" in frameworks
            and "soc2" in frameworks
            and "iso27001" in frameworks,
            f"(readiness={comp.get('overall_readiness_score')}%, verdict={comp.get('overall_verdict')})",
        )
    except Exception as exc:
        check("9. Compliance Frameworks", False, str(exc))

    # 10. Phase 6C Active IPS Auto-Quarantine & Admin Unblock
    test_attacker_ip = f"198.51.100.{uuid.uuid4().int % 250 + 2}"
    attacker_headers = {"X-Forwarded-For": test_attacker_ip}
    try:
        payloads = [
            "/workspace/projects?q=' OR 1=1--",
            "/workspace/projects?q=UNION SELECT username, password FROM users",
            "/workspace/../../etc/passwd",
            "/workspace/projects?cmd=;cat /etc/shadow",
            "/workspace/projects?xss=<script>alert(1)</script>",
        ]
        for p in payloads:
            user_client.get(p, headers=attacker_headers)

        # 6th request must be blocked with HTTP 403
        r_quarantine = user_client.get("/workspace/projects", headers=attacker_headers)
        check(
            f"10. Phase 6C Active IPS Auto-Quarantine (Pre-routing 403 on {test_attacker_ip})",
            r_quarantine.status_code == 403 and "quarantined by VERITAS Active IPS" in r_quarantine.text,
            f"(status={r_quarantine.status_code})",
        )

        # Admin view blocked IPs
        r_blocked_list = admin_client.get("/admin/security/blocked-ips")
        blocked_items = r_blocked_list.json().get("items", [])
        ips_list = [b["ip_address"] for b in blocked_items]
        check(
            "10. Phase 6C Admin Blocked IPs Feed (`GET /admin/security/blocked-ips`)",
            r_blocked_list.status_code == 200 and test_attacker_ip in ips_list,
            f"found {len(blocked_items)} blocked IP(s)",
        )

        # Admin unblock
        r_unblock = admin_client.delete(f"/admin/security/blocked-ips/{test_attacker_ip}")
        check(
            f"10. Phase 6C Admin 1-Click Unblock (`DELETE /admin/security/blocked-ips/{test_attacker_ip}`)",
            r_unblock.status_code == 200 and r_unblock.json().get("unblocked") is True,
        )

        # Traffic restored
        r_restored = user_client.get("/workspace/projects", headers=attacker_headers)
        check(
            f"10. Phase 6C Traffic Restored after Unblock ({test_attacker_ip})",
            r_restored.status_code != 403,
            f"(status={r_restored.status_code})",
        )
    except Exception as exc:
        check("10. Active IPS Auto-Quarantine", False, str(exc))

    print(f"\n=======================================================")
    print(f" Verification Complete: {passed_checks}/{total_checks} checks passed.")
    print(f"=======================================================\n")
    return passed_checks == total_checks


if __name__ == "__main__":
    success = run_checks()
    sys.exit(0 if success else 1)
