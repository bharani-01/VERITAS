from __future__ import annotations

import json
import os
import tempfile
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

TEST_DB_DIR = tempfile.mkdtemp(prefix="veritas-phase6b-tests-")
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = f"sqlite:///{Path(TEST_DB_DIR) / 'test_phase6b.db'}"
os.environ["BOOTSTRAP_ADMIN_EMAIL"] = "admin@example.com"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "StrongPass!123"
os.environ["EMAIL_DELIVERY_MODE"] = "Sink"
os.environ["TOKEN_ENCRYPTION_SECRET"] = "test-secret-for-phase6b-suite"

from app.core import database as db  # noqa: E402
from app.core.rate_limit import rate_limiter
from app.core.time import ensure_utc, utcnow  # noqa: E402
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    AuditEvent,
    Finding,
    FindingSuppression,
    Project,
    Scan,
    ScanSbomArtifact,
    User,
)
from app.services.auth import bootstrap_admin_account, ensure_schema, hash_password  # noqa: E402
from app.services.compliance import compute_finding_sla  # noqa: E402


def _make_active_user(email: str, password: str = "UserPass!123456") -> str:
    with db.SessionLocal() as session:
        user = User(
            email=email,
            password_hash=hash_password(password),
            role="user",
            status="active",
            email_verified_at=utcnow(),
            approved_at=utcnow(),
        )
        session.add(user)
        session.commit()
        return user.id


@pytest.fixture()
def client():
    rate_limiter.events.clear()
    db.reload_engine(f"sqlite:///{Path(TEST_DB_DIR) / 'test_phase6b.db'}")
    db.Base.metadata.drop_all(bind=db.engine)
    ensure_schema()
    with db.SessionLocal() as session:
        bootstrap_admin_account(session)
    with TestClient(app) as c:
        yield c


def _login(c: TestClient, email: str, password: str = "UserPass!123456"):
    rate_limiter.events.clear()
    resp = c.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text


# ============================================================================
# 1. Project Member RBAC Roles & Auditor Read-Only Enforcement
# ============================================================================


def test_project_member_rbac_roles_and_auditor_readonly(client: TestClient):
    owner_id = _make_active_user("rbac_owner@example.com")
    _make_active_user("rbac_auditor@example.com")
    _make_active_user("rbac_outsider@example.com")

    with db.SessionLocal() as session:
        proj = Project(owner_user_id=owner_id, name="RBAC Enterprise Project")
        session.add(proj)
        session.commit()
        session.refresh(proj)

        scan = Scan(
            project_id=proj.id,
            created_by_user_id=owner_id,
            target="https://github.com/example/rbac-repo",
            status="succeeded",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        finding = Finding(
            scan_id=scan.id,
            engine="semgrep",
            rule_id="python.sqli",
            vuln_family="sqli",
            cwe="CWE-89",
            owasp_category="A03:2021-Injection",
            severity="high",
            title="SQL Injection in query builder",
            file_path="app/db.py",
            line_start=42,
            risk_score=8.0,
            effective_priority_score=8.0,
            fingerprint="fp-rbac-sqli-1",
        )
        session.add(finding)
        session.add(
            ScanSbomArtifact(
                scan_id=scan.id,
                project_id=proj.id,
                spec_version="CycloneDX-1.5",
                component_count=1,
                license_summary_json=json.dumps({"permissive": 1, "weak_copyleft": 0, "restricted_copyleft": 0, "unknown": 0}),
                policy_violations_count=0,
                sbom_json=json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "fastapi", "version": "0.115.0", "purl": "pkg:pypi/fastapi@0.115.0", "licenses": [{"license": {"id": "MIT"}}]}]}),
            )
        )
        session.commit()
        project_id = proj.id
        scan_id = scan.id
        finding_id = finding.id

    # Owner invites rbac_auditor@example.com with role='auditor'
    _login(client, "rbac_owner@example.com")
    add_resp = client.post(
        f"/workspace/projects/{project_id}/members",
        json={"email": "rbac_auditor@example.com", "role": "auditor"},
    )
    assert add_resp.status_code == 200, add_resp.text
    assert add_resp.json()["member"]["role"] == "auditor"

    members_resp = client.get(f"/workspace/projects/{project_id}/members")
    assert members_resp.status_code == 200
    assert members_resp.json()["total"] == 2
    client.post("/auth/logout")

    # Invited auditor can GET project scans, findings, SBOM, and compliance (200 OK)
    _login(client, "rbac_auditor@example.com")
    assert client.get(f"/workspace/projects/{project_id}").status_code == 200
    assert client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/findings").status_code == 200
    assert client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/sbom").status_code == 200
    assert client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/compliance").status_code == 200

    # Invited auditor is blocked with 403 Forbidden on write mutations
    scan_trigger = client.post(
        f"/workspace/projects/{project_id}/scans",
        json={"target": "https://github.com/example/rbac-repo"},
    )
    assert scan_trigger.status_code == 403

    patch_attempt = client.patch(
        f"/workspace/findings/{finding_id}",
        json={"status": "false_positive", "suppress": True},
    )
    assert patch_attempt.status_code == 403
    client.post("/auth/logout")

    # Uninvited outsider still receives 404 Not Found
    _login(client, "rbac_outsider@example.com")
    assert client.get(f"/workspace/projects/{project_id}").status_code == 404
    assert client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/compliance").status_code == 404


# ============================================================================
# 2. Two-Person Suppression Request & Security Lead Approval Workflow
# ============================================================================


def test_two_person_suppression_request_and_lead_approval(client: TestClient):
    owner_id = _make_active_user("gov_owner@example.com")
    _make_active_user("gov_dev@example.com")
    _make_active_user("gov_lead@example.com")

    with db.SessionLocal() as session:
        proj = Project(
            owner_user_id=owner_id,
            name="Two-Person Governance App",
            require_suppression_approval=True,
        )
        session.add(proj)
        session.commit()
        session.refresh(proj)

        scan = Scan(
            project_id=proj.id,
            created_by_user_id=owner_id,
            target="https://github.com/example/gov-app",
            status="succeeded",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        finding = Finding(
            scan_id=scan.id,
            engine="gitleaks",
            rule_id="generic-api-key",
            vuln_family="secret",
            cwe="CWE-798",
            severity="high",
            title="Test fixture token in mock_data.py",
            file_path="tests/mock_data.py",
            line_start=12,
            status="open",
            fingerprint="fp-gov-secret-12",
        )
        session.add(finding)
        session.commit()
        project_id = proj.id
        finding_id = finding.id

    # Owner adds developer and security_lead
    _login(client, "gov_owner@example.com")
    assert (
        client.post(
            f"/workspace/projects/{project_id}/members",
            json={"email": "gov_dev@example.com", "role": "developer"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/workspace/projects/{project_id}/members",
            json={"email": "gov_lead@example.com", "role": "security_lead"},
        ).status_code
        == 200
    )
    client.post("/auth/logout")

    # Developer submits a risk-acceptance suppression request -> creates pending_approval, finding stays open
    _login(client, "gov_dev@example.com")
    patch_resp = client.patch(
        f"/workspace/findings/{finding_id}",
        json={
            "status": "false_positive",
            "suppress": True,
            "suppression_type": "risk_accepted",
            "justification": "Synthetic unit test fixture token, non-production.",
            "expires_in_days": 60,
        },
    )
    assert patch_resp.status_code == 200, patch_resp.text
    assert patch_resp.json()["finding"]["status"] == "open"

    supps_resp = client.get(f"/workspace/projects/{project_id}/suppressions")
    assert supps_resp.status_code == 200
    supps = supps_resp.json()["suppressions"]
    assert len(supps) == 1
    assert supps[0]["status"] == "pending_approval"
    assert supps[0]["suppression_type"] == "risk_accepted"
    suppression_id = supps[0]["id"]
    client.post("/auth/logout")

    # Security Lead approves the pending suppression -> finding transitions to false_positive + AuditEvent recorded
    _login(client, "gov_lead@example.com")
    review_resp = client.post(
        f"/workspace/projects/{project_id}/suppressions/{suppression_id}/review",
        json={
            "decision": "approved",
            "review_note": "Verified mock test key; approved for 60 days.",
            "expires_in_days": 60,
        },
    )
    assert review_resp.status_code == 200, review_resp.text
    assert review_resp.json()["suppression"]["status"] == "approved"

    with db.SessionLocal() as session:
        refreshed_finding = session.scalar(select(Finding).where(Finding.id == finding_id))
        assert refreshed_finding is not None
        assert refreshed_finding.status == "false_positive"

        audit_row = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "finding.suppression.reviewed")
        )
        assert audit_row is not None


# ============================================================================
# 3. Expired Suppression Auto-Reopen & SLA Calculation
# ============================================================================


def test_expired_suppression_auto_reopens_and_sla_calculation(client: TestClient):
    owner_id = _make_active_user("sla_owner@example.com")

    with db.SessionLocal() as session:
        proj = Project(
            owner_user_id=owner_id,
            name="SLA & Expiry App",
            sla_critical_days=5,
            sla_high_days=10,
        )
        session.add(proj)
        session.commit()
        session.refresh(proj)

        due_crit, breached_crit = compute_finding_sla(proj, severity="critical", is_kev=True)
        expected_due = utcnow() + timedelta(days=5)
        assert abs((ensure_utc(due_crit) - expected_due).total_seconds()) < 10
        assert breached_crit is False

        scan = Scan(
            project_id=proj.id,
            created_by_user_id=owner_id,
            target="https://github.com/example/sla-app",
            status="succeeded",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        # Create a suppression whose expires_at is already in the past
        past_expiry = utcnow() - timedelta(days=2)
        session.add(
            FindingSuppression(
                project_id=proj.id,
                fingerprint="fp-expired-vuln-1",
                reason="Temporary 30d exception",
                created_by_user_id=owner_id,
                status="approved",
                suppression_type="risk_accepted",
                expires_at=past_expiry,
            )
        )
        finding = Finding(
            scan_id=scan.id,
            engine="semgrep",
            rule_id="xss-rule",
            vuln_family="xss",
            cwe="CWE-79",
            severity="high",
            title="Reflected XSS in search param",
            file_path="src/views.py",
            line_start=20,
            status="false_positive",
            fingerprint="fp-expired-vuln-1",
            sla_due_at=utcnow() - timedelta(days=1),
            sla_breached=True,
        )
        session.add(finding)
        session.commit()
        project_id = proj.id
        scan_id = scan.id

    _login(client, "sla_owner@example.com")
    supps_resp = client.get(f"/workspace/projects/{project_id}/suppressions")
    assert supps_resp.status_code == 200
    supp_list = supps_resp.json()["suppressions"]
    assert len(supp_list) == 1
    assert supp_list[0]["status"] == "expired"

    # Verify the previously suppressed finding automatically reopened and flags sla_breached=True
    findings_resp = client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    f_item = findings_resp.json()["findings"][0]
    assert f_item["status"] == "open"
    assert f_item["sla_breached"] is True


# ============================================================================
# 4. Compliance Posture Mapping (OWASP / SOC 2 / ISO 27001) & Certificate Export
# ============================================================================


def test_compliance_posture_mapping_and_certificate_export(client: TestClient):
    owner_id = _make_active_user("comp_owner@example.com")

    with db.SessionLocal() as session:
        proj = Project(owner_user_id=owner_id, name="Compliance Scorecard Service")
        session.add(proj)
        session.commit()
        session.refresh(proj)

        scan = Scan(
            project_id=proj.id,
            created_by_user_id=owner_id,
            target="https://github.com/example/compliance-service",
            commit_sha="a1b2c3d4e5f60718293a",
            status="succeeded",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        # 1. SQL Injection -> OWASP A03:2021, SOC 2 CC7.1, ISO 27001 A.8.28
        session.add(
            Finding(
                scan_id=scan.id,
                engine="semgrep",
                rule_id="sqli",
                vuln_family="sqli",
                cwe="CWE-89",
                owasp_category="A03:2021-Injection",
                severity="critical",
                title="SQL Injection in raw query",
                file_path="app/repo.py",
                line_start=55,
                status="open",
                fingerprint="fp-comp-1",
            )
        )
        # 2. Hardcoded Secret -> OWASP A07:2021, SOC 2 CC6.1, ISO 27001 A.8.25
        session.add(
            Finding(
                scan_id=scan.id,
                engine="gitleaks",
                rule_id="aws-access-key",
                vuln_family="secret",
                cwe="CWE-798",
                severity="high",
                title="AWS Secret Key leaked",
                file_path="app/config.py",
                line_start=10,
                status="open",
                fingerprint="fp-comp-2",
            )
        )
        # 3. Restricted Copyleft License -> OWASP A06:2021, SOC 2 CC6.8, ISO 27001 A.5.36
        session.add(
            Finding(
                scan_id=scan.id,
                engine="trivy_license",
                rule_id="LICENSE-AGPL-3.0",
                vuln_family="license",
                cwe="CWE-1104",
                owasp_category="A06:2021-Vulnerable and Outdated Components",
                severity="high",
                title="Restricted Copyleft License Detected: pdf-lib@1.0.0 (AGPL-3.0)",
                file_path="package.json",
                line_start=1,
                status="open",
                fingerprint="fp-comp-3",
            )
        )
        session.add(
            ScanSbomArtifact(
                scan_id=scan.id,
                project_id=proj.id,
                spec_version="CycloneDX-1.5",
                component_count=12,
                license_summary_json=json.dumps({"permissive": 11, "weak_copyleft": 0, "restricted_copyleft": 1, "unknown": 0}),
                policy_violations_count=1,
                sbom_json=json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}),
            )
        )
        session.commit()
        project_id = proj.id
        scan_id = scan.id

    _login(client, "comp_owner@example.com")
    comp_resp = client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/compliance")
    assert comp_resp.status_code == 200, comp_resp.text
    body = comp_resp.json()

    assert body["sbom_verified"] is True
    assert body["sbom_component_count"] == 12
    assert body["total_open_findings"] == 3

    owasp_controls = {c["control_id"]: c for c in body["frameworks"]["owasp_top_10"]["controls"]}
    assert owasp_controls["A03:2021"]["status"] == "fail"
    assert owasp_controls["A06:2021"]["status"] == "fail"
    assert owasp_controls["A07:2021"]["status"] == "fail"
    assert owasp_controls["A01:2021"]["status"] == "pass"

    soc2_controls = {c["control_id"]: c for c in body["frameworks"]["soc2"]["controls"]}
    assert soc2_controls["CC6.1"]["status"] == "fail"
    assert soc2_controls["CC6.8"]["status"] == "fail"
    assert soc2_controls["CC7.1"]["status"] == "fail"

    iso_controls = {c["control_id"]: c for c in body["frameworks"]["iso27001"]["controls"]}
    assert iso_controls["A.8.8"]["status"] == "fail"
    assert iso_controls["A.8.28"]["status"] == "fail"
    assert iso_controls["A.5.36"]["status"] == "fail"

    # Verify printable HTML Compliance Audit Certificate export
    cert_resp = client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/compliance/export")
    assert cert_resp.status_code == 200
    assert "text/html" in cert_resp.headers.get("content-type", "")
    assert "VERITAS DevSecOps Compliance Audit Certificate" in cert_resp.text
    assert "Compliance Scorecard Service" in cert_resp.text
    assert "ISO/IEC 27001:2022 Annex A" in cert_resp.text
