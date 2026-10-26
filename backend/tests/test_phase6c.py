from __future__ import annotations

import os
import tempfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

TEST_DB_DIR = tempfile.mkdtemp(prefix="veritas-phase6c-tests-")
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = f"sqlite:///{Path(TEST_DB_DIR) / 'test_phase6c.db'}"
os.environ["BOOTSTRAP_ADMIN_EMAIL"] = "admin@example.com"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "StrongPass!123"
os.environ["EMAIL_DELIVERY_MODE"] = "Sink"
os.environ["TOKEN_ENCRYPTION_SECRET"] = "test-secret-for-phase6c-suite"

from app.core import database as db  # noqa: E402
from app.core.time import utcnow  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Project, Scan, User  # noqa: E402
from app.services.auth import bootstrap_admin_account, ensure_schema, hash_password  # noqa: E402
from app.services.engines.dast_probe import (  # noqa: E402
    DastTargetBlockedError,
    run_dast_probe,
    validate_dast_target_url,
)
from app.services.http_traffic import refresh_blocked_ip_cache  # noqa: E402


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
    db.reload_engine(f"sqlite:///{Path(TEST_DB_DIR) / 'test_phase6c.db'}")
    db.Base.metadata.drop_all(bind=db.engine)
    ensure_schema()
    with db.SessionLocal() as session:
        bootstrap_admin_account(session)
        refresh_blocked_ip_cache(session)
    with TestClient(app) as c:
        yield c


def _login(c: TestClient, email: str, password: str = "UserPass!123456"):
    resp = c.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text


def test_dast_live_url_probe_headers_cors_and_exposed_env():
    def _mock_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        origin = request.headers.get("origin")

        if path == "/.env":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                text="DATABASE_URL=postgresql://admin:secret@db.internal:5432/prod\nJWT_SECRET=supersecret\n",
            )
        if path == "/swagger.json":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text="<!DOCTYPE html><html><body><div id='root'>SPA</div></body></html>",
            )
        if path in ("/.git/HEAD", "/openapi.json"):
            return httpx.Response(404, text="Not Found")

        resp_headers = [
            ("Server", "nginx/1.18.0"),
            ("Set-Cookie", "session_id=xyz987; Path=/"),
        ]
        if origin == "https://evil-origin.veritas.invalid":
            resp_headers.append(("Access-Control-Allow-Origin", origin))
            resp_headers.append(("Access-Control-Allow-Credentials", "true"))

        return httpx.Response(200, headers=resp_headers, text="<html><body>Welcome</body></html>")

    mock_transport = httpx.MockTransport(_mock_handler)
    findings, meta = run_dast_probe(
        "https://vulnerable-web.example.com",
        transport=mock_transport,
        enforce_public_ip=False,
    )

    assert meta["available"] is True
    rule_ids = {f.rule_id for f in findings}
    assert "dast.header.csp" in rule_ids
    assert "dast.header.hsts" in rule_ids
    assert "dast.header.clickjacking" in rule_ids
    assert "dast.header.nosniff" in rule_ids
    assert "dast.header.version_disclosure" in rule_ids
    assert "dast.cookie.insecure" in rule_ids
    assert "dast.cors.origin_reflection" in rule_ids
    assert "dast.exposure.dotenv" in rule_ids
    assert "dast.exposure.swagger" not in rule_ids


def test_dast_ssrf_private_ip_protection():
    with pytest.raises(DastTargetBlockedError):
        validate_dast_target_url("http://169.254.169.254/latest/meta-data/", enforce_public_ip=True)

    with pytest.raises(DastTargetBlockedError):
        validate_dast_target_url("http://127.0.0.1:8000/admin", enforce_public_ip=True)

    with pytest.raises(DastTargetBlockedError):
        validate_dast_target_url("http://localhost:3000", enforce_public_ip=True)

    with pytest.raises(DastTargetBlockedError):
        validate_dast_target_url("ftp://example.com/file", enforce_public_ip=True)


def test_finding_fix_plan_generation_and_authz(client: TestClient):
    owner_id = _make_active_user("fix_owner@example.com")
    _make_active_user("fix_stranger@example.com")

    with db.SessionLocal() as session:
        proj = Project(owner_user_id=owner_id, name="Remediation PR App")
        session.add(proj)
        session.commit()
        session.refresh(proj)

        scan = Scan(
            project_id=proj.id,
            created_by_user_id=owner_id,
            target="https://github.com/example/remediation-app",
            status="succeeded",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        finding = Finding(
            scan_id=scan.id,
            engine="osv",
            rule_id="CVE-2026-102268",
            vuln_family="sca",
            cwe="CWE-937",
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            severity="critical",
            title="CVE-2026-102268 in requests 2.31.0",
            file_path="requirements.txt",
            line_start=4,
            cve_id="CVE-2026-102268",
            is_kev=True,
            epss_score=0.72,
            effective_priority_score=10.0,
            raw_json='{"package_name": "requests", "installed_version": "2.31.0", "fixed_version": "2.32.2"}',
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id

    _login(client, "fix_owner@example.com")
    resp = client.post(f"/workspace/findings/{finding_id}/fix-plan")
    assert resp.status_code == 200, resp.text
    plan = resp.json()
    assert plan["branch_name"].startswith("veritas/fix-")
    assert "CVE-2026-102268" in plan["commit_message"]
    assert "-requests==2.31.0" in plan["unified_diff"]
    assert "+requests>=2.32.2" in plan["unified_diff"]
    assert "CISA KEV Active Exploit" in plan["pr_body"]
    client.post("/auth/logout")

    _login(client, "fix_stranger@example.com")
    stranger_resp = client.post(f"/workspace/findings/{finding_id}/fix-plan")
    assert stranger_resp.status_code == 404


def test_active_ips_auto_quarantine_and_admin_unblock(client: TestClient):
    attacker_headers = {"X-Forwarded-For": "198.51.100.77"}

    attack_paths = [
        "/workspace/projects?q=' OR 1=1--",
        "/workspace/projects?q=UNION SELECT username, password FROM users",
        "/workspace/../../etc/passwd",
        "/workspace/projects?cmd=;cat /etc/shadow",
        "/workspace/projects?xss=<script>alert(1)</script>",
    ]
    for p in attack_paths:
        client.get(p, headers=attacker_headers)

    blocked_resp = client.get("/workspace/projects", headers=attacker_headers)
    assert blocked_resp.status_code == 403
    assert "quarantined by VERITAS Active IPS" in blocked_resp.json()["detail"]

    _login(client, "admin@example.com", "StrongPass!123")
    list_resp = client.get("/admin/security/blocked-ips")
    assert list_resp.status_code == 200
    ips = [item["ip_address"] for item in list_resp.json()["blocked_ips"]]
    assert "198.51.100.77" in ips

    del_resp = client.delete("/admin/security/blocked-ips/198.51.100.77")
    assert del_resp.status_code == 200
    assert del_resp.json()["unblocked"] is True

    restored_resp = client.get("/workspace/projects", headers=attacker_headers)
    assert restored_resp.status_code != 403
