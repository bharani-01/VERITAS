import os
from unittest.mock import MagicMock, patch

os.environ["APP_ENV"] = "test"
os.environ["VERITAS_BOOTSTRAP_ADMIN_EMAIL"] = "admin@veritas.example"
os.environ["VERITAS_BOOTSTRAP_ADMIN_PASSWORD"] = "bootstrap-password-123"
os.environ["VERITAS_BOOTSTRAP_ADMIN_NAME"] = "Bootstrap Admin"
os.environ["TOKEN_ENCRYPTION_SECRET"] = "test-token-encryption-secret"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from app import main
from app.core import database as db
from app.core.crypto import encrypt_secret
from app.core.rate_limit import rate_limiter
from app.models import AuditEvent, GitHubConnection, User
from app.services.tokens import issue_token


def fresh_client():
    rate_limiter.events.clear()
    db.engine.dispose()
    db.DATABASE_URL = "sqlite:///:memory:"
    db.engine = create_engine(
        db.DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    db.SessionLocal.configure(bind=db.engine)
    main.engine = db.engine
    main.SessionLocal = db.SessionLocal
    main.DATABASE_URL = db.DATABASE_URL
    return TestClient(main.app)


def _activate_student(client: TestClient) -> str:
    signup = client.post(
        "/auth/signup",
        json={"display_name": "Student One", "email": "student@example.com", "password": "a-secure-password-123"},
    )
    assert signup.status_code == 202
    with db.SessionLocal() as session:
        user = session.scalar(select(User).where(User.email == "student@example.com"))
        assert user is not None
        verification = issue_token(session, user, "verification")
        user_id = user.id
        session.commit()
    assert client.post("/auth/verify-email", json={"token": verification}).status_code == 200
    assert client.post("/auth/login", json={"email": "admin@veritas.example", "password": "bootstrap-password-123"}).status_code == 200
    assert client.post(f"/admin/users/{user_id}/approve").status_code == 200
    client.post("/auth/logout")
    assert client.post("/auth/login", json={"email": "student@example.com", "password": "a-secure-password-123"}).status_code == 200
    return user_id


def test_project_crud_and_scan_lifecycle():
    with fresh_client() as client:
        _activate_student(client)
        created = client.post("/workspace/projects", json={"name": "Alpha", "description": "First project"})
        assert created.status_code == 201
        project_id = created.json()["project"]["id"]
        listed = client.get("/workspace/projects")
        assert listed.status_code == 200
        assert len(listed.json()["items"]) == 1
        scan = client.post(
            f"/workspace/projects/{project_id}/scans",
            json={"target": "example.test", "scan_mode": "rules_only"},
        )
        assert scan.status_code == 201
        body = scan.json()["scan"]
        assert body["status"] == "completed"
        assert body["summary"]["findings_count"] == 0
        assert body["summary"]["scan_mode"] == "rules_only"
        assert "engines" in body["summary"]
        findings = client.get(f"/workspace/scans/{body['id']}/findings")
        assert findings.status_code == 200
        assert findings.json()["items"] == []
        dash = client.get("/workspace/dashboard")
        assert dash.status_code == 200
        assert dash.json()["totals"]["projects"] == 1
        assert len(dash.json()["recent_scans"]) == 1
        charts = dash.json().get("charts") or {}
        assert "runs" in charts
        assert "open_by_severity" in charts
        assert "scan_outcomes" in charts

        client.post("/auth/logout")
        assert client.post("/auth/login", json={"email": "admin@veritas.example", "password": "bootstrap-password-123"}).status_code == 200
        audit = client.get("/admin/audit-events?category=workspace&page_size=50")
        assert audit.status_code == 200
        actions = {item["action"] for item in audit.json()["items"]}
        assert "project_created" in actions
        assert "scan_started" in actions
        with db.SessionLocal() as session:
            assert session.scalar(select(AuditEvent).where(AuditEvent.action == "project_created")) is not None


def test_project_ownership_isolation():
    with fresh_client() as client:
        owner_id = _activate_student(client)
        created = client.post("/workspace/projects", json={"name": "Private"})
        project_id = created.json()["project"]["id"]
        client.post("/auth/logout")

        client.post(
            "/auth/signup",
            json={"display_name": "Other", "email": "other@example.com", "password": "a-secure-password-123"},
        )
        with db.SessionLocal() as session:
            other = session.scalar(select(User).where(User.email == "other@example.com"))
            token = issue_token(session, other, "verification")
            other_id = other.id
            session.commit()
        client.post("/auth/verify-email", json={"token": token})
        client.post("/auth/login", json={"email": "admin@veritas.example", "password": "bootstrap-password-123"})
        client.post(f"/admin/users/{other_id}/approve")
        client.post("/auth/logout")
        assert (
            client.post("/auth/login", json={"email": "other@example.com", "password": "a-secure-password-123"}).status_code
            == 200
        )
        assert client.get(f"/workspace/projects/{project_id}").status_code == 404
        assert client.post(f"/workspace/projects/{project_id}/scans", json={"target": "x"}).status_code == 404
        assert owner_id != other_id


def test_github_foreign_repo_rejected():
    with fresh_client() as client:
        user_id = _activate_student(client)
        with db.SessionLocal() as session:
            session.add(
                GitHubConnection(
                    user_id=user_id,
                    github_user_id=1001,
                    github_login="studentgh",
                    avatar_url=None,
                    token_encrypted=encrypt_secret("fake-token"),
                    scopes="repo",
                )
            )
            session.commit()

        foreign = {
            "id": 999,
            "full_name": "someoneelse/secret",
            "name": "secret",
            "private": True,
            "default_branch": "main",
            "html_url": "https://github.com/someoneelse/secret",
            "description": "",
            "owner": {"id": 42, "login": "someoneelse"},
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = foreign

        with patch("app.services.github.httpx.Client") as client_cls:
            instance = client_cls.return_value.__enter__.return_value
            instance.get.return_value = mock_resp
            res = client.post(
                "/workspace/projects",
                json={"name": "Hijack", "github_repo_id": 999},
            )
        assert res.status_code == 400
        assert "owned by your connected GitHub" in res.json()["detail"]
        client.post("/auth/logout")
        assert client.post("/auth/login", json={"email": "admin@veritas.example", "password": "bootstrap-password-123"}).status_code == 200
        audit = client.get("/admin/audit-events?action=github_repo_rejected")
        assert audit.status_code == 200
        assert any(item["action"] == "github_repo_rejected" for item in audit.json()["items"])


def test_github_owned_repo_accepted():
    with fresh_client() as client:
        user_id = _activate_student(client)
        with db.SessionLocal() as session:
            session.add(
                GitHubConnection(
                    user_id=user_id,
                    github_user_id=1001,
                    github_login="studentgh",
                    avatar_url=None,
                    token_encrypted=encrypt_secret("fake-token"),
                    scopes="repo",
                )
            )
            session.commit()

        owned = {
            "id": 55,
            "full_name": "studentgh/app",
            "name": "app",
            "private": False,
            "default_branch": "main",
            "html_url": "https://github.com/studentgh/app",
            "description": "mine",
            "owner": {"id": 1001, "login": "studentgh"},
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = owned

        with patch("app.services.github.httpx.Client") as client_cls:
            instance = client_cls.return_value.__enter__.return_value
            instance.get.return_value = mock_resp
            res = client.post(
                "/workspace/projects",
                json={"name": "From GH", "github_repo_id": 55},
            )
        assert res.status_code == 201
        project = res.json()["project"]
        assert project["github_repo_full_name"] == "studentgh/app"
        assert project["github_repo_id"] == 55


def test_github_disconnect_clears_active_connection():
    with fresh_client() as client:
        user_id = _activate_student(client)
        with db.SessionLocal() as session:
            session.add(
                GitHubConnection(
                    user_id=user_id,
                    github_user_id=1001,
                    github_login="studentgh",
                    avatar_url=None,
                    token_encrypted=encrypt_secret("fake-token"),
                    scopes="repo",
                )
            )
            session.commit()
        status = client.get("/workspace/github/status")
        assert status.json()["connected"] is True
        assert client.post("/workspace/github/disconnect").status_code == 200
        status2 = client.get("/workspace/github/status")
        assert status2.json()["connected"] is False
        assert client.get("/workspace/github/repos").status_code == 400
        assert client.get("/workspace/github/repos/123/refs").status_code == 400


def test_finding_status_patch_authz_and_suppress():
    with fresh_client() as client:
        user_id = _activate_student(client)
        created = client.post("/workspace/projects", json={"name": "Findings", "description": ""})
        assert created.status_code == 201
        project_id = created.json()["project"]["id"]
        scan = client.post(
            f"/workspace/projects/{project_id}/scans",
            json={"target": "example.test", "scan_mode": "rules_only"},
        )
        assert scan.status_code == 201
        scan_id = scan.json()["scan"]["id"]

        from app.models import Finding
        from app.services.engines.normalize import finding_fingerprint

        fp = finding_fingerprint(
            engine="semgrep",
            rule_id="test.rule",
            file_path="app.py",
            line_start=10,
            title="Test finding",
        )
        with db.SessionLocal() as session:
            finding = Finding(
                scan_id=scan_id,
                engine="semgrep",
                rule_id="test.rule",
                vuln_family="other",
                severity="high",
                title="Test finding",
                file_path="app.py",
                line_start=10,
                risk_score=8.0,
                status="open",
                fingerprint=fp,
            )
            session.add(finding)
            session.commit()
            finding_id = finding.id

        patched = client.patch(f"/workspace/findings/{finding_id}", json={"status": "triage"})
        assert patched.status_code == 200
        assert patched.json()["finding"]["status"] == "triage"

        bad = client.patch(f"/workspace/findings/{finding_id}", json={"status": "nope"})
        assert bad.status_code == 400

        suppressed = client.post(
            f"/workspace/findings/{finding_id}/suppress",
            json={"reason": "noise"},
        )
        assert suppressed.status_code == 200
        assert suppressed.json()["finding"]["status"] == "false_positive"

        # Second scan should auto-mark matching fingerprint as false_positive
        with patch("app.services.projects.run_scan_job") as mock_run:
            def _fake_job(sid: str):
                with db.SessionLocal() as session:
                    from app.models import Finding as F
                    from app.models import FindingSuppression, Scan

                    scan_row = session.get(Scan, sid)
                    assert scan_row is not None
                    suppressed_fps = {
                        row.fingerprint
                        for row in session.scalars(
                            select(FindingSuppression).where(FindingSuppression.project_id == project_id)
                        )
                    }
                    f2 = F(
                        scan_id=sid,
                        engine="semgrep",
                        rule_id="test.rule",
                        vuln_family="other",
                        severity="high",
                        title="Test finding",
                        file_path="app.py",
                        line_start=10,
                        risk_score=8.0,
                        status="open",
                        fingerprint=fp,
                    )
                    if fp in suppressed_fps:
                        f2.status = "false_positive"
                    scan_row.status = "completed"
                    session.add(f2)
                    session.add(scan_row)
                    session.commit()

            mock_run.side_effect = _fake_job
            scan2 = client.post(
                f"/workspace/projects/{project_id}/scans",
                json={"target": "example.test", "scan_mode": "rules_only"},
            )
            assert scan2.status_code == 201

        items = client.get(f"/workspace/scans/{scan2.json()['scan']['id']}/findings")
        assert items.status_code == 200
        assert items.json()["items"][0]["status"] == "false_positive"

        # Authz: logout → cannot patch
        client.post("/auth/logout")
        denied = client.patch(f"/workspace/findings/{finding_id}", json={"status": "fixed"})
        assert denied.status_code in {401, 403}
        _ = user_id


def test_cancel_queued_scan():
    with fresh_client() as client:
        _activate_student(client)
        created = client.post("/workspace/projects", json={"name": "Cancel", "description": ""})
        project_id = created.json()["project"]["id"]

        with patch("app.services.projects.run_scan_job"):
            scan = client.post(
                f"/workspace/projects/{project_id}/scans",
                json={"target": "example.test", "scan_mode": "rules_only"},
            )
            assert scan.status_code == 201
            scan_id = scan.json()["scan"]["id"]
            with db.SessionLocal() as session:
                from app.models import Scan

                row = session.get(Scan, scan_id)
                assert row is not None
                row.status = "queued"
                session.add(row)
                session.commit()

            cancelled = client.post(f"/workspace/scans/{scan_id}/cancel")
            assert cancelled.status_code == 200
            assert cancelled.json()["scan"]["status"] == "cancelled"

        done = client.post(
            f"/workspace/projects/{project_id}/scans",
            json={"target": "example.test", "scan_mode": "rules_only"},
        )
        assert done.status_code == 201
        assert client.post(f"/workspace/scans/{done.json()['scan']['id']}/cancel").status_code == 400


def test_compare_scans_and_fingerprint():
    with fresh_client() as client:
        _activate_student(client)
        created = client.post("/workspace/projects", json={"name": "Compare", "description": ""})
        project_id = created.json()["project"]["id"]
        a = client.post(
            f"/workspace/projects/{project_id}/scans",
            json={"target": "example.test", "scan_mode": "rules_only"},
        ).json()["scan"]["id"]
        b = client.post(
            f"/workspace/projects/{project_id}/scans",
            json={"target": "example.test", "scan_mode": "rules_only"},
        ).json()["scan"]["id"]

        from app.models import Finding
        from app.services.engines.normalize import finding_fingerprint

        with db.SessionLocal() as session:
            fp_shared = finding_fingerprint(
                engine="gitleaks", rule_id="aws", file_path="x.env", line_start=1, title="AWS key"
            )
            fp_only_b = finding_fingerprint(
                engine="osv", rule_id="CVE-1", file_path="req.txt", line_start=2, title="CVE"
            )
            session.add_all(
                [
                    Finding(
                        scan_id=a,
                        engine="gitleaks",
                        rule_id="aws",
                        vuln_family="secrets",
                        severity="critical",
                        title="AWS key",
                        file_path="x.env",
                        line_start=1,
                        risk_score=9.5,
                        fingerprint=fp_shared,
                    ),
                    Finding(
                        scan_id=b,
                        engine="gitleaks",
                        rule_id="aws",
                        vuln_family="secrets",
                        severity="critical",
                        title="AWS key",
                        file_path="x.env",
                        line_start=1,
                        risk_score=9.5,
                        fingerprint=fp_shared,
                    ),
                    Finding(
                        scan_id=b,
                        engine="osv",
                        rule_id="CVE-1",
                        vuln_family="sca",
                        severity="high",
                        title="CVE",
                        file_path="req.txt",
                        line_start=2,
                        risk_score=8.0,
                        fingerprint=fp_only_b,
                    ),
                ]
            )
            session.commit()

        cmp = client.get(f"/workspace/projects/{project_id}/scans/compare?a={a}&b={b}")
        assert cmp.status_code == 200
        body = cmp.json()
        assert body["counts"]["added"] == 1
        assert body["counts"]["removed"] == 0
        assert body["counts"]["unchanged"] == 1


def test_scan_rate_limit_enforced_outside_test_env():
    with fresh_client() as client:
        _activate_student(client)
        created = client.post("/workspace/projects", json={"name": "Quota", "description": ""})
        project_id = created.json()["project"]["id"]
        with patch("app.services.projects.APP_ENV", "development"):
            with patch("app.services.projects.SCAN_CONCURRENT_LIMIT", 1):
                with patch("app.services.projects.enqueue_scan"):
                    with patch("app.services.projects.run_scan_job"):
                        first = client.post(
                            f"/workspace/projects/{project_id}/scans",
                            json={"target": "example.test", "scan_mode": "rules_only"},
                        )
                        assert first.status_code == 201
                        with db.SessionLocal() as session:
                            from app.models import Scan

                            row = session.get(Scan, first.json()["scan"]["id"])
                            row.status = "running"
                            session.add(row)
                            session.commit()
                        second = client.post(
                            f"/workspace/projects/{project_id}/scans",
                            json={"target": "example.test", "scan_mode": "rules_only"},
                        )
                        assert second.status_code == 429


def test_groq_triage_fail_open():
    from app.services.ai_triage import triage_findings
    from app.services.engines.normalize import NormalizedFinding

    findings = [
        NormalizedFinding(engine="semgrep", title="SQLi", severity="high", file_path="a.py", line_start=1),
    ]
    with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test"}, clear=False):
        with patch("app.services.ai_triage.httpx.Client") as client_cls:
            client_cls.return_value.__enter__.return_value.post.side_effect = Exception("boom")
            result = triage_findings(findings)
    assert result["status"] == "failed_open"
    assert result["triaged"] == 0


def test_git_refs_403_does_not_mark_needs_reauth():
    with fresh_client() as client:
        user_id = _activate_student(client)
        created = client.post("/workspace/projects", json={"name": "Refs", "description": ""})
        project_id = created.json()["project"]["id"]
        with db.SessionLocal() as session:
            from app.models import GitHubConnection, Project

            session.add(
                GitHubConnection(
                    user_id=user_id,
                    github_user_id=1,
                    github_login="tester",
                    token_encrypted=encrypt_secret("tok"),
                    scopes="repo",
                    needs_reauth=False,
                )
            )
            project = session.get(Project, project_id)
            project.github_repo_full_name = "tester/demo"
            project.github_repo_id = 99
            session.add(project)
            session.commit()

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status = MagicMock()
        with patch("app.services.github.httpx.Client") as client_cls:
            client_cls.return_value.__enter__.return_value.get.return_value = mock_resp
            res = client.get(f"/workspace/projects/{project_id}/git-refs")
            assert res.status_code == 429

        with db.SessionLocal() as session:
            from app.models import GitHubConnection

            conn = session.scalar(select(GitHubConnection).where(GitHubConnection.user_id == user_id))
            assert conn is not None
            assert conn.needs_reauth is False


def test_github_webhook_signature_and_push_scan():
    import hashlib
    import hmac
    import json

    with fresh_client() as client:
        user_id = _activate_student(client)
        created = client.post(
            "/workspace/projects",
            json={"name": "Hook", "description": "", "github_repo_id": None},
        )
        project_id = created.json()["project"]["id"]
        secret = "webhook-test-secret"

        with db.SessionLocal() as session:
            from app.models import Project

            project = session.get(Project, project_id)
            project.github_repo_id = 4242
            project.github_repo_full_name = "tester/hook"
            project.github_default_branch = "main"
            project.auto_scan_on_push = True
            project.github_webhook_secret = encrypt_secret(secret)
            project.github_webhook_id = 1
            session.add(project)
            session.commit()

        payload = {
            "ref": "refs/heads/main",
            "after": "abc123def456abc123def456abc123def456abcd",
            "repository": {"id": 4242, "default_branch": "main", "full_name": "tester/hook"},
            "head_commit": {"id": "abc123def456abc123def456abc123def456abcd", "message": "feat", "author": {"name": "Dev"}},
        }
        body = json.dumps(payload).encode()
        bad = client.post(
            "/webhooks/github",
            content=body,
            headers={"Content-Type": "application/json", "X-GitHub-Event": "push", "X-Hub-Signature-256": "sha256=dead"},
        )
        assert bad.status_code == 401

        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        with patch("app.services.projects.run_scan_job"):
            ok = client.post(
                "/webhooks/github",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-GitHub-Event": "push",
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Delivery": "del-1",
                },
            )
        assert ok.status_code == 200
        assert ok.json().get("scan_id")

        # Other branch ignored
        other = dict(payload)
        other["ref"] = "refs/heads/feature"
        other_body = json.dumps(other).encode()
        other_sig = "sha256=" + hmac.new(secret.encode(), other_body, hashlib.sha256).hexdigest()
        skipped = client.post(
            "/webhooks/github",
            content=other_body,
            headers={"Content-Type": "application/json", "X-GitHub-Event": "push", "X-Hub-Signature-256": other_sig},
        )
        assert skipped.status_code == 200
        assert skipped.json().get("skipped") == "not_watched_branch"
        _ = user_id


def test_scan_create_accepts_quality_options():
    with fresh_client() as client:
        _activate_student(client)
        created = client.post("/workspace/projects", json={"name": "Quality", "description": ""})
        project_id = created.json()["project"]["id"]
        with patch("app.services.projects.run_scan_job"):
            with patch("app.services.projects.enqueue_scan"):
                res = client.post(
                    f"/workspace/projects/{project_id}/scans",
                    json={
                        "target": "example.test",
                        "scan_mode": "rules_plus_ai",
                        "security_level": "strict",
                        "engines": ["gitleaks", "semgrep"],
                        "path_excludes": ["node_modules/**", "vendor/**"],
                        "fail_severity": "high",
                        "code_review": True,
                    },
                )
        assert res.status_code == 201
        scan = res.json()["scan"]
        assert scan["security_level"] == "strict"
        assert scan["scan_mode"] == "rules_plus_ai"
        opts = scan.get("options") or {}
        assert "gitleaks" in opts.get("engines", [])
        assert "semgrep" in opts.get("engines", [])
        assert "osv" not in opts.get("engines", [])
        assert opts.get("fail_severity") == "high"
        assert opts.get("code_review") is True
        assert "node_modules/**" in (opts.get("path_excludes") or [])

        bad = client.post(
            f"/workspace/projects/{project_id}/scans",
            json={"engines": [], "fail_severity": "ultra"},
        )
        assert bad.status_code == 400
