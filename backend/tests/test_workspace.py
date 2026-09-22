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
