import os

os.environ["APP_ENV"] = "test"
os.environ["VERITAS_BOOTSTRAP_ADMIN_EMAIL"] = "admin@veritas.example"
os.environ["VERITAS_BOOTSTRAP_ADMIN_PASSWORD"] = "bootstrap-password-123"
os.environ["VERITAS_BOOTSTRAP_ADMIN_NAME"] = "Bootstrap Admin"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from app import main
from app.core import database as db
from app.core.rate_limit import rate_limiter
from app.models import User
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


def test_signup_verify_approve_login_and_deactivate():
    with fresh_client() as client:
        assert client.get("/auth/me").status_code == 401
        signup = client.post(
            "/auth/signup",
            json={"display_name": "Student One", "email": "Student@Example.com", "password": "a-secure-password-123"},
        )
        assert signup.status_code == 202
        with db.SessionLocal() as session:
            user = session.scalar(select(User).where(User.email == "student@example.com"))
            assert user.status == "pending_verification"
            assert user.password_hash != "a-secure-password-123"
            verification = issue_token(session, user, "verification")
            session.commit()
        assert client.post("/auth/verify-email", json={"token": verification}).status_code == 200
        assert (
            client.post("/auth/login", json={"email": "student@example.com", "password": "a-secure-password-123"}).status_code
            == 403
        )
        admin = client.post("/auth/login", json={"email": "admin@veritas.example", "password": "bootstrap-password-123"})
        assert admin.status_code == 200
        with db.SessionLocal() as session:
            user = session.scalar(select(User).where(User.email == "student@example.com"))
            user_id = user.id
        assert client.post(f"/admin/users/{user_id}/approve").status_code == 200
        dash = client.get("/admin/dashboard")
        assert dash.status_code == 200
        body = dash.json()
        assert body["totals"]["users"] >= 2
        assert "pending_approval" in body
        assert "recent_events" in body
        client.post("/auth/logout")
        assert (
            client.post("/auth/login", json={"email": "student@example.com", "password": "a-secure-password-123"}).status_code
            == 200
        )
        client.post("/auth/logout")
        client.post("/auth/login", json={"email": "admin@veritas.example", "password": "bootstrap-password-123"})
        assert client.post(f"/admin/users/{user_id}/deactivate").status_code == 200
        client.post("/auth/logout")
        assert (
            client.post("/auth/login", json={"email": "student@example.com", "password": "a-secure-password-123"}).status_code
            == 403
        )


def test_password_reset_revokes_sessions_and_email_change_requires_verification():
    with fresh_client() as client:
        client.post("/auth/login", json={"email": "admin@veritas.example", "password": "bootstrap-password-123"})
        with db.SessionLocal() as session:
            admin = session.scalar(select(User).where(User.email == "admin@veritas.example"))
            reset = issue_token(session, admin, "password_reset")
            session.commit()
        assert (
            client.post("/auth/password-reset/confirm", json={"token": reset, "password": "replacement-password-123"}).status_code
            == 200
        )
        assert client.get("/auth/me").status_code == 401
