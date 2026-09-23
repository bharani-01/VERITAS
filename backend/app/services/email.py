from __future__ import annotations

import httpx
from sqlalchemy.orm import Session

from app.core.config import PUBLIC_APP_URL, RESEND_API_KEY, RESEND_FROM_EMAIL
from app.models import EmailDelivery, User
from app.services.tokens import issue_token

RESEND_EMAILS_URL = "https://api.resend.com/emails"


def send_email(db: Session, user: User, template: str, subject: str, html: str) -> None:
    delivery = EmailDelivery(user_id=user.id, template=template, delivery_status="queued")
    db.add(delivery)
    db.flush()
    if not RESEND_API_KEY:
        return
    payload = {
        "from": RESEND_FROM_EMAIL,
        "to": [user.email],
        "subject": subject,
        "html": html,
    }
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                RESEND_EMAILS_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "User-Agent": "VERITAS/0.1",
                },
            )
            response.raise_for_status()
            result = response.json()
            delivery.delivery_status = "sent"
            delivery.provider_message_id = result.get("id")
    except (httpx.HTTPError, ValueError, TypeError):
        delivery.delivery_status = "failed"


def send_token_email(db: Session, user: User, token_type: str) -> None:
    raw = issue_token(db, user, token_type)
    if token_type == "verification":
        url = f"{PUBLIC_APP_URL}/verify?token={raw}"
        send_email(
            db,
            user,
            "email_verification",
            "Verify your VERITAS email",
            f"<p>Verify your email to continue: <a href='{url}'>Verify email</a></p>",
        )
    else:
        url = f"{PUBLIC_APP_URL}/reset?token={raw}"
        send_email(
            db,
            user,
            "password_reset",
            "Reset your VERITAS password",
            f"<p>Reset your password: <a href='{url}'>Reset password</a></p>",
        )
