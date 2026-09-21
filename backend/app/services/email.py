from __future__ import annotations

import json
import urllib.error
import urllib.request

from sqlalchemy.orm import Session

from app.core.config import PUBLIC_APP_URL, RESEND_API_KEY, RESEND_FROM_EMAIL
from app.models import EmailDelivery, User
from app.services.tokens import issue_token


def send_email(db: Session, user: User, template: str, subject: str, html: str) -> None:
    delivery = EmailDelivery(user_id=user.id, template=template, delivery_status="queued")
    db.add(delivery)
    db.flush()
    if not RESEND_API_KEY:
        return
    body = json.dumps(
        {
            "from": RESEND_FROM_EMAIL,
            "to": [user.email],
            "subject": subject,
            "html": html,
        }
    ).encode()
    request = urllib.request.Request(
        "https://api.resend.com/emails",
        data=body,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "VERITAS/0.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode())
            delivery.delivery_status = "sent"
            delivery.provider_message_id = result.get("id")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
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
