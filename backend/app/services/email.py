from __future__ import annotations

import httpx
from sqlalchemy.orm import Session

from app.core.config import OPS_ALERT_EMAIL, PUBLIC_APP_URL, RESEND_API_KEY, RESEND_FROM_EMAIL
from app.models import EmailDelivery, User
from app.services import email_templates as templates
from app.services.tokens import issue_token

RESEND_EMAILS_URL = "https://api.resend.com/emails"


def send_email_address(
    db: Session,
    *,
    to_email: str,
    template: str,
    subject: str,
    html: str,
    user_id: str | None = None,
) -> None:
    """Send transactional mail to an arbitrary address (ops alerts, etc.)."""
    dest = (to_email or "").strip()
    if not dest:
        return
    delivery = EmailDelivery(user_id=user_id, template=template, delivery_status="queued")
    db.add(delivery)
    db.flush()
    if not RESEND_API_KEY:
        return
    payload = {
        "from": RESEND_FROM_EMAIL,
        "to": [dest],
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
                    "User-Agent": "VERITAS/0.2",
                },
            )
            response.raise_for_status()
            result = response.json()
            delivery.delivery_status = "sent"
            delivery.provider_message_id = result.get("id")
    except (httpx.HTTPError, ValueError, TypeError):
        delivery.delivery_status = "failed"


def send_email(db: Session, user: User, template: str, subject: str, html: str) -> None:
    send_email_address(
        db,
        to_email=user.email,
        template=template,
        subject=subject,
        html=html,
        user_id=user.id,
    )


def send_message(db: Session, user: User, message: templates.EmailMessage) -> None:
    send_email(db, user, message.template, message.subject, message.html)


def send_token_email(db: Session, user: User, token_type: str) -> None:
    raw = issue_token(db, user, token_type)
    if token_type == "verification":
        msg = templates.verification_email(
            display_name=user.display_name,
            verify_url=f"{PUBLIC_APP_URL}/verify?token={raw}",
        )
    else:
        msg = templates.password_reset_email(
            display_name=user.display_name,
            reset_url=f"{PUBLIC_APP_URL}/reset?token={raw}",
        )
    send_message(db, user, msg)


def send_password_changed(db: Session, user: User) -> None:
    send_message(
        db,
        user,
        templates.password_changed_email(
            display_name=user.display_name,
            sign_in_url=f"{PUBLIC_APP_URL}/",
        ),
    )


def send_account_status(db: Session, user: User, status: str) -> None:
    send_message(
        db,
        user,
        templates.account_status_email(
            display_name=user.display_name,
            status=status,
            sign_in_url=f"{PUBLIC_APP_URL}/",
        ),
    )


def send_admin_approval_required(db: Session, admin: User, applicant: User) -> None:
    send_message(
        db,
        admin,
        templates.admin_approval_required_email(
            applicant_name=applicant.display_name,
            applicant_email=applicant.email,
            directory_url=f"{PUBLIC_APP_URL}/admin/directory",
        ),
    )


def send_scan_finished(
    db: Session,
    user: User,
    *,
    project_name: str,
    project_id: str,
    scan_id: str,
    status: str,
    findings_count: int,
    scan_mode: str,
) -> None:
    send_message(
        db,
        user,
        templates.scan_finished_email(
            display_name=user.display_name,
            project_name=project_name,
            status=status,
            findings_count=findings_count,
            scan_mode=scan_mode,
            report_url=f"{PUBLIC_APP_URL}/user/projects/{project_id}/scans/{scan_id}",
        ),
    )


def send_ops_scan_alert(
    db: Session,
    *,
    project_name: str,
    project_id: str,
    scan_id: str,
    status: str,
    owner_email: str | None,
    issues: list[str],
) -> None:
    """Notify ops inbox about missing engines or app-side scan failures. Fail-open."""
    if not issues:
        return
    to_email = OPS_ALERT_EMAIL
    if not to_email:
        return
    msg = templates.ops_scan_alert_email(
        project_name=project_name,
        scan_id=scan_id,
        status=status,
        owner_email=owner_email,
        issues=issues,
        report_url=f"{PUBLIC_APP_URL}/user/projects/{project_id}/scans/{scan_id}",
    )
    send_email_address(
        db,
        to_email=to_email,
        template=msg.template,
        subject=msg.subject,
        html=msg.html,
        user_id=None,
    )
