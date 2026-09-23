"""Transactional email HTML — compact, plain, no marketing chrome."""

from __future__ import annotations

import html
from dataclasses import dataclass


@dataclass(frozen=True)
class EmailMessage:
    template: str
    subject: str
    html: str


def _esc(value: str | None) -> str:
    return html.escape((value or "").strip(), quote=True)


def render_layout(
    *,
    title: str,
    paragraphs: list[str],
    cta_label: str | None = None,
    cta_url: str | None = None,
    meta_lines: list[str] | None = None,
    footer: str = "VERITAS · application security workspace",
) -> str:
    """Single-column transactional layout. Works in common email clients."""
    # Match product UI: Inter + Segoe UI / system fallbacks (docs/design.md).
    font = "'Inter','Segoe UI',system-ui,-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif"
    body_bits: list[str] = []
    for p in paragraphs:
        body_bits.append(
            f'<p style="margin:0 0 14px;font-size:15px;line-height:1.5;color:#3a3a3a;'
            f'font-family:{font};">{_esc(p)}</p>'
        )
    if meta_lines:
        rows = "".join(
            f'<tr><td style="padding:4px 0;font-size:13px;color:#6b6b6b;font-family:{font};">'
            f"{_esc(line)}</td></tr>"
            for line in meta_lines
            if line
        )
        body_bits.append(
            '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
            'style="margin:4px 0 16px;border-top:1px solid #e8e8e8;border-bottom:1px solid #e8e8e8;'
            f'padding:10px 0;">{rows}</table>'
        )
    cta = ""
    if cta_label and cta_url:
        cta = (
            '<table role="presentation" cellspacing="0" cellpadding="0" style="margin:8px 0 20px;">'
            "<tr><td>"
            f'<a href="{_esc(cta_url)}" style="display:inline-block;padding:10px 16px;'
            f"background:#111111;color:#ffffff;text-decoration:none;font-size:14px;"
            f'font-weight:600;border-radius:4px;font-family:{font};">{_esc(cta_label)}</a>'
            "</td></tr></table>"
            f'<p style="margin:0 0 16px;font-size:12px;line-height:1.45;color:#8a8a8a;font-family:{font};">'
            f'Or open: <a href="{_esc(cta_url)}" style="color:#4f8cff;word-break:break-all;">'
            f"{_esc(cta_url)}</a></p>"
        )
    body = "".join(body_bits)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_esc(title)}</title>
  <!--[if !mso]><!-->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
  <!--<![endif]-->
</head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:{font};">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f4f4;">
    <tr>
      <td align="center" style="padding:28px 16px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
               style="max-width:520px;background:#ffffff;border:1px solid #e6e6e6;">
          <tr>
            <td style="padding:22px 24px 8px;font-family:{font};">
              <p style="margin:0 0 18px;font-size:12px;font-weight:700;letter-spacing:0.08em;
                        text-transform:uppercase;color:#111111;font-family:{font};">VERITAS</p>
              <h1 style="margin:0 0 14px;font-size:20px;line-height:1.3;font-weight:600;color:#111111;
                         font-family:{font};">
                {_esc(title)}
              </h1>
              {body}
              {cta}
              <p style="margin:24px 0 0;padding-top:16px;border-top:1px solid #ececec;
                        font-size:12px;line-height:1.45;color:#9a9a9a;font-family:{font};">{_esc(footer)}</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def verification_email(*, display_name: str, verify_url: str) -> EmailMessage:
    name = display_name.strip() or "there"
    return EmailMessage(
        template="email_verification",
        subject="Verify your email · VERITAS",
        html=render_layout(
            title="Confirm your email",
            paragraphs=[
                f"Hi {name},",
                "Use the button below to verify this address and continue account setup. "
                "The link expires in 30 minutes.",
                "If you did not create a VERITAS account, you can ignore this message.",
            ],
            cta_label="Verify email",
            cta_url=verify_url,
        ),
    )


def password_reset_email(*, display_name: str, reset_url: str) -> EmailMessage:
    name = display_name.strip() or "there"
    return EmailMessage(
        template="password_reset",
        subject="Reset your password · VERITAS",
        html=render_layout(
            title="Reset your password",
            paragraphs=[
                f"Hi {name},",
                "We received a request to reset the password for your VERITAS account. "
                "This link expires in 30 minutes and can be used once.",
                "If you did not request a reset, you can ignore this email. Your password will stay the same.",
            ],
            cta_label="Choose a new password",
            cta_url=reset_url,
        ),
    )


def password_changed_email(*, display_name: str, sign_in_url: str) -> EmailMessage:
    name = display_name.strip() or "there"
    return EmailMessage(
        template="password_changed",
        subject="Password updated · VERITAS",
        html=render_layout(
            title="Your password was updated",
            paragraphs=[
                f"Hi {name},",
                "The password for your VERITAS account was changed successfully. "
                "All existing sessions were signed out.",
                "If you did not make this change, reset your password immediately and contact an administrator.",
            ],
            cta_label="Sign in",
            cta_url=sign_in_url,
        ),
    )


def account_approved_email(*, display_name: str, sign_in_url: str) -> EmailMessage:
    name = display_name.strip() or "there"
    return EmailMessage(
        template="account_approved",
        subject="Account approved · VERITAS",
        html=render_layout(
            title="Your account is active",
            paragraphs=[
                f"Hi {name},",
                "An administrator approved your VERITAS account. You can sign in and start using the workspace.",
            ],
            cta_label="Sign in to VERITAS",
            cta_url=sign_in_url,
        ),
    )


def account_rejected_email(*, display_name: str) -> EmailMessage:
    name = display_name.strip() or "there"
    return EmailMessage(
        template="account_rejected",
        subject="Account request declined · VERITAS",
        html=render_layout(
            title="Account request declined",
            paragraphs=[
                f"Hi {name},",
                "Your request for a VERITAS account was not approved. "
                "If you believe this was a mistake, contact your administrator.",
            ],
        ),
    )


def account_deactivated_email(*, display_name: str) -> EmailMessage:
    name = display_name.strip() or "there"
    return EmailMessage(
        template="account_deactivated",
        subject="Account deactivated · VERITAS",
        html=render_layout(
            title="Your account was deactivated",
            paragraphs=[
                f"Hi {name},",
                "Your VERITAS account has been deactivated and active sessions were signed out. "
                "Contact an administrator if you need access restored.",
            ],
        ),
    )


def admin_approval_required_email(
    *,
    applicant_name: str,
    applicant_email: str,
    directory_url: str,
) -> EmailMessage:
    return EmailMessage(
        template="admin_approval_required",
        subject="Approval needed · VERITAS",
        html=render_layout(
            title="New account awaiting approval",
            paragraphs=[
                "A user verified their email and is waiting for administrator approval.",
            ],
            meta_lines=[
                f"Name: {applicant_name}",
                f"Email: {applicant_email}",
            ],
            cta_label="Open directory",
            cta_url=directory_url,
        ),
    )


def scan_finished_email(
    *,
    display_name: str,
    project_name: str,
    status: str,
    findings_count: int,
    scan_mode: str,
    report_url: str,
) -> EmailMessage:
    name = display_name.strip() or "there"
    status_label = (status or "unknown").replace("_", " ")
    mode_label = "Rules + AI" if scan_mode == "rules_plus_ai" else "Rules only"
    return EmailMessage(
        template="scan_completed",
        subject=f"Scan finished · {project_name}",
        html=render_layout(
            title="Scan finished",
            paragraphs=[
                f"Hi {name},",
                f"A scan for {project_name} has finished.",
            ],
            meta_lines=[
                f"Status: {status_label}",
                f"Findings: {findings_count}",
                f"Mode: {mode_label}",
            ],
            cta_label="View results",
            cta_url=report_url,
        ),
    )


def account_status_email(*, display_name: str, status: str, sign_in_url: str) -> EmailMessage:
    """Fallback for status transitions — prefer specific builders above."""
    key = (status or "").strip().lower()
    if key == "active":
        return account_approved_email(display_name=display_name, sign_in_url=sign_in_url)
    if key == "rejected":
        return account_rejected_email(display_name=display_name)
    if key == "deactivated":
        return account_deactivated_email(display_name=display_name)
    name = display_name.strip() or "there"
    label = key.replace("_", " ") or "updated"
    return EmailMessage(
        template="account_status",
        subject=f"Account update · VERITAS",
        html=render_layout(
            title="Account status update",
            paragraphs=[
                f"Hi {name},",
                f"Your VERITAS account status is now: {label}.",
            ],
        ),
    )
