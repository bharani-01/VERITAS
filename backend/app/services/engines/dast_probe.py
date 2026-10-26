from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.services.engines.normalize import NormalizedFinding

logger = logging.getLogger(__name__)

VERSION_DISCLOSURE_RE = re.compile(r"[A-Za-z0-9_\-]+/\d+\.\d+(?:\.\d+)?|PHP/\d|Express", re.IGNORECASE)
ENV_KEY_VALUE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}=\S+", re.MULTILINE)


class DastTargetBlockedError(ValueError):
    """Raised when a DAST target URL points to a restricted loopback/private/metadata IP."""


def _allow_local_dast() -> bool:
    return (
        os.getenv("VERITAS_ALLOW_LOCAL_DAST", "").strip() in ("1", "true", "yes")
        or os.getenv("APP_ENV", "").strip().lower() == "test"
    )


def validate_dast_target_url(url: str, *, enforce_public_ip: bool | None = None) -> str:
    """
    Validates that `url` uses `http://` or `https://` and does not resolve to
    loopback, link-local, RFC1918 private, or cloud metadata IP addresses unless
    explicitly permitted via `VERITAS_ALLOW_LOCAL_DAST=1`.
    """
    cleaned = (url or "").strip()
    parsed = urlparse(cleaned)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise DastTargetBlockedError("DAST target must be a valid http:// or https:// URL.")

    hostname = parsed.hostname.strip().lower()
    must_enforce = (not _allow_local_dast()) if enforce_public_ip is None else enforce_public_ip

    if must_enforce:
        if hostname in ("localhost", "localhost.localdomain", "metadata.google.internal"):
            raise DastTargetBlockedError(f"DAST target host '{hostname}' is blocked by SSRF policy.")

        try:
            ip_obj = ipaddress.ip_address(hostname)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                raise DastTargetBlockedError(
                    f"DAST target IP '{ip_obj}' is restricted (private/loopback/metadata range)."
                )
        except ValueError:
            try:
                addr_info = socket.getaddrinfo(
                    hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
                )
            except socket.gaierror as exc:
                raise DastTargetBlockedError(
                    f"Could not resolve DAST target host '{hostname}': {exc}"
                ) from exc

            for family, _, _, _, sockaddr in addr_info:
                if family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                ip_str = sockaddr[0]
                ip_obj = ipaddress.ip_address(ip_str)
                if (
                    ip_obj.is_private
                    or ip_obj.is_loopback
                    or ip_obj.is_link_local
                    or ip_obj.is_multicast
                    or ip_obj.is_reserved
                    or ip_obj.is_unspecified
                ):
                    raise DastTargetBlockedError(
                        f"DAST target '{hostname}' resolved to restricted IP '{ip_obj}'."
                    )

    return cleaned


def _inspect_tls_endpoint(hostname: str, port: int, timeout: float = 5.0) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_ver = ssock.version() or ""
                if tls_ver in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    findings.append(
                        NormalizedFinding(
                            engine="veritas_dast",
                            title=f"Deprecated TLS Protocol Negotiated ({tls_ver})",
                            severity="high",
                            rule_id="dast.tls.deprecated_version",
                            vuln_family="crypto",
                            cwe="CWE-326",
                            owasp_category="A02:2021-Cryptographic Failures",
                            message=f"Endpoint {hostname}:{port} negotiated legacy protocol {tls_ver}. Enforce TLS 1.2 or TLS 1.3.",
                            file_path=f"https://{hostname}:{port}",
                            raw={"tls_version": tls_ver, "confidence_level": "high"},
                        )
                    )
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter") if isinstance(cert, dict) else None
                if isinstance(not_after, str):
                    exp_ts = ssl.cert_time_to_seconds(not_after)
                    days_left = (exp_ts - datetime.now(timezone.utc).timestamp()) / 86400.0
                    if days_left < 14:
                        findings.append(
                            NormalizedFinding(
                                engine="veritas_dast",
                                title=f"TLS Certificate Expiring Soon ({int(days_left)} days remaining)",
                                severity="medium" if days_left > 0 else "critical",
                                rule_id="dast.tls.cert_expiring",
                                vuln_family="crypto",
                                cwe="CWE-295",
                                owasp_category="A02:2021-Cryptographic Failures",
                                message=f"TLS certificate for {hostname} expires on {not_after} ({int(days_left)} days remaining).",
                                file_path=f"https://{hostname}:{port}",
                                raw={"days_remaining": round(days_left, 1), "confidence_level": "high"},
                            )
                        )
    except Exception:
        return findings
    return findings


def _looks_like_html_fallback(text: str, content_type: str) -> bool:
    ct_lower = (content_type or "").lower()
    head = (text or "").lstrip()[:300].lower()
    return (
        "text/html" in ct_lower
        or head.startswith("<!doctype html")
        or head.startswith("<html")
        or '<div id="root"' in head
        or "<div id='root'" in head
    )


def run_dast_probe(
    target_url: str,
    *,
    security_level: str = "standard",
    transport: httpx.BaseTransport | None = None,
    enforce_public_ip: bool | None = None,
) -> tuple[list[NormalizedFinding], dict[str, Any]]:
    """
    Executes non-destructive live web vulnerability checks (TLS, HTTP security headers,
    cookie security flags, CORS origin reflection, and sensitive path disclosures).
    Returns `(findings, engine_meta)`.
    """
    meta: dict[str, Any] = {
        "engine": "veritas_dast",
        "available": True,
        "target_url": target_url,
        "findings": 0,
    }
    findings: list[NormalizedFinding] = []

    try:
        validated_url = validate_dast_target_url(target_url, enforce_public_ip=enforce_public_ip)
    except DastTargetBlockedError as exc:
        meta["skipped"] = str(exc)
        return [], meta

    parsed = urlparse(validated_url)
    is_https = parsed.scheme.lower() == "https"

    if is_https and parsed.hostname and transport is None and not _allow_local_dast():
        findings.extend(_inspect_tls_endpoint(parsed.hostname, parsed.port or 443))

    client_kwargs: dict[str, Any] = {
        "follow_redirects": True,
        "timeout": 10.0,
        "headers": {"User-Agent": "VERITAS-DAST-Scanner/2.1 (+https://veritas.trackifyapp.co.in)"},
    }
    if transport is not None:
        client_kwargs["transport"] = transport

    try:
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(validated_url)
            final_url = str(resp.url)
            final_scheme = urlparse(final_url).scheme.lower()
            headers = resp.headers

            # 1. Cleartext HTTP transport check
            if final_scheme == "http":
                findings.append(
                    NormalizedFinding(
                        engine="veritas_dast",
                        title="Cleartext HTTP Transport Without HTTPS Enforcement",
                        severity="high",
                        rule_id="dast.http.cleartext",
                        vuln_family="crypto",
                        cwe="CWE-319",
                        owasp_category="A02:2021-Cryptographic Failures",
                        message=(
                            f"Target {validated_url} serves traffic over unencrypted HTTP ({final_url}) "
                            "without redirecting to HTTPS, exposing credentials and session tokens in transit."
                        ),
                        file_path=final_url,
                        raw={"url": final_url, "confidence_level": "high"},
                    )
                )

            # 2. Content-Security-Policy check
            csp = headers.get("content-security-policy")
            if not csp:
                findings.append(
                    NormalizedFinding(
                        engine="veritas_dast",
                        title="Missing Content-Security-Policy (CSP) Header",
                        severity="medium",
                        rule_id="dast.header.csp",
                        vuln_family="misconfig",
                        cwe="CWE-693",
                        owasp_category="A05:2021-Security Misconfiguration",
                        message=(
                            f"Response from {final_url} does not include a Content-Security-Policy header, "
                            "increasing susceptibility to Cross-Site Scripting (XSS) and data injection."
                        ),
                        file_path=final_url,
                        raw={"missing_header": "Content-Security-Policy", "confidence_level": "high"},
                    )
                )
            elif "'unsafe-inline'" in csp.lower() or "'unsafe-eval'" in csp.lower():
                findings.append(
                    NormalizedFinding(
                        engine="veritas_dast",
                        title="Weak Content-Security-Policy Allows unsafe-inline / unsafe-eval",
                        severity="medium",
                        rule_id="dast.header.csp.weak",
                        vuln_family="xss",
                        cwe="CWE-693",
                        owasp_category="A05:2021-Security Misconfiguration",
                        message=f"CSP header on {final_url} contains permissive directives: {csp[:180]}",
                        file_path=final_url,
                        snippet=f"Content-Security-Policy: {csp[:240]}",
                        raw={"csp": csp[:240], "confidence_level": "high"},
                    )
                )

            # 3. Strict-Transport-Security (HSTS) check
            if final_scheme == "https" and not headers.get("strict-transport-security"):
                findings.append(
                    NormalizedFinding(
                        engine="veritas_dast",
                        title="Missing Strict-Transport-Security (HSTS) Header",
                        severity="medium",
                        rule_id="dast.header.hsts",
                        vuln_family="misconfig",
                        cwe="CWE-319",
                        owasp_category="A05:2021-Security Misconfiguration",
                        message=(
                            f"HTTPS endpoint {final_url} omits Strict-Transport-Security, allowing SSL-stripping "
                            "downgrade attacks on first-time connections."
                        ),
                        file_path=final_url,
                        raw={"missing_header": "Strict-Transport-Security", "confidence_level": "high"},
                    )
                )

            # 4. Anti-Clickjacking check (X-Frame-Options / frame-ancestors)
            xfo = headers.get("x-frame-options")
            has_frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
            if not xfo and not has_frame_ancestors:
                findings.append(
                    NormalizedFinding(
                        engine="veritas_dast",
                        title="Missing Anti-Clickjacking Header (X-Frame-Options / frame-ancestors)",
                        severity="low",
                        rule_id="dast.header.clickjacking",
                        vuln_family="misconfig",
                        cwe="CWE-1021",
                        owasp_category="A05:2021-Security Misconfiguration",
                        message=f"{final_url} can be embedded in arbitrary third-party iframes.",
                        file_path=final_url,
                        raw={"missing_header": "X-Frame-Options", "confidence_level": "high"},
                    )
                )

            # 5. X-Content-Type-Options check
            xcto = (headers.get("x-content-type-options") or "").strip().lower()
            if xcto != "nosniff":
                findings.append(
                    NormalizedFinding(
                        engine="veritas_dast",
                        title="Missing X-Content-Type-Options: nosniff Header",
                        severity="low",
                        rule_id="dast.header.nosniff",
                        vuln_family="misconfig",
                        cwe="CWE-693",
                        owasp_category="A05:2021-Security Misconfiguration",
                        message=f"Response from {final_url} omits 'X-Content-Type-Options: nosniff'.",
                        file_path=final_url,
                        raw={"missing_header": "X-Content-Type-Options", "confidence_level": "high"},
                    )
                )

            # 6. Server / X-Powered-By Version Disclosure check
            server_hdr = headers.get("server") or ""
            powered_by = headers.get("x-powered-by") or ""
            combined_banner = f"{server_hdr} {powered_by}".strip()
            if VERSION_DISCLOSURE_RE.search(combined_banner):
                findings.append(
                    NormalizedFinding(
                        engine="veritas_dast",
                        title=f"Server Technology Version Disclosure ({combined_banner})",
                        severity="low",
                        rule_id="dast.header.version_disclosure",
                        vuln_family="misconfig",
                        cwe="CWE-200",
                        owasp_category="A05:2021-Security Misconfiguration",
                        message=f"Response headers disclose backend stack version: '{combined_banner}'.",
                        file_path=final_url,
                        snippet=f"Server: {server_hdr}\nX-Powered-By: {powered_by}".strip(),
                        raw={"banner": combined_banner, "confidence_level": "high"},
                    )
                )

            # 7. Set-Cookie Security Flags check
            set_cookies = headers.get_list("set-cookie")
            for cookie_raw in set_cookies:
                cookie_name = cookie_raw.split("=", 1)[0].strip() or "session"
                c_low = cookie_raw.lower()
                missing_flags: list[str] = []
                if "httponly" not in c_low:
                    missing_flags.append("HttpOnly")
                if final_scheme == "https" and "secure" not in c_low:
                    missing_flags.append("Secure")
                if "samesite" not in c_low:
                    missing_flags.append("SameSite")

                if missing_flags:
                    cwe = (
                        "CWE-1004"
                        if "HttpOnly" in missing_flags
                        else ("CWE-614" if "Secure" in missing_flags else "CWE-352")
                    )
                    findings.append(
                        NormalizedFinding(
                            engine="veritas_dast",
                            title=f"Cookie '{cookie_name}' Missing Security Attributes ({', '.join(missing_flags)})",
                            severity="medium"
                            if ("HttpOnly" in missing_flags or "Secure" in missing_flags)
                            else "low",
                            rule_id="dast.cookie.insecure",
                            vuln_family="auth",
                            cwe=cwe,
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            message=(
                                f"Cookie '{cookie_name}' set by {final_url} is missing {', '.join(missing_flags)} "
                                "attributes, exposing it to XSS theft or cross-site transmission."
                            ),
                            file_path=final_url,
                            snippet=f"Set-Cookie: {cookie_raw[:200]}",
                            raw={"cookie": cookie_name, "missing_flags": missing_flags, "confidence_level": "high"},
                        )
                    )

            # 8. CORS Origin Reflection & Credential Theft Probe
            evil_origin = "https://evil-origin.veritas.invalid"
            cors_resp = client.get(validated_url, headers={"Origin": evil_origin})
            acao = (cors_resp.headers.get("access-control-allow-origin") or "").strip()
            acac = (cors_resp.headers.get("access-control-allow-credentials") or "").strip().lower()
            if (acao == evil_origin or acao == "*") and acac == "true":
                findings.append(
                    NormalizedFinding(
                        engine="veritas_dast",
                        title="Permissive CORS Origin Reflection With Credentials Enabled",
                        severity="critical",
                        rule_id="dast.cors.origin_reflection",
                        vuln_family="authz",
                        cwe="CWE-942",
                        owasp_category="A01:2021-Broken Access Control",
                        message=(
                            f"Target {final_url} reflected arbitrary Origin '{acao}' alongside "
                            "'Access-Control-Allow-Credentials: true', allowing cross-origin account takeover."
                        ),
                        file_path=final_url,
                        snippet=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        raw={"acao": acao, "acac": acac, "confidence_level": "high"},
                    )
                )

            # 9. Sensitive File & Unauthenticated API Schema Exposure Probes
            base_root = f"{parsed.scheme}://{parsed.netloc}/"
            probes = [
                (
                    ".env",
                    "dast.exposure.dotenv",
                    "Exposed Environment Configuration File (/.env)",
                    "critical",
                    "secret",
                    "CWE-538",
                    lambda body, ct: (not _looks_like_html_fallback(body, ct))
                    and bool(ENV_KEY_VALUE_RE.search(body)),
                ),
                (
                    ".git/HEAD",
                    "dast.exposure.git",
                    "Exposed Git Repository Metadata (/.git/HEAD)",
                    "high",
                    "misconfig",
                    "CWE-538",
                    lambda body, ct: (not _looks_like_html_fallback(body, ct)) and ("ref: refs/" in body),
                ),
                (
                    "openapi.json",
                    "dast.exposure.openapi",
                    "Publicly Exposed OpenAPI Specification (/openapi.json)",
                    "low",
                    "misconfig",
                    "CWE-200",
                    lambda body, ct: (not _looks_like_html_fallback(body, ct))
                    and ('"openapi"' in body or '"swagger"' in body),
                ),
                (
                    "swagger.json",
                    "dast.exposure.swagger",
                    "Publicly Exposed Swagger API Schema (/swagger.json)",
                    "low",
                    "misconfig",
                    "CWE-200",
                    lambda body, ct: (not _looks_like_html_fallback(body, ct))
                    and ('"swagger"' in body or '"openapi"' in body),
                ),
            ]

            for rel_path, rule_id, title, sev, fam, cwe, validator in probes:
                probe_url = urljoin(base_root, rel_path)
                try:
                    p_resp = client.get(probe_url)
                    if p_resp.status_code == 200:
                        body_text = p_resp.text[:4000]
                        ct = p_resp.headers.get("content-type") or ""
                        if validator(body_text, ct):
                            findings.append(
                                NormalizedFinding(
                                    engine="veritas_dast",
                                    title=title,
                                    severity=sev,
                                    rule_id=rule_id,
                                    vuln_family=fam,
                                    cwe=cwe,
                                    owasp_category="A05:2021-Security Misconfiguration",
                                    message=f"Sensitive endpoint {probe_url} returned HTTP 200 with verified signature.",
                                    file_path=probe_url,
                                    snippet=body_text[:240],
                                    raw={"probe_url": probe_url, "confidence_level": "high"},
                                )
                            )
                except Exception:
                    continue

    except Exception as exc:
        logger.warning("DAST probe encountered network error for %s: %s", validated_url, str(exc)[:200])
        meta["error"] = str(exc)[:200]

    meta["findings"] = len(findings)
    return findings, meta
