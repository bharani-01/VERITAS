#!/usr/bin/env python3
"""
Lab-only HTTP traffic simulator for VERITAS Security dashboard.

Sends request patterns that match VERITAS heuristic classifiers so
/admin/security and the Groq AI agent have telemetry to analyze.

AUTHORIZED USE ONLY — point --base-url at your own VERITAS instance.
Do not use against systems you do not own.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class Probe:
    label: str
    method: str
    path: str
    query: str | None = None
    headers: dict[str, str] | None = None
    body: bytes | None = None


ATTACK_LABELS = (
    "clean",
    "sqli",
    "xss",
    "cmd_inject",
    "path_traversal",
    "ssrf",
    "ssti",
    "open_redirect",
    "header_abuse",
    "csrf",
    "scanner",
    "auth",
    "weak_headers",
)


def _probes() -> list[Probe]:
    """Patterns aligned with backend/app/services/http_classifier.py."""
    return [
        # --- clean ---
        Probe("clean", "GET", "/health"),
        Probe("clean", "GET", "/auth/me"),
        Probe("clean", "GET", "/workspace/projects"),
        Probe("clean", "GET", "/admin/users"),
        # --- SQLi ---
        Probe("sqli", "GET", "/workspace/projects", "id=1' OR '1'='1"),
        Probe("sqli", "GET", "/admin/users", "q=1 UNION SELECT username,password FROM users-- "),
        Probe("sqli", "GET", "/workspace/scans", "filter=1; DROP TABLE findings-- "),
        Probe("sqli", "GET", "/auth/login", "email=admin' OR 1=1-- &redirect=/admin"),
        Probe("sqli", "GET", "/workspace/projects", "sort=id&wait=SLEEP(5)"),
        # --- XSS ---
        Probe("xss", "GET", "/workspace/projects", "name=<script>alert(1)</script>"),
        Probe("xss", "GET", "/admin/audit", "q=<img src=x onerror=alert(1)>"),
        Probe("xss", "GET", "/workspace/findings", "note=javascript:alert(document.cookie)"),
        Probe("xss", "GET", "/auth/callback", "state=%3Cscript%3Ealert(1)%3C/script%3E"),
        # --- command injection ---
        Probe("cmd_inject", "GET", "/workspace/projects", "name=test; id"),
        Probe("cmd_inject", "GET", "/admin/users", "q=x|whoami"),
        Probe("cmd_inject", "GET", "/workspace/scans", "path=$(cat /etc/passwd)"),
        Probe("cmd_inject", "GET", "/health", "cmd=`uname -a`"),
        # --- path traversal / LFI ---
        Probe("path_traversal", "GET", "/workspace/projects", "file=../../etc/passwd"),
        Probe("path_traversal", "GET", "/admin/audit", "path=..%2f..%2fetc%2fshadow"),
        Probe("path_traversal", "GET", "/workspace/findings", "template=....//....//boot.ini"),
        Probe("path_traversal", "GET", "/auth/me", "include=/proc/self/environ"),
        # --- SSRF ---
        Probe("ssrf", "GET", "/workspace/projects", "url=http://127.0.0.1:8000/admin/users"),
        Probe("ssrf", "GET", "/workspace/scans", "proxy=http://169.254.169.254/latest/meta-data/"),
        Probe("ssrf", "GET", "/admin/users", "feed=file:///etc/passwd"),
        Probe("ssrf", "GET", "/webhooks/github", "target=http://localhost/admin"),
        # --- SSTI ---
        Probe("ssti", "GET", "/workspace/projects", "name={{config.items()}}"),
        Probe("ssti", "GET", "/admin/audit", "q=${7*7}"),
        Probe("ssti", "GET", "/workspace/findings", "note={{request.application.__globals__}}"),
        # --- open redirect ---
        Probe("open_redirect", "GET", "/auth/login", "next=https://evil.example/phish"),
        Probe("open_redirect", "GET", "/auth/callback", "redirect=https://attacker.test/"),
        Probe("open_redirect", "GET", "/workspace/projects", "returnUrl=//evil.example/"),
        # --- header abuse (request headers) ---
        Probe(
            "header_abuse",
            "GET",
            "/admin/users",
            headers={
                "X-Forwarded-Host": "evil.example",
                "X-Original-Url": "/admin/users",
            },
        ),
        Probe(
            "header_abuse",
            "GET",
            "/workspace/projects",
            headers={"X-Forwarded-For": "127.0.0.1"},
        ),
        Probe(
            "header_abuse",
            "GET",
            "/auth/me",
            headers={"X-Rewrite-Url": "/admin/security-overview"},
        ),
        Probe(
            "header_abuse",
            "GET",
            "/workspace/projects",
            "q=test%0d%0aSet-Cookie:%20session=hijacked",
        ),
        # --- CSRF ---
        Probe(
            "csrf",
            "POST",
            "/workspace/projects",
            headers={"Cookie": "veritas_session=lab-fake-session-token"},
            body=b"{}",
        ),
        Probe(
            "csrf",
            "DELETE",
            "/workspace/projects/lab-target",
            headers={"Cookie": "veritas_session=lab-fake-session-token"},
        ),
        Probe(
            "csrf",
            "PATCH",
            "/admin/users/lab-target",
            headers={
                "Cookie": "veritas_session=lab-fake-session-token",
                "Origin": "https://evil.example",
            },
            body=b'{"role":"admin"}',
        ),
        # --- scanner UA ---
        Probe(
            "scanner",
            "GET",
            "/admin/users",
            headers={"User-Agent": "sqlmap/1.7 (https://sqlmap.org)"},
        ),
        Probe(
            "scanner",
            "GET",
            "/workspace/projects",
            headers={"User-Agent": "Nikto/2.1.6"},
        ),
        Probe(
            "scanner",
            "GET",
            "/health",
            headers={"User-Agent": "nuclei - lab fingerprint"},
        ),
        # --- auth anomaly ---
        Probe(
            "auth",
            "POST",
            "/auth/login",
            body=b'{"email":"attacker@example.com","password":"wrong-password"}',
            headers={"Content-Type": "application/json"},
        ),
        Probe(
            "auth",
            "POST",
            "/auth/login",
            body=b'{"email":"admin@veritas.local","password":"hunter2"}',
            headers={"Content-Type": "application/json"},
        ),
        Probe(
            "auth",
            "GET",
            "/admin/security-overview",
            headers={"Cookie": "veritas_session=invalid-token"},
        ),
        # --- weak response headers probe (hits tracked route; server may lack HSTS/CSP/…) ---
        Probe("weak_headers", "GET", "/health"),
        Probe("weak_headers", "GET", "/auth/me"),
    ]


def _build_url(base: str, path: str, query: str | None) -> str:
    base = base.rstrip("/")
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"base-url must be http(s)://host — got {base!r}")
    if not path.startswith("/"):
        path = "/" + path
    # Rebuild so urllib cannot be steered to file:// via query/path tricks.
    safe = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, path, "", query or "", "")
    )
    return safe


def _send(base: str, probe: Probe, timeout: float) -> tuple[int, str]:
    url = _build_url(base, probe.path, probe.query)
    headers = {
        "User-Agent": "VERITAS-LabTrafficSimulator/1.0",
        "Accept": "application/json, text/plain, */*",
    }
    if probe.headers:
        headers.update(probe.headers)
    if probe.body is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url,
        data=probe.body,
        headers=headers,
        method=probe.method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), "ok"
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.reason or "http-error"
    except urllib.error.URLError as exc:
        return 0, str(exc.reason if hasattr(exc, "reason") else exc)
    except Exception as exc:  # noqa: BLE001 — lab tool: surface any failure
        return 0, str(exc)


def _pick(probes: list[Probe], labels: set[str] | None, rng: random.Random) -> Probe:
    if labels:
        filtered = [p for p in probes if p.label in labels]
        if not filtered:
            raise SystemExit(f"No probes for labels={sorted(labels)}")
        return rng.choice(filtered)
    return rng.choice(probes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Simulate attack-like HTTP traffic against your VERITAS instance (lab only).",
    )
    parser.add_argument(
        "--base-url",
        default="https://veritas.trackifyapp.co.in",
        help="VERITAS origin you own",
    )
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--delay", type=float, default=0.15)
    parser.add_argument(
        "--mix",
        default="all",
        help="Comma list of families or 'all' "
        f"(choices: {','.join(ATTACK_LABELS)})",
    )
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="Required confirmation that --base-url is your VERITAS lab instance",
    )
    args = parser.parse_args(argv)

    if not args.i_own_this_target:
        print(
            "Refusing to run: pass --i-own-this-target to confirm "
            f"{args.base_url!r} is your own VERITAS instance.",
            file=sys.stderr,
        )
        return 2

    labels: set[str] | None
    if args.mix.strip().lower() == "all":
        labels = None
    else:
        labels = {x.strip() for x in args.mix.split(",") if x.strip()}
        bad = labels - set(ATTACK_LABELS)
        if bad:
            raise SystemExit(f"Unknown mix labels: {sorted(bad)}")

    rng = random.Random(args.seed)
    probes = _probes()
    tallies: dict[str, int] = {}
    status_tallies: dict[str, int] = {}

    print(f"Target: {args.base_url}")
    print(f"Sending {args.count} probes (mix={args.mix}, delay={args.delay}s)")
    print("-" * 60)

    for i in range(1, args.count + 1):
        probe = _pick(probes, labels, rng)
        status, detail = _send(args.base_url, probe, args.timeout)
        tallies[probe.label] = tallies.get(probe.label, 0) + 1
        key = str(status) if status else "err"
        status_tallies[key] = status_tallies.get(key, 0) + 1
        q = f"?{probe.query}" if probe.query else ""
        print(
            f"[{i:03d}/{args.count}] {probe.label:14} "
            f"{probe.method:6} {probe.path}{q[:40]} → {status or 'ERR'} {detail}"
        )
        if args.delay > 0 and i < args.count:
            time.sleep(args.delay)

    print("-" * 60)
    print("By classification intent:", dict(sorted(tallies.items())))
    print("By HTTP status:", dict(sorted(status_tallies.items(), key=lambda x: x[0])))
    print()
    print("Next: open /admin/security → refresh → Run AI agent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
