from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from app.services.engines.normalize import NormalizedFinding, classify_family, normalize_severity


def _which(*names: str) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def _semgrep_cmd() -> list[str] | None:
    """Prefer the same interpreter that runs VERITAS (venv), then PATH binary."""
    try:
        probe = subprocess.run(
            [sys.executable, "-m", "semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if probe.returncode == 0:
            return [sys.executable, "-m", "semgrep"]
    except Exception:
        pass
    binary = _which("semgrep", "semgrep.exe")
    if binary:
        return [binary]
    return None


def run_gitleaks(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    meta: dict = {"engine": "gitleaks", "available": False}
    binary = _which("gitleaks")
    if not binary:
        meta["skipped"] = "gitleaks binary not found"
        return [], meta
    meta["available"] = True
    report = workdir / ".veritas-gitleaks.json"
    # Deep mode: prefer git history when present (catches committed secrets), else filesystem walk.
    use_git = (workdir / ".git").exists()
    cmd = [binary, "detect", "--source", str(workdir), "-f", "json", "-r", str(report), "--exit-code", "0"]
    if not use_git:
        cmd.insert(2, "--no-git")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=420,
            check=False,
        )
        meta["returncode"] = proc.returncode
        meta["mode"] = "git-history" if use_git else "filesystem"
        findings: list[NormalizedFinding] = []
        if report.is_file() and report.stat().st_size > 2:
            data = json.loads(report.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    title = item.get("RuleID") or item.get("Description") or "Secret detected"
                    secret = item.get("Secret") or ""
                    findings.append(
                        NormalizedFinding(
                            engine="gitleaks",
                            title=str(title)[:512],
                            severity="high",
                            rule_id=item.get("RuleID"),
                            vuln_family="secret",
                            message=item.get("Description"),
                            file_path=item.get("File"),
                            line_start=item.get("StartLine"),
                            line_end=item.get("EndLine"),
                            snippet=(secret[:80] + ("…" if len(secret) > 80 else "")),
                            raw=item if isinstance(item, dict) else {},
                        )
                    )
        meta["findings"] = len(findings)
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta
    finally:
        if report.exists():
            report.unlink(missing_ok=True)


def run_osv(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    meta: dict = {"engine": "osv", "available": False}
    binary = _which("osv-scanner", "osv-scanner.exe")
    if not binary:
        meta["skipped"] = "osv-scanner binary not found"
        return [], meta
    meta["available"] = True
    try:
        proc = subprocess.run(
            [binary, "--format", "json", "--recursive", str(workdir)],
            capture_output=True,
            text=True,
            timeout=420,
            check=False,
        )
        # Older osv-scanner builds may not support --recursive; retry without it.
        if proc.returncode != 0 and "recursive" in ((proc.stderr or "") + (proc.stdout or "")).lower():
            proc = subprocess.run(
                [binary, "--format", "json", str(workdir)],
                capture_output=True,
                text=True,
                timeout=420,
                check=False,
            )
        meta["returncode"] = proc.returncode
        meta["mode"] = "deep"
        findings: list[NormalizedFinding] = []
        raw = (proc.stdout or "").strip()
        if not raw:
            meta["findings"] = 0
            return [], meta
        data = json.loads(raw)
        results = data.get("results") if isinstance(data, dict) else []
        for result in results or []:
            for pkg in result.get("packages") or []:
                package = (pkg.get("package") or {}).get("name") or "dependency"
                for vuln in pkg.get("vulnerabilities") or []:
                    sev = "medium"
                    for s in vuln.get("severity") or []:
                        if isinstance(s, dict) and s.get("type") == "CVSS_V3":
                            try:
                                score = float(s.get("score") or 0)
                            except (TypeError, ValueError):
                                score = 0
                            if score >= 9:
                                sev = "critical"
                            elif score >= 7:
                                sev = "high"
                            elif score >= 4:
                                sev = "medium"
                            else:
                                sev = "low"
                    vid = vuln.get("id") or "osv"
                    findings.append(
                        NormalizedFinding(
                            engine="osv",
                            title=f"{vid} in {package}",
                            severity=normalize_severity(sev),
                            rule_id=vid,
                            vuln_family="sca",
                            message=(vuln.get("summary") or "")[:2000],
                            file_path=(result.get("source") or {}).get("path"),
                            raw=vuln if isinstance(vuln, dict) else {},
                        )
                    )
        meta["findings"] = len(findings)
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta


def semgrep_configs(security_level: str) -> list[str]:
    """Deep Semgrep packs — broader SAST coverage than a thin CI pack."""
    level = (security_level or "standard").lower()
    if level == "basic":
        return ["p/ci", "p/owasp-top-ten"]
    if level == "strict":
        return [
            "p/default",
            "p/ci",
            "p/owasp-top-ten",
            "p/security-audit",
            "p/secrets",
            "p/r2c-security-audit",
        ]
    # standard = deep scan (default for VERITAS)
    return ["p/default", "p/ci", "p/owasp-top-ten", "p/security-audit", "p/secrets"]


def run_semgrep(
    workdir: Path,
    security_level: str = "standard",
    *,
    include_paths: list[str] | None = None,
    excludes: list[str] | None = None,
) -> tuple[list[NormalizedFinding], dict]:
    meta: dict = {"engine": "semgrep", "available": False, "configs": semgrep_configs(security_level)}
    cmd_prefix = _semgrep_cmd()
    if not cmd_prefix:
        meta["skipped"] = "semgrep not found (pip install semgrep)"
        return [], meta

    if include_paths is not None and len(include_paths) == 0:
        meta["available"] = True
        meta["mode"] = "changed"
        meta["skipped"] = "no changed files"
        meta["findings"] = 0
        return [], meta

    meta["available"] = True
    meta["invocation"] = " ".join(cmd_prefix)
    meta["mode"] = "changed" if include_paths else "deep"
    cmd = [*cmd_prefix, "scan", "--json", "--quiet", "--disable-version-check"]
    for cfg in meta["configs"]:
        cmd.extend(["--config", cfg])
    if include_paths:
        for rel in include_paths[:400]:
            cmd.extend(["--include", rel.replace("\\", "/")])
    for pattern in excludes or []:
        cleaned = (pattern or "").strip().replace("\\", "/")
        if cleaned:
            cmd.extend(["--exclude", cleaned])
    cmd.append(str(workdir))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, check=False)
        meta["returncode"] = proc.returncode
        raw = (proc.stdout or "").strip()
        if not raw:
            meta["stderr"] = (proc.stderr or "")[:400]
            meta["findings"] = 0
            return [], meta
        data = json.loads(raw)
        findings: list[NormalizedFinding] = []
        for item in data.get("results") or []:
            extra = item.get("extra") or {}
            meta_extra = extra.get("metadata") or {}
            severity = normalize_severity(extra.get("severity") or meta_extra.get("severity"))
            rule_id = item.get("check_id")
            title = (extra.get("message") or rule_id or "Semgrep finding")[:512]
            cwes = meta_extra.get("cwe") or []
            cwe = cwes[0] if isinstance(cwes, list) and cwes else (cwes if isinstance(cwes, str) else None)
            owasp = meta_extra.get("owasp")
            if isinstance(owasp, list):
                owasp = owasp[0] if owasp else None
            start = item.get("start") or {}
            end = item.get("end") or {}
            findings.append(
                NormalizedFinding(
                    engine="semgrep",
                    title=title,
                    severity=severity,
                    rule_id=rule_id,
                    vuln_family=classify_family(rule_id, title, extra.get("message")),
                    cwe=str(cwe)[:32] if cwe else None,
                    owasp_category=str(owasp)[:64] if owasp else None,
                    message=extra.get("message"),
                    file_path=item.get("path"),
                    line_start=start.get("line"),
                    line_end=end.get("line"),
                    snippet=(extra.get("lines") or "")[:2000],
                    raw=item if isinstance(item, dict) else {},
                )
            )
        meta["findings"] = len(findings)
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta
