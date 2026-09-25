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
        # Maximum registry coverage — language packs + security audits + IaC.
        return [
            "p/default",
            "p/ci",
            "p/owasp-top-ten",
            "p/security-audit",
            "p/secrets",
            "p/r2c-security-audit",
            "p/python",
            "p/javascript",
            "p/typescript",
            "p/react",
            "p/java",
            "p/golang",
            "p/php",
            "p/ruby",
            "p/csharp",
            "p/kotlin",
            "p/rust",
            "p/docker",
            "p/kubernetes",
            "p/terraform",
            "p/nginx",
        ]
    # standard = deep scan (default for VERITAS)
    return [
        "p/default",
        "p/ci",
        "p/owasp-top-ten",
        "p/security-audit",
        "p/secrets",
        "p/docker",
        "p/kubernetes",
    ]


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


def run_trufflehog(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    """Deep secrets (verified + unverified). Soft-skip if binary missing."""
    meta: dict = {"engine": "trufflehog", "available": False}
    binary = _which("trufflehog")
    if not binary:
        meta["skipped"] = "trufflehog binary not found"
        return [], meta
    meta["available"] = True
    try:
        use_git = (workdir / ".git").exists()
        if use_git:
            cmd = [binary, "git", "file://" + str(workdir.resolve()), "--json", "--no-update"]
        else:
            cmd = [binary, "filesystem", str(workdir), "--json", "--no-update"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, check=False)
        meta["returncode"] = proc.returncode
        meta["mode"] = "git" if use_git else "filesystem"
        findings: list[NormalizedFinding] = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            detector = item.get("DetectorName") or "secret"
            raw_secret = item.get("Raw") or item.get("Redacted") or ""
            verified = bool(item.get("Verified"))
            sev = "critical" if verified else "high"
            src_meta = (item.get("SourceMetadata") or {}).get("Data") or {}
            src = src_meta.get("Filesystem") or src_meta.get("Git") or {}
            file_path = src.get("file") or src.get("file_name")
            line_no = src.get("line")
            title = f"TruffleHog: {detector}" + (" (verified)" if verified else "")
            snippet = str(raw_secret)
            if len(snippet) > 80:
                snippet = snippet[:80] + "…"
            findings.append(
                NormalizedFinding(
                    engine="trufflehog",
                    title=title[:512],
                    severity=normalize_severity(sev),
                    rule_id=str(detector)[:120],
                    vuln_family="secret",
                    message=f"Possible secret ({detector}). Verified={verified}.",
                    file_path=str(file_path) if file_path else None,
                    line_start=int(line_no) if isinstance(line_no, int) else None,
                    snippet=snippet or None,
                    raw=item,
                )
            )
        meta["findings"] = len(findings)
        if proc.returncode not in (0, 1) and not findings:
            meta["error"] = ((proc.stderr or proc.stdout) or f"exit {proc.returncode}")[:300]
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta


def run_trivy(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    """Filesystem SCA + misconfig + secrets. Soft-skip if binary missing."""
    meta: dict = {"engine": "trivy", "available": False}
    binary = _which("trivy")
    if not binary:
        meta["skipped"] = "trivy binary not found"
        return [], meta
    meta["available"] = True
    try:
        proc = subprocess.run(
            [
                binary,
                "fs",
                "--format",
                "json",
                "--scanners",
                "vuln,secret,misconfig",
                "--quiet",
                str(workdir),
            ],
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        meta["returncode"] = proc.returncode
        raw = (proc.stdout or "").strip()
        data = json.loads(raw) if raw else {}
        findings: list[NormalizedFinding] = []
        for result in data.get("Results") or []:
            if not isinstance(result, dict):
                continue
            target = result.get("Target") or ""
            for vuln in result.get("Vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                sev = normalize_severity(vuln.get("Severity"))
                vid = vuln.get("VulnerabilityID") or vuln.get("PkgID") or "CVE"
                pkg = vuln.get("PkgName") or ""
                title = f"{vid} in {pkg}".strip() if pkg else str(vid)
                msg = vuln.get("Description") or vuln.get("Title") or ""
                fixed = vuln.get("FixedVersion")
                if fixed:
                    msg = f"{msg} Fixed in {fixed}.".strip()
                findings.append(
                    NormalizedFinding(
                        engine="trivy",
                        title=title[:512],
                        severity=sev,
                        rule_id=str(vid)[:120],
                        vuln_family="sca",
                        cwe=(vuln.get("CweIDs") or [None])[0],
                        message=msg[:2000],
                        file_path=target or None,
                        raw=vuln,
                    )
                )
            for secret in result.get("Secrets") or []:
                if not isinstance(secret, dict):
                    continue
                findings.append(
                    NormalizedFinding(
                        engine="trivy",
                        title=f"Secret: {secret.get('Title') or secret.get('RuleID') or 'detected'}"[:512],
                        severity=normalize_severity(secret.get("Severity") or "HIGH"),
                        rule_id=str(secret.get("RuleID") or "secret")[:120],
                        vuln_family="secret",
                        message=(secret.get("Match") or secret.get("Title") or "")[:2000],
                        file_path=target or secret.get("FilePath"),
                        line_start=secret.get("StartLine"),
                        line_end=secret.get("EndLine"),
                        raw=secret,
                    )
                )
            for mis in result.get("Misconfigurations") or []:
                if not isinstance(mis, dict):
                    continue
                findings.append(
                    NormalizedFinding(
                        engine="trivy",
                        title=f"Misconfig: {mis.get('Title') or mis.get('ID') or 'issue'}"[:512],
                        severity=normalize_severity(mis.get("Severity") or "MEDIUM"),
                        rule_id=str(mis.get("ID") or mis.get("AVDID") or "misconfig")[:120],
                        vuln_family=classify_family(mis.get("ID"), mis.get("Title") or "", mis.get("Description")),
                        message=(mis.get("Description") or mis.get("Message") or "")[:2000],
                        file_path=target or None,
                        raw=mis,
                    )
                )
        meta["findings"] = len(findings)
        if proc.returncode not in (0, 1) and not findings:
            meta["error"] = ((proc.stderr or proc.stdout) or f"exit {proc.returncode}")[:300]
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta


def _bandit_cmd() -> list[str] | None:
    try:
        probe = subprocess.run(
            [sys.executable, "-m", "bandit", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if probe.returncode == 0:
            return [sys.executable, "-m", "bandit"]
    except Exception:
        pass
    binary = _which("bandit", "bandit.exe")
    if binary:
        return [binary]
    return None


def run_bandit(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    """Python-focused SAST. Soft-skip if not installed."""
    meta: dict = {"engine": "bandit", "available": False}
    cmd = _bandit_cmd()
    if not cmd:
        meta["skipped"] = "bandit not found"
        return [], meta
    meta["available"] = True
    try:
        proc = subprocess.run(
            [*cmd, "-r", str(workdir), "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        meta["returncode"] = proc.returncode
        raw = (proc.stdout or "").strip()
        data = json.loads(raw) if raw else {}
        findings: list[NormalizedFinding] = []
        for item in data.get("results") or []:
            if not isinstance(item, dict):
                continue
            test_id = item.get("test_id") or item.get("test_name") or "Bxxx"
            title = item.get("test_name") or test_id
            line_range = item.get("line_range") or []
            line_end = line_range[-1] if line_range else item.get("line_number")
            cwe_id = None
            cwe = item.get("issue_cwe")
            if isinstance(cwe, dict) and cwe.get("id") is not None:
                cwe_id = str(cwe.get("id"))[:32]
            findings.append(
                NormalizedFinding(
                    engine="bandit",
                    title=str(title)[:512],
                    severity=normalize_severity(item.get("issue_severity")),
                    rule_id=str(test_id)[:120],
                    vuln_family=classify_family(str(test_id), str(title), item.get("issue_text")),
                    cwe=cwe_id,
                    message=(item.get("issue_text") or "")[:2000],
                    file_path=item.get("filename"),
                    line_start=item.get("line_number"),
                    line_end=line_end,
                    snippet=(item.get("code") or "")[:2000],
                    raw=item,
                )
            )
        meta["findings"] = len(findings)
        # Bandit exits 1 when findings exist
        if proc.returncode not in (0, 1) and not findings:
            meta["error"] = ((proc.stderr or proc.stdout) or f"exit {proc.returncode}")[:300]
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta

def _py_module_cmd(module: str, *probe_args: str) -> list[str] | None:
    args = list(probe_args) if probe_args else ["--version"]
    try:
        probe = subprocess.run(
            [sys.executable, "-m", module, *args],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        # Many modules return 0 on --version; some print help and exit 0/2.
        if probe.returncode in (0, 2) or (probe.stdout or probe.stderr):
            # Confirm importable module actually exists
            check = subprocess.run(
                [sys.executable, "-c", f"import {module.split('.')[0]}"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if check.returncode == 0:
                return [sys.executable, "-m", module]
    except Exception:
        pass
    binary = _which(module.replace(".", "-"), module, module.replace("_", "-"))
    if binary:
        return [binary]
    return None


def run_detect_secrets(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    """Yelp detect-secrets — complementary entropy/keyword secret heuristics."""
    meta: dict = {"engine": "detect_secrets", "available": False}
    cmd = _py_module_cmd("detect_secrets") or _which("detect-secrets")
    if isinstance(cmd, str):
        cmd = [cmd]
    if not cmd:
        meta["skipped"] = "detect-secrets not found"
        return [], meta
    meta["available"] = True
    try:
        # `detect-secrets scan` writes JSON baseline to stdout
        proc = subprocess.run(
            [*cmd, "scan", "--all-files"],
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        meta["returncode"] = proc.returncode
        raw = (proc.stdout or "").strip()
        data = json.loads(raw) if raw else {}
        findings: list[NormalizedFinding] = []
        results = data.get("results") if isinstance(data, dict) else {}
        if isinstance(results, dict):
            for file_path, items in results.items():
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    kind = item.get("type") or "Secret"
                    findings.append(
                        NormalizedFinding(
                            engine="detect_secrets",
                            title=f"detect-secrets: {kind}"[:512],
                            severity="high",
                            rule_id=str(kind)[:120],
                            vuln_family="secret",
                            message=f"Possible secret ({kind}) flagged by detect-secrets.",
                            file_path=str(file_path),
                            line_start=item.get("line_number"),
                            raw=item,
                        )
                    )
        meta["findings"] = len(findings)
        if proc.returncode not in (0, 1) and not findings:
            meta["error"] = ((proc.stderr or proc.stdout) or f"exit {proc.returncode}")[:300]
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta


def run_pip_audit(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    """Python dependency CVEs via pip-audit against requirements files."""
    meta: dict = {"engine": "pip_audit", "available": False}
    cmd = _py_module_cmd("pip_audit") or _which("pip-audit")
    if isinstance(cmd, str):
        cmd = [cmd]
    if not cmd:
        meta["skipped"] = "pip-audit not found"
        return [], meta
    req_files: list[Path] = []
    for pattern in ("requirements*.txt", "requirements/*.txt"):
        req_files.extend(sorted(workdir.glob(pattern)))
    # Dedupe
    seen: set[str] = set()
    unique: list[Path] = []
    for path in req_files:
        key = str(path.resolve())
        if key in seen or not path.is_file():
            continue
        seen.add(key)
        unique.append(path)
    if not unique:
        meta["available"] = True
        meta["skipped"] = "no requirements files"
        meta["findings"] = 0
        return [], meta
    meta["available"] = True
    findings: list[NormalizedFinding] = []
    try:
        for req in unique[:12]:
            proc = subprocess.run(
                [*cmd, "-r", str(req), "-f", "json", "--progress-spinner", "off"],
                capture_output=True,
                text=True,
                timeout=420,
                check=False,
            )
            raw = (proc.stdout or "").strip()
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            # Format: list of {name, version, vulns: [{id, fix_versions, description}]}
            rows = data if isinstance(data, list) else data.get("dependencies") or data.get("vulns") or []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                pkg = row.get("name") or row.get("package") or "package"
                version = row.get("version") or ""
                vulns = row.get("vulns") or row.get("vulnerabilities") or []
                if not vulns and row.get("id"):
                    vulns = [row]
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue
                    vid = vuln.get("id") or vuln.get("vulnerability_id") or "CVE"
                    fix = vuln.get("fix_versions") or vuln.get("fixed_versions") or []
                    fix_s = ", ".join(str(x) for x in fix[:4]) if isinstance(fix, list) else str(fix or "")
                    msg = vuln.get("description") or ""
                    if fix_s:
                        msg = f"{msg} Fix: {fix_s}".strip()
                    findings.append(
                        NormalizedFinding(
                            engine="pip_audit",
                            title=f"{vid} in {pkg} {version}".strip()[:512],
                            severity=normalize_severity(vuln.get("severity") or "high"),
                            rule_id=str(vid)[:120],
                            vuln_family="sca",
                            message=msg[:2000],
                            file_path=str(req.relative_to(workdir)).replace("\\", "/"),
                            raw=vuln if isinstance(vuln, dict) else {},
                        )
                    )
        meta["findings"] = len(findings)
        meta["requirements_scanned"] = len(unique)
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta


def run_checkov(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    """IaC / Dockerfile / K8s misconfig via Checkov."""
    meta: dict = {"engine": "checkov", "available": False}
    cmd = _py_module_cmd("checkov") or _which("checkov")
    if isinstance(cmd, str):
        cmd = [cmd]
    if not cmd:
        meta["skipped"] = "checkov not found"
        return [], meta
    meta["available"] = True
    try:
        proc = subprocess.run(
            [*cmd, "-d", str(workdir), "-o", "json", "--quiet", "--compact", "--soft-fail"],
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        meta["returncode"] = proc.returncode
        raw = (proc.stdout or "").strip()
        if not raw:
            meta["findings"] = 0
            return [], meta
        data = json.loads(raw)
        reports = data if isinstance(data, list) else [data]
        findings: list[NormalizedFinding] = []
        for report in reports:
            if not isinstance(report, dict):
                continue
            failed = (report.get("results") or {}).get("failed_checks") or []
            for item in failed:
                if not isinstance(item, dict):
                    continue
                check_id = item.get("check_id") or item.get("guideline") or "CKV"
                title = item.get("check_name") or check_id
                sev = item.get("severity") or "MEDIUM"
                file_path = item.get("file_path") or item.get("repo_file_path")
                findings.append(
                    NormalizedFinding(
                        engine="checkov",
                        title=str(title)[:512],
                        severity=normalize_severity(sev),
                        rule_id=str(check_id)[:120],
                        vuln_family=classify_family(str(check_id), str(title), item.get("description")),
                        message=(item.get("description") or item.get("check_name") or "")[:2000],
                        file_path=str(file_path).lstrip("/") if file_path else None,
                        line_start=(item.get("file_line_range") or [None])[0]
                        if isinstance(item.get("file_line_range"), list)
                        else item.get("file_line_range"),
                        raw=item,
                    )
                )
        meta["findings"] = len(findings)
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta


def run_njsscan(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    """Node.js / Electron SAST via njsscan."""
    meta: dict = {"engine": "njsscan", "available": False}
    cmd = _py_module_cmd("njsscan") or _which("njsscan")
    if isinstance(cmd, str):
        cmd = [cmd]
    if not cmd:
        meta["skipped"] = "njsscan not found"
        return [], meta
    meta["available"] = True
    try:
        proc = subprocess.run(
            [*cmd, "--json", "-w", str(workdir)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        # Older CLI: njsscan DIR --json
        if proc.returncode not in (0, 1) and "unrecognized" in (proc.stderr or "").lower():
            proc = subprocess.run(
                [*cmd, str(workdir), "--json"],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        meta["returncode"] = proc.returncode
        raw = (proc.stdout or "").strip()
        data = json.loads(raw) if raw else {}
        findings: list[NormalizedFinding] = []

        def _ingest(bucket: dict | None) -> None:
            if not isinstance(bucket, dict):
                return
            for file_path, items in bucket.items():
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    meta_info = item.get("metadata") or {}
                    rule_id = item.get("rule_id") or meta_info.get("cwe") or "njsscan"
                    title = meta_info.get("description") or item.get("match_string") or rule_id
                    sev = meta_info.get("severity") or "WARNING"
                    findings.append(
                        NormalizedFinding(
                            engine="njsscan",
                            title=str(title)[:512],
                            severity=normalize_severity(sev),
                            rule_id=str(rule_id)[:120],
                            vuln_family=classify_family(str(rule_id), str(title), meta_info.get("description")),
                            cwe=str(meta_info.get("cwe") or "")[:32] or None,
                            message=(meta_info.get("description") or "")[:2000],
                            file_path=str(file_path),
                            line_start=(item.get("lines") or [None])[0]
                            if isinstance(item.get("lines"), list)
                            else None,
                            snippet=(item.get("match_string") or "")[:2000],
                            raw=item,
                        )
                    )

        if isinstance(data, dict):
            _ingest(data.get("nodejs"))
            _ingest(data.get("templates"))
        meta["findings"] = len(findings)
        if proc.returncode not in (0, 1) and not findings:
            meta["error"] = ((proc.stderr or proc.stdout) or f"exit {proc.returncode}")[:300]
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta


def _iter_dockerfiles(workdir: Path) -> list[Path]:
    out: list[Path] = []
    for path in workdir.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name == "dockerfile" or name.startswith("dockerfile."):
            out.append(path)
        if len(out) >= 40:
            break
    return out


def run_hadolint(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    """Dockerfile lint / security hygiene via Hadolint."""
    meta: dict = {"engine": "hadolint", "available": False}
    binary = _which("hadolint")
    if not binary:
        meta["skipped"] = "hadolint binary not found"
        return [], meta
    files = _iter_dockerfiles(workdir)
    if not files:
        meta["available"] = True
        meta["skipped"] = "no Dockerfiles"
        meta["findings"] = 0
        return [], meta
    meta["available"] = True
    findings: list[NormalizedFinding] = []
    try:
        for path in files:
            proc = subprocess.run(
                [binary, "-f", "json", str(path)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            raw = (proc.stdout or "").strip()
            if not raw:
                continue
            try:
                items = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(items, list):
                continue
            rel = str(path.relative_to(workdir)).replace("\\", "/")
            for item in items:
                if not isinstance(item, dict):
                    continue
                code = item.get("code") or "DL000"
                level = (item.get("level") or "info").lower()
                sev = {"error": "high", "warning": "medium", "info": "low", "style": "info"}.get(level, "info")
                findings.append(
                    NormalizedFinding(
                        engine="hadolint",
                        title=f"Hadolint {code}: {item.get('message') or code}"[:512],
                        severity=normalize_severity(sev),
                        rule_id=str(code)[:120],
                        vuln_family="other",
                        message=(item.get("message") or "")[:2000],
                        file_path=rel,
                        line_start=item.get("line"),
                        raw=item,
                    )
                )
        meta["findings"] = len(findings)
        meta["dockerfiles"] = len(files)
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta


def _iter_shell_scripts(workdir: Path) -> list[Path]:
    out: list[Path] = []
    for path in workdir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".sh", ".bash", ".ksh"} or path.name.lower().endswith(".sh"):
            out.append(path)
        if len(out) >= 80:
            break
    return out


def run_shellcheck(workdir: Path) -> tuple[list[NormalizedFinding], dict]:
    """Shell script security / correctness via ShellCheck."""
    meta: dict = {"engine": "shellcheck", "available": False}
    binary = _which("shellcheck")
    if not binary:
        meta["skipped"] = "shellcheck binary not found"
        return [], meta
    files = _iter_shell_scripts(workdir)
    if not files:
        meta["available"] = True
        meta["skipped"] = "no shell scripts"
        meta["findings"] = 0
        return [], meta
    meta["available"] = True
    findings: list[NormalizedFinding] = []
    try:
        for path in files:
            proc = subprocess.run(
                [binary, "-f", "json", str(path)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            raw = (proc.stdout or "").strip()
            if not raw:
                continue
            try:
                items = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(items, list):
                continue
            rel = str(path.relative_to(workdir)).replace("\\", "/")
            for item in items:
                if not isinstance(item, dict):
                    continue
                code = item.get("code")
                level = (item.get("level") or "info").lower()
                sev = {"error": "high", "warning": "medium", "info": "low", "style": "info"}.get(level, "info")
                msg = item.get("message") or f"SC{code}"
                findings.append(
                    NormalizedFinding(
                        engine="shellcheck",
                        title=f"ShellCheck SC{code}: {msg}"[:512],
                        severity=normalize_severity(sev),
                        rule_id=f"SC{code}"[:120],
                        vuln_family="other",
                        message=str(msg)[:2000],
                        file_path=rel,
                        line_start=item.get("line"),
                        line_end=item.get("endLine") or item.get("line"),
                        raw=item,
                    )
                )
        meta["findings"] = len(findings)
        meta["scripts"] = len(files)
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:300]
        return [], meta
