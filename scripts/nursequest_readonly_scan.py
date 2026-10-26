# Read-only NurseQuest metrics + login screenshots. Never writes into NurseQuest.
from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"d:\E0224033\InFoSec\CL\LB_Proj\VERITAS")
NQ = ROOT / "report_scan_targets" / "NurseQuest"
OUT = ROOT / "report_figures"
PY = ROOT / "backend" / ".venv" / "Scripts" / "python.exe"
OUT.mkdir(parents=True, exist_ok=True)


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def run_detect_secrets() -> dict:
    targets = [p for p in ("backend", "frontend", "src", "app", "server", "client") if (NQ / p).exists()]
    if not targets:
        targets = ["."]
    proc = subprocess.run(
        [str(PY), "-m", "detect_secrets", "scan", "--all-files", *targets],
        cwd=str(NQ),
        capture_output=True,
        text=True,
    )
    path = OUT / "nursequest_detect_secrets.json"
    raw = (proc.stdout or "").strip() or (proc.stderr or "").strip()
    path.write_text(raw or "{}", encoding="utf-8")
    if not raw.startswith("{"):
        return {
            "error": "no JSON output",
            "returncode": proc.returncode,
            "stderr_tail": (proc.stderr or "")[-400:],
            "stdout_tail": (proc.stdout or "")[-400:],
        }
    data = json.loads(raw)
    results = data.get("results") or {}
    return {
        "engine": "detect-secrets",
        "status": "ran",
        "findings": sum(len(v) for v in results.values()),
        "files_with_hits": len(results),
        "targets": targets,
        "top": [{"file": k, "count": len(v)} for k, v in list(results.items())[:10]],
    }


def run_bandit() -> dict:
    backend = NQ / "backend"
    if not backend.exists():
        return {"engine": "bandit", "status": "skipped", "reason": "no backend dir"}
    out_json = OUT / "nursequest_bandit.json"
    exclude = ",".join(
        str(p)
        for p in (
            backend / "node_modules",
            backend / ".venv",
            backend / "venv",
            NQ / "node_modules",
        )
        if p.exists() or True
    )
    proc = subprocess.run(
        [
            str(PY),
            "-m",
            "bandit",
            "-r",
            str(backend),
            "-x",
            exclude,
            "-f",
            "json",
            "-o",
            str(out_json),
            "-q",
        ],
        capture_output=True,
        text=True,
    )
    if not out_json.exists() or out_json.stat().st_size == 0:
        return {
            "engine": "bandit",
            "status": "error",
            "error": (proc.stderr or proc.stdout or "")[-500:],
            "returncode": proc.returncode,
        }
    data = json.loads(out_json.read_text(encoding="utf-8"))
    results = data.get("results") or []
    sev: dict[str, int] = {}
    for r in results:
        s = (r.get("issue_severity") or "UNKNOWN").upper()
        sev[s] = sev.get(s, 0) + 1
    return {
        "engine": "bandit",
        "status": "ran",
        "findings": len(results),
        "by_severity": sev,
        "returncode": proc.returncode,
        "top": [
            {
                "severity": r.get("issue_severity"),
                "test": r.get("test_id"),
                "file": r.get("filename"),
                "text": (r.get("issue_text") or "")[:140],
            }
            for r in results[:10]
        ],
    }


def run_pip_audit() -> dict:
    req_candidates = [
        NQ / "backend" / "requirements.txt",
        NQ / "requirements.txt",
        NQ / "backend" / "requirements" / "base.txt",
        NQ / "backend" / "pyproject.toml",
        NQ / "pyproject.toml",
    ]
    req = next((p for p in req_candidates if p.exists()), None)
    if req is None:
        return {"engine": "pip-audit", "status": "skipped", "reason": "no requirements.txt/pyproject.toml found"}
    out_json = OUT / "nursequest_pip_audit.json"
    cmd = [str(PY), "-m", "pip_audit"]
    if req.suffix == ".toml":
        cmd += ["--path", str(req.parent)]
    else:
        cmd += ["-r", str(req)]
    cmd += ["--format", "json", "--progress-spinner", "off"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    raw = (proc.stdout or "").strip()
    out_json.write_text(raw or (proc.stderr or ""), encoding="utf-8")
    if not raw:
        return {
            "engine": "pip-audit",
            "status": "error",
            "returncode": proc.returncode,
            "stderr_tail": (proc.stderr or "")[-500:],
            "requirements": str(req),
        }
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "engine": "pip-audit",
            "status": "error",
            "returncode": proc.returncode,
            "stderr_tail": (proc.stderr or raw)[-500:],
            "requirements": str(req),
        }
    # pip-audit JSON can be list of deps or dict
    vulns = 0
    deps = 0
    if isinstance(data, list):
        deps = len(data)
        for item in data:
            vulns += len(item.get("vulns") or [])
    elif isinstance(data, dict):
        deps_list = data.get("dependencies") or data.get("deps") or []
        deps = len(deps_list)
        for item in deps_list:
            vulns += len(item.get("vulns") or [])
    return {
        "engine": "pip-audit",
        "status": "ran",
        "requirements": str(req.relative_to(NQ)),
        "dependencies": deps,
        "vulnerabilities": vulns,
        "returncode": proc.returncode,
    }


def skipped_external_engines() -> list[dict]:
    skips = []
    for name, cmd in (
        ("gitleaks", "gitleaks"),
        ("osv-scanner", "osv-scanner"),
        ("semgrep", "semgrep"),
    ):
        path = which(cmd)
        if path:
            skips.append({"engine": name, "status": "present_not_run", "path": path, "note": "available on PATH but not executed in this pass"})
        else:
            skips.append({"engine": name, "status": "skipped", "reason": f"{cmd} not installed on host"})
    return skips


def screenshot_login_and_admin() -> dict:
    out_login = OUT / "live_login.png"
    out_admin = OUT / "live_admin.png"
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        subprocess.check_call([str(PY), "-m", "pip", "install", "-q", "playwright"])
        subprocess.check_call([str(PY), "-m", "playwright", "install", "chromium"])
        from playwright.sync_api import sync_playwright

    result = {"login": None, "admin": None, "login_ok": False}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.goto("http://127.0.0.1:8000/", wait_until="networkidle", timeout=60000)
        page.screenshot(path=str(out_login), full_page=True)
        result["login"] = str(out_login)
        page.fill('input[type="email"], input[name="email"], #email', "admin@veritas.example")
        page.fill('input[type="password"], input[name="password"], #password', "VeritasLab@2026")
        page.get_by_role("button", name="Sign in").click()
        page.wait_for_timeout(2500)
        # Admin shell usually lands on /admin/
        try:
            page.wait_for_url("**/admin**", timeout=8000)
            result["login_ok"] = True
        except Exception:
            result["login_ok"] = "/admin" in page.url
        page.screenshot(path=str(out_admin), full_page=True)
        result["admin"] = str(out_admin)
        result["final_url"] = page.url
        browser.close()
    return result


def main() -> None:
    assert NQ.exists(), f"missing {NQ}"
    sha_full = subprocess.check_output(["git", "-C", str(NQ), "rev-parse", "HEAD"], text=True).strip()
    sha = subprocess.check_output(["git", "-C", str(NQ), "rev-parse", "--short", "HEAD"], text=True).strip()
    origin = subprocess.check_output(["git", "-C", str(NQ), "remote", "get-url", "origin"], text=True).strip()
    push = subprocess.check_output(["git", "-C", str(NQ), "remote", "get-url", "--push", "origin"], text=True).strip()
    assert "Swaminathan8237/NurseQuest" in origin, origin
    assert push == "DISABLED" or "DISABLED" in push, push

    engines_ran = {
        "detect_secrets": run_detect_secrets(),
        "bandit": run_bandit(),
        "pip_audit": run_pip_audit(),
    }
    engines_skipped = skipped_external_engines()

    file_count = sum(1 for p in NQ.rglob("*") if p.is_file() and ".git" not in p.parts)
    summary = {
        "repo": "Swaminathan8237/NurseQuest",
        "repo_url": "https://github.com/Swaminathan8237/NurseQuest",
        "commit": sha,
        "commit_full": sha_full,
        "origin": origin,
        "push": push,
        "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "read_only": True,
        "scan_mode": "local_clone",
        "oauth_required": False,
        "oauth_note": "In-app Connect GitHub needs GITHUB_CLIENT_ID/SECRET from user; this pass used local clone only.",
        "file_count": file_count,
        "engines": engines_ran,
        "engines_skipped": engines_skipped,
    }

    shot_err = None
    try:
        summary["screenshots"] = screenshot_login_and_admin()
    except Exception as e:
        shot_err = str(e)
        summary["screenshot_error"] = shot_err

    (OUT / "nursequest_scan_metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    lines = [
        "# NurseQuest local-clone scan metrics",
        "",
        f"- Repo: `{summary['repo']}`",
        f"- Commit: `{summary['commit_full']}` (short `{summary['commit']}`)",
        f"- Files scanned (excluding `.git`): **{summary['file_count']}**",
        "- Mode: local clone only (no GitHub OAuth)",
        "- Read-only: yes (push remote DISABLED)",
        "",
        "## Engines ran",
        "",
    ]
    for eng, info in engines_ran.items():
        lines += [f"### {eng}", "```json", json.dumps(info, indent=2), "```", ""]
    lines += ["## Engines skipped / unavailable", "", "```json", json.dumps(engines_skipped, indent=2), "```", ""]
    if shot_err:
        lines += ["## Screenshots", "", f"Error: `{shot_err}`", ""]
    elif summary.get("screenshots"):
        lines += [
            "## Screenshots",
            "",
            f"- Login: `{summary['screenshots'].get('login')}`",
            f"- Admin: `{summary['screenshots'].get('admin')}`",
            f"- Login OK: `{summary['screenshots'].get('login_ok')}`",
            f"- Final URL: `{summary['screenshots'].get('final_url')}`",
            "",
        ]
    (OUT / "nursequest_scan_metrics.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
