# NurseQuest local-clone scan metrics

- Repo: `Swaminathan8237/NurseQuest`
- Commit: `69d678b218da65cb4bada813279effd6f0415d73` (short `69d678b`)
- Files scanned (excluding `.git`): **559**
- Mode: local clone only (no GitHub OAuth)
- Read-only: yes (push remote DISABLED)

## Engines ran

### detect_secrets
```json
{
  "engine": "detect-secrets",
  "status": "ran",
  "findings": 3,
  "files_with_hits": 3,
  "targets": [
    "backend",
    "frontend"
  ],
  "top": [
    {
      "file": "backend\\scratch\\test_local_login.js",
      "count": 1
    },
    {
      "file": "backend\\scratch\\test_local_register.js",
      "count": 1
    },
    {
      "file": "backend\\scratch\\test_signup_api.js",
      "count": 1
    }
  ]
}
```

### bandit
```json
{
  "engine": "bandit",
  "status": "ran",
  "findings": 0,
  "by_severity": {},
  "returncode": 0,
  "top": []
}
```

### pip_audit
```json
{
  "engine": "pip-audit",
  "status": "skipped",
  "reason": "no requirements.txt/pyproject.toml found"
}
```

## Engines skipped / unavailable

```json
[
  {
    "engine": "gitleaks",
    "status": "skipped",
    "reason": "gitleaks not installed on host"
  },
  {
    "engine": "osv-scanner",
    "status": "skipped",
    "reason": "osv-scanner not installed on host"
  },
  {
    "engine": "semgrep",
    "status": "skipped",
    "reason": "semgrep not installed on host"
  }
]
```

## Screenshots

Error: `BrowserType.launch: Executable doesn't exist at C:\Users\Swaminathan\AppData\Local\ms-playwright\chromium_headless_shell-1243\chrome-headless-shell-win64\chrome-headless-shell.exe
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝`

## Screenshots

- Login: `report_figures/live_login.png`
- Admin: `report_figures/live_admin.png`
- Login OK: `True`
- Final URL: `http://127.0.0.1:8000/admin/`
- Capture tool: cursor-ide-browser (+ Chrome DevTools MCP for interactive login)

## Notes

- Local clone scan only; in-app Connect GitHub needs `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`.
- `pip-audit` skipped: NurseQuest is Node.js (no requirements.txt/pyproject.toml).
- Admin email for local login: `admin@veritas.example` (`.local` reserved by email-validator).
