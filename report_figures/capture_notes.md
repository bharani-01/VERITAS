# Screenshot capture notes

## Local laboratory server
- URL: `http://127.0.0.1:8000/`
- Health: `GET /health` → HTTP 200
- SPA: `backend/app/web/static/spa/index.html` present

## Live production deployment
- URL: `https://veritas.trackifyapp.co.in`
- Account: `@neelambalguruswami` (user role)
- GitHub: `@Swaminathan8237` (reconnected 2026-09-26; scopes `read:user,repo`)

### NurseQuest (primary test target)
- Project id: `ecac4867-5223-4ef5-8471-3260d937d72a`
- Target: `Swaminathan8237/NurseQuest`
- Scan id: `53b5c73e-5425-42b4-a74c-b1589a3cca28` (git `69d678b`)
- Observed: **35 findings**, risk score **8** (high=7, medium=19, info=9; gitleaks + semgrep)

### AI Honeypot (secondary)
- Target: `Swaminathan8237/mirage-honeypot`
- Observed: **8 findings**, risk score **8** (high=6, medium=2)

## Outputs
| File | Description |
|------|-------------|
| `live_prod_scan_nursequest.png` | Production NurseQuest scan findings |
| `live_prod_nursequest_scan_metrics.json` | Structured NurseQuest prod metrics |
| `live_prod_scan_ai_honeypot.png` | Production AI Honeypot findings |
| `live_prod_scan_metrics.json` | AI Honeypot metrics |
| `nursequest_scan_metrics.json` | Supplementary local-clone metrics |

## Capture time
- 2026-09-26 (IST)
