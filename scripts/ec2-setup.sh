#!/usr/bin/env bash
set -euo pipefail

DOMAIN="veritas.trackifyapp.co.in"
APP_ROOT="/opt/veritas"

sudo mkdir -p "$APP_ROOT"
sudo chown ubuntu:ubuntu "$APP_ROOT"
cd "$APP_ROOT"

if [[ -f "$HOME/veritas-deploy.tgz" ]]; then
  tar -xzf "$HOME/veritas-deploy.tgz"
  rm -f "$HOME/veritas-deploy.tgz"
fi

if [[ -f "$HOME/veritas.env.upload" ]]; then
  cp "$HOME/veritas.env.upload" "$APP_ROOT/backend/.env"
  rm -f "$HOME/veritas.env.upload"
fi
chmod 600 "$APP_ROOT/backend/.env"

python3 - <<'PY'
from pathlib import Path

p = Path("/opt/veritas/backend/.env")
text = p.read_text(encoding="utf-8")
replacements = {
    "APP_ENV": "production",
    "SESSION_COOKIE_SECURE": "true",
    "PUBLIC_APP_URL": "https://veritas.trackifyapp.co.in",
    "GITHUB_REDIRECT_URI": "https://veritas.trackifyapp.co.in/workspace/github/callback",
}
lines = []
for line in text.splitlines():
    raw = line.strip()
    if not raw or raw.startswith("#") or "=" not in line:
        lines.append(line)
        continue
    key, _, _ = line.partition("=")
    key = key.strip()
    if key in replacements:
        lines.append(f"{key}={replacements[key]}")
    else:
        lines.append(line)
p.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("env_rewritten")
PY

cd "$APP_ROOT/backend"
python3 -m venv .venv
.venv/bin/pip install -q -U pip
.venv/bin/pip install -q -r requirements.txt

# Phase 3 scan engines (Semgrep from requirements on Linux; extras best-effort)
sudo apt-get update -qq
sudo apt-get install -y -qq git curl unzip || true
"$APP_ROOT/backend/.venv/bin/pip" install -q "semgrep>=1.90,<2.0" || true
"$APP_ROOT/backend/.venv/bin/python" -m semgrep --version || true
if ! command -v gitleaks >/dev/null 2>&1; then
  GITLEAKS_VER="8.21.2"
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_x64.tar.gz" \
    | sudo tar -xz -C /usr/local/bin gitleaks || true
fi
if ! command -v osv-scanner >/dev/null 2>&1; then
  OSV_VER="1.9.2"
  curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_VER}/osv-scanner_linux_amd64" \
    -o /tmp/osv-scanner && sudo install -m 755 /tmp/osv-scanner /usr/local/bin/osv-scanner || true
fi
# Deep engines (soft-skip at runtime if missing)
"$APP_ROOT/backend/.venv/bin/pip" install -q "bandit>=1.7,<2.0" "detect-secrets>=1.5,<2.0" "pip-audit>=2.7,<3.0" "checkov>=3.2,<4.0" "njsscan>=0.3,<1.0" || true
if ! command -v trufflehog >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sudo sh -s -- -b /usr/local/bin || true
fi
if ! command -v trivy >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sudo sh -s -- -b /usr/local/bin || true
fi
if ! command -v hadolint >/dev/null 2>&1; then
  HADOLINT_VER="2.12.0"
  curl -fsSL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VER}/hadolint-Linux-x86_64" \
    -o /tmp/hadolint && sudo install -m 755 /tmp/hadolint /usr/local/bin/hadolint || true
fi
if ! command -v shellcheck >/dev/null 2>&1; then
  sudo apt-get install -y -qq shellcheck || true
fi
command -v trufflehog >/dev/null && trufflehog --version || true
command -v trivy >/dev/null && trivy --version || true
command -v hadolint >/dev/null && hadolint --version || true
command -v shellcheck >/dev/null && shellcheck --version || true
"$APP_ROOT/backend/.venv/bin/python" -m bandit --version || true
"$APP_ROOT/backend/.venv/bin/python" -m detect_secrets --version || true
"$APP_ROOT/backend/.venv/bin/python" -m pip_audit --version || true
"$APP_ROOT/backend/.venv/bin/python" -m checkov --version || true
"$APP_ROOT/backend/.venv/bin/njsscan" --help >/dev/null 2>&1 || "$APP_ROOT/backend/.venv/bin/python" -c "import njsscan" || true

sudo tee /etc/systemd/system/veritas.service >/dev/null <<EOF
[Unit]
Description=VERITAS Infosec API
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=$APP_ROOT/backend
Environment=PATH=$APP_ROOT/backend/.venv/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$APP_ROOT/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir $APP_ROOT/backend
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/nginx/sites-available/veritas >/dev/null <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    client_max_body_size 20m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

sudo ln -sfn /etc/nginx/sites-available/veritas /etc/nginx/sites-enabled/veritas
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable --now veritas
sudo systemctl restart nginx
sudo systemctl reload nginx || true

# HTTPS via Let's Encrypt (HTTP-01). Safe to re-run; expands if cert exists.
sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@bharani-01.xyz --redirect || true

sudo systemctl restart veritas
sleep 2
curl -fsS -o /dev/null -w "local_health=%{http_code}\n" http://127.0.0.1:8000/health || true
curl -fsS -o /dev/null -w "http_domain=%{http_code}\n" "http://$DOMAIN/health" || true
curl -fsSk -o /dev/null -w "https_domain=%{http_code}\n" "https://$DOMAIN/health" || true
systemctl is-active veritas nginx
echo SETUP_DONE
