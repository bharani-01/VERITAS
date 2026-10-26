from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

TEST_DB_DIR = tempfile.mkdtemp(prefix="veritas-phase6a-tests-")
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = f"sqlite:///{Path(TEST_DB_DIR) / 'test_phase6a.db'}"
os.environ["BOOTSTRAP_ADMIN_EMAIL"] = "admin@example.com"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "StrongPass!123"
os.environ["EMAIL_DELIVERY_MODE"] = "Sink"
os.environ["TOKEN_ENCRYPTION_SECRET"] = "test-secret-for-phase6a-suite"

from app.core import database as db  # noqa: E402
from app.core.time import utcnow  # noqa: E402
from app.main import app  # noqa: E402
from app.models import CveIntelCache, Finding, Project, Scan, User  # noqa: E402
from app.services.auth import bootstrap_admin_account, ensure_schema, hash_password  # noqa: E402
from app.services.correlator import correlate_findings  # noqa: E402
from app.services.engines.normalize import NormalizedFinding  # noqa: E402
from app.services.engines.trivy_sbom import run_trivy_sbom  # noqa: E402
from app.services.threat_intel import (  # noqa: E402
    compute_effective_priority_score,
    enrich_findings_with_intel,
    sync_threat_intel_feeds,
)


def _make_active_user(email: str, password: str = "UserPass!123456") -> str:
    with db.SessionLocal() as session:
        user = User(
            email=email,
            password_hash=hash_password(password),
            role="user",
            status="active",
            email_verified_at=utcnow(),
            approved_at=utcnow(),
        )
        session.add(user)
        session.commit()
        return user.id


@pytest.fixture()
def client():
    db.reload_engine(f"sqlite:///{Path(TEST_DB_DIR) / 'test_phase6a.db'}")
    db.Base.metadata.drop_all(bind=db.engine)
    ensure_schema()
    with db.SessionLocal() as session:
        bootstrap_admin_account(session)
    with TestClient(app) as c:
        yield c


def _login(c: TestClient, email: str, password: str = "UserPass!123456"):
    resp = c.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text


# ============================================================================
# 1. Cross-Engine SCA and Secret Deduplication
# ============================================================================


def test_cross_engine_sca_and_secret_deduplication():
    raw_hits = [
        # Three SCA engines flagging the exact same CVE-2026-102268 on requests 2.31.0
        NormalizedFinding(
            engine="trivy",
            title="CVE-2026-102268 in requests 2.31.0",
            severity="medium",
            rule_id="CVE-2026-102268",
            vuln_family="sca",
            message="Short Trivy advisory summary.",
            file_path="requirements.txt",
            raw={
                "VulnerabilityID": "CVE-2026-102268",
                "PkgName": "requests",
                "InstalledVersion": "2.31.0",
                "FixedVersion": "2.32.0",
                "ecosystem": "pypi",
            },
        ),
        NormalizedFinding(
            engine="osv",
            title="GHSA-9wx4-h78v-vm56 in requests",
            severity="high",
            rule_id="GHSA-9wx4-h78v-vm56",
            vuln_family="sca",
            message=(
                "Detailed OSV advisory explaining how crafted redirects leak proxy-authorization "
                "headers in requests 2.31.0 when following cross-origin redirects."
            ),
            file_path="./requirements.txt",
            raw={
                "id": "GHSA-9wx4-h78v-vm56",
                "aliases": ["CVE-2026-102268"],
                "package_name": "Requests",
                "installed_version": "2.31.0",
                "ecosystem": "PyPI",
            },
        ),
        NormalizedFinding(
            engine="pip_audit",
            title="PYSEC-2026-42 in requests 2.31.0",
            severity="high",
            rule_id="PYSEC-2026-42",
            vuln_family="sca",
            message="pip-audit advisory for requests.",
            file_path="requirements.txt",
            raw={
                "id": "PYSEC-2026-42",
                "aliases": ["CVE-2026-102268"],
                "package": "requests",
                "version": "2.31.0",
                "fix_versions": ["2.32.2"],
            },
        ),
        # Two secret scanners flagging the same leaked GitHub token on line 18
        NormalizedFinding(
            engine="gitleaks",
            title="GitHub Personal Access Token",
            severity="high",
            rule_id="github-pat",
            vuln_family="secret",
            message="Detected GitHub PAT in config.py",
            file_path="src/config.py",
            line_start=18,
            snippet="GH_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuv'",
            raw={"RuleID": "github-pat"},
        ),
        NormalizedFinding(
            engine="trufflehog",
            title="TruffleHog: GitHub (verified)",
            severity="critical",
            rule_id="GitHub",
            vuln_family="secret",
            message="Verified active GitHub token in src/config.py",
            file_path="./src/config.py",
            line_start=18,
            snippet="GH_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuv'",
            raw={"DetectorName": "GitHub", "Verified": True},
        ),
    ]

    corr = correlate_findings(raw_hits)
    assert corr.raw_findings_count == 5
    assert corr.correlated_findings_count == 2
    assert corr.deduplicated_count == 3
    assert corr.multi_engine_confirmed_count == 2

    by_family = {f.vuln_family: f for f in corr.findings}
    sca_finding = by_family["sca"]
    assert sca_finding.raw["cve_id"] == "CVE-2026-102268"
    assert sca_finding.raw["engine_count"] == 3
    assert sca_finding.raw["matched_engines"] == ["osv", "pip_audit", "trivy"]
    assert sca_finding.raw["confidence_level"] == "high"
    assert sca_finding.severity == "high"
    assert "cross-origin redirects" in (sca_finding.message or "")
    assert "2.32.0" in (sca_finding.message or "")

    secret_finding = by_family["secret"]
    assert secret_finding.raw["engine_count"] == 2
    assert secret_finding.raw["matched_engines"] == ["gitleaks", "trufflehog"]
    assert secret_finding.raw["confidence_level"] == "high"
    assert secret_finding.severity == "critical"


# ============================================================================
# 2. KEV + EPSS Enrichment and Composite Priority Sorting
# ============================================================================


def test_kev_and_epss_enrichment_and_priority_sorting(client: TestClient):
    with db.SessionLocal() as session:
        session.add(
            CveIntelCache(
                cve_id="CVE-2024-21626",
                is_kev=True,
                kev_vendor="Docker",
                kev_product="runc",
                kev_date_added="2024-02-01",
                kev_due_date="2024-02-22",
                epss_score=0.65,
                epss_percentile=0.985,
                updated_at=utcnow(),
            )
        )
        session.add(
            CveIntelCache(
                cve_id="CVE-2024-99999",
                is_kev=False,
                epss_score=0.04,
                epss_percentile=0.45,
                updated_at=utcnow(),
            )
        )
        session.commit()

        raw_findings = [
            # Non-KEV high finding
            NormalizedFinding(
                engine="trivy",
                title="CVE-2024-99999 in urllib3 1.26.0",
                severity="high",
                rule_id="CVE-2024-99999",
                vuln_family="sca",
                file_path="requirements.txt",
                raw={"cve_id": "CVE-2024-99999", "engine_count": 1, "matched_engines": ["trivy"]},
            ),
            # KEV medium finding confirmed by 2 engines (should auto-promote to critical & rank #1)
            NormalizedFinding(
                engine="osv",
                title="CVE-2024-21626 in runc 1.1.11",
                severity="medium",
                rule_id="CVE-2024-21626",
                vuln_family="sca",
                file_path="go.mod",
                raw={
                    "cve_id": "CVE-2024-21626",
                    "engine_count": 2,
                    "matched_engines": ["osv", "trivy"],
                },
            ),
        ]

        enriched = enrich_findings_with_intel(session, raw_findings, allow_network=False)
        assert len(enriched) == 2

        top = enriched[0]
        second = enriched[1]

        assert top.raw["cve_id"] == "CVE-2024-21626"
        assert top.raw["is_kev"] is True
        assert top.raw["kev_due_date"] == "2024-02-22"
        assert top.severity == "critical"
        assert top.raw["epss_score"] == pytest.approx(0.65)
        assert top.raw["effective_priority_score"] == pytest.approx(10.0)
        assert top.raw["effective_priority_score"] > second.raw["effective_priority_score"]

        expected_second_score = compute_effective_priority_score(
            severity="high",
            is_kev=False,
            epss_score=0.04,
            engine_count=1,
        )
        assert second.raw["effective_priority_score"] == pytest.approx(expected_second_score)


# ============================================================================
# 3. Threat Intel Sync Fail-Open Resilience
# ============================================================================


def test_threat_intel_sync_fail_open(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    def _boom_get(self, url, *args, **kwargs):
        raise httpx.ConnectTimeout("Simulated CISA/FIRST network timeout")

    monkeypatch.setattr(httpx.Client, "get", _boom_get)

    with db.SessionLocal() as session:
        status_res = sync_threat_intel_feeds(
            session,
            cve_ids=["CVE-2025-0001"],
            include_bulk_epss=True,
        )
        assert isinstance(status_res, dict)
        assert status_res["kev_upserted"] == 0
        assert status_res["epss_upserted"] == 0
        assert status_res["total_cached_cves"] == 0


# ============================================================================
# 4. CycloneDX SBOM Generation, Copyleft Policy Finding, & Ownership AuthZ
# ============================================================================


def test_sbom_generation_and_copyleft_license_finding(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    # Force deterministic manifest parser so test is environment-independent
    monkeypatch.setattr("shutil.which", lambda _cmd: None)

    owner_id = _make_active_user("sbom_owner@example.com")
    _make_active_user("sbom_stranger@example.com")

    # Create sample repo workspace with permissive, weak copyleft, and restricted copyleft packages
    repo_dir = tmp_path / "sample_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "requirements.txt").write_text(
        "fastapi==0.115.0 # license: MIT\n"
        "psycopg2==2.9.9 # license: LGPL-3.0\n"
        "pyminizip==0.2.6 # license: GPL-3.0\n",
        encoding="utf-8",
    )
    (repo_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "sample-ui",
                "version": "1.0.0",
                "dependencies": {
                    "react": {"version": "18.3.1", "license": "MIT"},
                    "agpl-pdf-engine": {"version": "2.1.0", "license": "AGPL-3.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    with db.SessionLocal() as session:
        proj = Project(owner_user_id=owner_id, name="SBOM Governance App")
        session.add(proj)
        session.commit()
        session.refresh(proj)

        scan = Scan(
            project_id=proj.id,
            created_by_user_id=owner_id,
            target="https://github.com/example/sbom-app",
            status="succeeded",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        sbom_res, meta = run_trivy_sbom(
            session,
            scan_id=scan.id,
            project_id=proj.id,
            workdir=repo_dir,
        )
        assert meta["available"] is True
        assert sbom_res.component_count == 5
        assert sbom_res.policy_violations_count == 2
        assert sbom_res.license_summary["permissive"] == 2
        assert sbom_res.license_summary["weak_copyleft"] == 1
        assert sbom_res.license_summary["restricted_copyleft"] == 2
        assert len(sbom_res.findings) == 2

        for nf in sbom_res.findings:
            assert nf.engine == "trivy_license"
            assert nf.vuln_family == "license"
            assert nf.severity == "high"
            assert nf.cwe == "CWE-1104"
            assert "Restricted Copyleft License Detected:" in nf.title
            session.add(
                Finding(
                    scan_id=scan.id,
                    engine=nf.engine,
                    rule_id=nf.rule_id,
                    vuln_family=nf.vuln_family,
                    cwe=nf.cwe,
                    owasp_category=nf.owasp_category,
                    severity=nf.severity,
                    title=nf.title,
                    message=nf.message,
                    file_path=nf.file_path,
                    line_start=nf.line_start,
                    line_end=nf.line_end,
                    risk_score=7.5,
                    effective_priority_score=7.5,
                    matched_engines_json='["trivy_license"]',
                    engine_count=1,
                    confidence_level="high",
                )
            )
        session.commit()
        project_id = proj.id
        scan_id = scan.id

    # Verify owner can fetch SBOM summary, download CycloneDX JSON, and filter license findings
    _login(client, "sbom_owner@example.com")

    sbom_resp = client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/sbom")
    assert sbom_resp.status_code == 200, sbom_resp.text
    sbom_body = sbom_resp.json()
    assert sbom_body["component_count"] == 5
    assert sbom_body["policy_violations_count"] == 2
    assert len(sbom_body["components"]) == 5

    dl_resp = client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/sbom/download")
    assert dl_resp.status_code == 200
    assert f'filename="veritas-sbom-scan-{scan_id}.cdx.json"' in dl_resp.headers.get(
        "content-disposition", ""
    )
    cdx_json = dl_resp.json()
    assert cdx_json["bomFormat"] == "CycloneDX"
    assert cdx_json["specVersion"] == "1.5"
    assert len(cdx_json["components"]) == 5

    findings_resp = client.get(
        f"/workspace/projects/{project_id}/scans/{scan_id}/findings?category=license"
    )
    assert findings_resp.status_code == 200
    assert findings_resp.json()["total"] == 2

    # Verify foreign user is strictly blocked (404 project ownership isolation)
    client.post("/auth/logout")
    _login(client, "sbom_stranger@example.com")
    assert client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/sbom").status_code == 404
    assert (
        client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/sbom/download").status_code
        == 404
    )
