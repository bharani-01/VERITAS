from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.models.workspace import ScanSbomArtifact
from app.services.correlator import CorrelatedFinding

logger = logging.getLogger("veritas.trivy_sbom")

PERMISSIVE_PREFIXES = (
    "MIT",
    "APACHE-2.0",
    "APACHE-1.1",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "BSD-4-CLAUSE",
    "0BSD",
    "ISC",
    "UNLICENSE",
    "PYTHON-2.0",
    "PSF-2.0",
    "ZLIB",
    "CC0-1.0",
    "WTFPL",
    "BLUEOAK-1.0.0",
)

WEAK_COPYLEFT_PREFIXES = (
    "LGPL-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "MPL-2.0",
    "MPL-1.1",
    "EPL-1.0",
    "EPL-2.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "CPL-1.0",
)

RESTRICTED_COPYLEFT_PREFIXES = (
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-1.0",
    "AGPL-3.0",
    "SSPL-1.0",
    "EUPL-1.1",
    "EUPL-1.2",
    "CPAL-1.0",
    "OSL-3.0",
)


@dataclass
class SbomExecutionResult:
    spec_version: str
    component_count: int
    policy_violations_count: int
    license_summary: dict[str, Any]
    components: list[dict[str, Any]]
    sbom_dict: dict[str, Any]
    sbom_json: str
    license_findings: list[Any] = field(default_factory=list)

    @property
    def findings(self) -> list[Any]:
        return self.license_findings


def classify_license_id(license_str: str | None) -> str:
    """
    Classifies an SPDX license ID or expression into:
      - `restricted_copyleft`
      - `weak_copyleft`
      - `permissive`
      - `unknown`
    """
    if not license_str or not license_str.strip():
        return "unknown"

    normalized = license_str.strip().upper()
    if normalized in ("NONE", "UNKNOWN", "NOASSERTION", "PROPRIETARY"):
        return "unknown"

    # Check weak copyleft BEFORE GPL-* substring checks so LGPL is not misclassified as GPL
    for prefix in WEAK_COPYLEFT_PREFIXES:
        if normalized.startswith(prefix) or f" {prefix}" in normalized:
            return "weak_copyleft"
    if "LESSER GENERAL PUBLIC LICENSE" in normalized or "MOZILLA PUBLIC LICENSE" in normalized:
        return "weak_copyleft"

    for prefix in RESTRICTED_COPYLEFT_PREFIXES:
        if normalized.startswith(prefix) or f" {prefix}" in normalized:
            return "restricted_copyleft"
    if any(
        kw in normalized
        for kw in (
            "AFFERO GENERAL PUBLIC LICENSE",
            "SERVER SIDE PUBLIC LICENSE",
            "GNU GENERAL PUBLIC LICENSE",
            "AGPL",
            "SSPL",
            "GPL",
        )
    ):
        return "restricted_copyleft"

    for prefix in PERMISSIVE_PREFIXES:
        if normalized.startswith(prefix) or f" {prefix}" in normalized:
            return "permissive"
    if any(kw in normalized for kw in ("MIT LICENSE", "APACHE LICENSE", "BSD LICENSE", "ISC LICENSE")):
        return "permissive"

    return "unknown"


def _infer_license_from_metadata_files(repo_dir: Path, pkg_name: str) -> str | None:
    """
    Optional helper used by the deterministic fallback parser: checks if the repository
    includes a local license map (`veritas-licenses.json` or inline comments).
    """
    license_map_file = repo_dir / "veritas-licenses.json"
    if license_map_file.is_file():
        try:
            data = json.loads(license_map_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                val = data.get(pkg_name) or data.get(pkg_name.lower())
                if isinstance(val, str) and val.strip():
                    return val.strip()
        except Exception:
            pass
    return None


def _parse_manifests_fallback(repo_workdir: str | Path) -> dict[str, Any]:
    """
    Deterministic manifest parser (`requirements.txt`, `package.json`, `pyproject.toml`, `go.mod`)
    that emits a valid CycloneDX 1.5 JSON structure when the `trivy` binary is unavailable
    (such as in unit test environments) or exits non-zero.
    """
    root = Path(repo_workdir)
    components: list[dict[str, Any]] = []
    seen_purls: set[str] = set()

    def add_component(
        name: str,
        version: str,
        ecosystem: str,
        purl: str,
        license_id: str | None,
        source_file: str,
    ) -> None:
        if purl in seen_purls:
            return
        seen_purls.add(purl)
        licenses_list: list[dict[str, Any]] = []
        if license_id:
            licenses_list.append({"license": {"id": license_id}})
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
                "licenses": licenses_list,
                "properties": [
                    {"name": "aquasecurity:trivy:PkgType", "value": ecosystem},
                    {"name": "veritas:source_file", "value": source_file},
                ],
            }
        )

    # 1. Parse requirements*.txt
    for req_file in sorted(root.rglob("*requirements*.txt")):
        if ".git" in req_file.parts or "node_modules" in req_file.parts:
            continue
        rel_path = str(req_file.relative_to(root)).replace("\\", "/")
        for raw_line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            # Support inline `# license: AGPL-3.0` annotations in manifests/tests
            inline_license: str | None = None
            if "#" in line:
                code_part, comment_part = line.split("#", 1)
                line = code_part.strip()
                lic_match = re.search(r"license\s*[:=]\s*([A-Za-z0-9.\-+]+)", comment_part, re.I)
                if lic_match:
                    inline_license = lic_match.group(1).strip()

            match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=|<=|>|<)\s*([A-Za-z0-9_.\-+]+)", line)
            if match:
                pkg_name = match.group(1).strip()
                pkg_ver = match.group(2).strip()
            else:
                pkg_name = re.split(r"[;\[\s]", line)[0].strip()
                pkg_ver = "0.0.0"

            if not pkg_name:
                continue
            lic = inline_license or _infer_license_from_metadata_files(root, pkg_name)
            purl = f"pkg:pypi/{pkg_name.lower()}@{pkg_ver}"
            add_component(pkg_name, pkg_ver, "pypi", purl, lic, rel_path)

    # 2. Parse package.json
    for pkg_json in sorted(root.rglob("package.json")):
        if ".git" in pkg_json.parts or "node_modules" in pkg_json.parts:
            continue
        rel_path = str(pkg_json.relative_to(root)).replace("\\", "/")
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        pkg_licenses_map = data.get("licensePolicies") or data.get("licensesMap") or {}
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for dep_name, dep_ver_spec in deps.items():
                if isinstance(dep_ver_spec, dict):
                    clean_ver = str(dep_ver_spec.get("version") or "0.0.0").lstrip("^~>=< ")
                    lic = str(dep_ver_spec.get("license") or "").strip() or None
                else:
                    clean_ver = str(dep_ver_spec or "0.0.0").lstrip("^~>=< ") or "0.0.0"
                    lic = (
                        pkg_licenses_map.get(dep_name)
                        if isinstance(pkg_licenses_map, dict)
                        else None
                    ) or _infer_license_from_metadata_files(root, dep_name)
                purl = f"pkg:npm/{dep_name}@{clean_ver}"
                add_component(dep_name, clean_ver, "npm", purl, lic, rel_path)

    # 3. Parse pyproject.toml
    for pyproject in sorted(root.rglob("pyproject.toml")):
        if ".git" in pyproject.parts or "node_modules" in pyproject.parts:
            continue
        rel_path = str(pyproject.relative_to(root)).replace("\\", "/")
        content = pyproject.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(
            r'"([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=|<=)\s*([0-9][A-Za-z0-9_.\-]*)"', content
        ):
            pkg_name, pkg_ver = match.group(1), match.group(2)
            lic = _infer_license_from_metadata_files(root, pkg_name)
            purl = f"pkg:pypi/{pkg_name.lower()}@{pkg_ver}"
            add_component(pkg_name, pkg_ver, "pypi", purl, lic, rel_path)

    # 4. Parse go.mod
    for gomod in sorted(root.rglob("go.mod")):
        if ".git" in gomod.parts:
            continue
        rel_path = str(gomod.relative_to(root)).replace("\\", "/")
        for raw_line in gomod.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("module ", "go ", "//", "require", ")")):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                pkg_name = parts[0]
                pkg_ver = parts[1]
                lic = _infer_license_from_metadata_files(root, pkg_name)
                purl = f"pkg:golang/{pkg_name}@{pkg_ver}"
                add_component(pkg_name, pkg_ver, "golang", purl, lic, rel_path)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "VERITAS DevSecOps",
                    "name": "veritas-cyclonedx-generator",
                    "version": "6.0.0",
                }
            ],
        },
        "components": components,
    }


def _extract_component_licenses(comp: dict[str, Any]) -> list[str]:
    licenses_raw = comp.get("licenses")
    extracted: list[str] = []
    if isinstance(licenses_raw, list):
        for entry in licenses_raw:
            if isinstance(entry, dict):
                lic_obj = entry.get("license")
                if isinstance(lic_obj, dict):
                    val = lic_obj.get("id") or lic_obj.get("name")
                    if isinstance(val, str) and val.strip():
                        extracted.append(val.strip())
                elif isinstance(entry.get("expression"), str) and entry["expression"].strip():
                    extracted.append(entry["expression"].strip())
            elif isinstance(entry, str) and entry.strip():
                extracted.append(entry.strip())
    return extracted


def _extract_ecosystem_from_component(comp: dict[str, Any]) -> str:
    purl = str(comp.get("purl") or "")
    if purl.startswith("pkg:"):
        after_pkg = purl[4:]
        eco = after_pkg.split("/", 1)[0].strip().lower()
        if eco:
            return eco
    for prop in comp.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") in (
            "aquasecurity:trivy:PkgType",
            "veritas:ecosystem",
        ):
            return str(prop.get("value") or "generic").lower()
    return str(comp.get("type") or "library").lower()


def _extract_source_file_from_component(comp: dict[str, Any]) -> str:
    for prop in comp.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") in (
            "veritas:source_file",
            "aquasecurity:trivy:FilePath",
            "aquasecurity:trivy:SrcFile",
        ):
            val = str(prop.get("value") or "").strip()
            if val:
                return val
    return "SBOM/CycloneDX"


def analyze_cyclonedx_sbom(sbom_data: dict[str, Any]) -> SbomExecutionResult:
    """
    Analyzes a parsed CycloneDX JSON dict, classifies all component licenses,
    builds summary counters, and emits `trivy_license` findings for restricted copyleft packages.
    """
    spec_version_raw = str(sbom_data.get("specVersion") or "1.5")
    spec_version = (
        f"CycloneDX-{spec_version_raw}"
        if not spec_version_raw.startswith("CycloneDX")
        else spec_version_raw
    )

    raw_components = sbom_data.get("components")
    if not isinstance(raw_components, list):
        raw_components = []

    category_counts: dict[str, int] = {
        "permissive": 0,
        "weak_copyleft": 0,
        "restricted_copyleft": 0,
        "unknown": 0,
    }
    by_license: dict[str, int] = {}
    parsed_components: list[dict[str, Any]] = []
    license_findings: list[dict[str, Any]] = []
    policy_violations_count = 0

    tier_priority = {
        "restricted_copyleft": 4,
        "weak_copyleft": 3,
        "unknown": 2,
        "permissive": 1,
    }

    for comp in raw_components:
        if not isinstance(comp, dict):
            continue
        # Skip root application container component entries if present
        if comp.get("type") == "application" and not comp.get("purl"):
            continue

        name = str(comp.get("name") or "unknown").strip()
        version = str(comp.get("version") or "0.0.0").strip()
        purl = str(comp.get("purl") or f"pkg:generic/{name}@{version}").strip()
        ecosystem = _extract_ecosystem_from_component(comp)
        source_file = _extract_source_file_from_component(comp)
        licenses = _extract_component_licenses(comp)

        if not licenses:
            component_tier = "unknown"
            by_license["UNKNOWN"] = by_license.get("UNKNOWN", 0) + 1
        else:
            tiers = [classify_license_id(lic) for lic in licenses]
            component_tier = max(tiers, key=lambda t: tier_priority.get(t, 0))
            for lic in licenses:
                by_license[lic] = by_license.get(lic, 0) + 1

        category_counts[component_tier] = category_counts.get(component_tier, 0) + 1

        parsed_components.append(
            {
                "name": name,
                "version": version,
                "purl": purl,
                "ecosystem": ecosystem,
                "licenses": licenses if licenses else ["UNKNOWN"],
                "risk_tier": component_tier,
                "source_file": source_file,
            }
        )

        if component_tier == "restricted_copyleft":
            policy_violations_count += 1
            restricted_lics = [
                lic for lic in licenses if classify_license_id(lic) == "restricted_copyleft"
            ] or licenses
            lic_display = ", ".join(restricted_lics)
            fp_seed = f"license|{source_file}|{ecosystem}:{name}@{version}|{lic_display}"
            fingerprint = hashlib.sha256(fp_seed.encode("utf-8")).hexdigest()[:32]

            license_findings.append(
                CorrelatedFinding(
                    {
                        "engine": "trivy_license",
                        "category": "license",
                        "vuln_family": "license",
                        "severity": "high",
                        "cwe": "CWE-1104",
                        "owasp": "A06:2021-Vulnerable and Outdated Components",
                        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                        "rule_id": f"LICENSE-RESTRICTED-{restricted_lics[0].upper()}",
                        "title": f"Restricted Copyleft License Detected: {name}@{version} ({lic_display})",
                        "description": (
                            f"Component '{name}' version '{version}' ({ecosystem}) is distributed under "
                            f"a restricted copyleft license ({lic_display}). Distributing or linking against "
                            f"strong copyleft dependencies in proprietary SaaS or commercial binaries may "
                            f"trigger mandatory source code disclosure obligations."
                        ),
                        "message": (
                            f"Component '{name}' version '{version}' ({ecosystem}) is distributed under "
                            f"a restricted copyleft license ({lic_display})."
                        ),
                        "remediation": (
                            f"Replace '{name}@{version}' with a permissive alternative (MIT, Apache-2.0, BSD) "
                            f"or obtain legal approval and commercial dual-licensing."
                        ),
                        "countermeasure": (
                            f"Replace '{name}@{version}' with a permissive alternative (MIT, Apache-2.0, BSD) "
                            f"or obtain legal approval and commercial dual-licensing."
                        ),
                        "file_path": source_file,
                        "line_number": 1,
                        "line_start": 1,
                        "package_name": name,
                        "installed_version": version,
                        "ecosystem": ecosystem,
                        "confidence_level": "high",
                        "fingerprint": fingerprint,
                    }
                )
            )

    license_summary = {
        "permissive": category_counts["permissive"],
        "weak_copyleft": category_counts["weak_copyleft"],
        "restricted_copyleft": category_counts["restricted_copyleft"],
        "unknown": category_counts["unknown"],
        "by_license": dict(sorted(by_license.items(), key=lambda kv: (-kv[1], kv[0]))),
    }

    sbom_json_str = json.dumps(sbom_data, indent=2)
    return SbomExecutionResult(
        spec_version=spec_version,
        component_count=len(parsed_components),
        policy_violations_count=policy_violations_count,
        license_summary=license_summary,
        components=parsed_components,
        sbom_dict=sbom_data,
        sbom_json=sbom_json_str,
        license_findings=license_findings,
    )


def generate_and_persist_sbom(
    db: Session,
    scan_id: Any,
    project_id: Any,
    repo_workdir: str | Path,
) -> SbomExecutionResult:
    """
    Runs Trivy in CycloneDX SBOM + license scanner mode on `repo_workdir` (falling back
    to the deterministic manifest parser if `trivy` is not installed or fails),
    persists `ScanSbomArtifact`, and returns the result + any `trivy_license` findings.
    """
    workdir_str = str(repo_workdir)
    sbom_data: dict[str, Any] | None = None

    trivy_bin = shutil.which("trivy")
    if trivy_bin:
        fd, tmp_sbom_path = tempfile.mkstemp(prefix=f"veritas-sbom-{scan_id}-", suffix=".cdx.json")
        os.close(fd)
        try:
            cmd = [
                trivy_bin,
                "fs",
                "--format",
                "cyclonedx",
                "--scanners",
                "license",
                "--quiet",
                "--output",
                tmp_sbom_path,
                workdir_str,
            ]
            proc = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            if proc.returncode == 0 and os.path.exists(tmp_sbom_path) and os.path.getsize(tmp_sbom_path) > 0:
                with open(tmp_sbom_path, "r", encoding="utf-8", errors="replace") as f:
                    parsed = json.load(f)
                if isinstance(parsed, dict) and parsed.get("bomFormat") == "CycloneDX":
                    sbom_data = parsed
        except Exception as exc:
            logger.warning("Trivy CycloneDX CLI execution failed; using fallback manifest parser: %s", exc)
        finally:
            try:
                if os.path.exists(tmp_sbom_path):
                    os.remove(tmp_sbom_path)
            except OSError:
                pass

    if sbom_data is None:
        sbom_data = _parse_manifests_fallback(workdir_str)

    result = analyze_cyclonedx_sbom(sbom_data)

    # Upsert ScanSbomArtifact record for this scan
    existing = (
        db.query(ScanSbomArtifact)
        .filter(ScanSbomArtifact.scan_id == str(scan_id))
        .first()
    )
    if existing is None:
        artifact = ScanSbomArtifact(
            scan_id=str(scan_id),
            project_id=str(project_id),
            spec_version=result.spec_version,
            component_count=result.component_count,
            license_summary_json=json.dumps(result.license_summary),
            policy_violations_count=result.policy_violations_count,
            sbom_json=result.sbom_json,
        )
        db.add(artifact)
    else:
        existing.spec_version = result.spec_version
        existing.component_count = result.component_count
        existing.license_summary_json = json.dumps(result.license_summary)
        existing.policy_violations_count = result.policy_violations_count
        existing.sbom_json = result.sbom_json

    db.commit()
    return result


def run_trivy_sbom(
    db: Session,
    *,
    scan_id: str,
    project_id: str,
    workdir: Path | str | None,
) -> tuple[SbomExecutionResult, dict[str, Any]]:
    """
    Scan engine wrapper invoked by `scan_runner.py`.
    Runs CycloneDX SBOM + license governance and returns (result, engine_meta).
    """
    if not workdir or not Path(workdir).exists():
        empty_res = analyze_cyclonedx_sbom(
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        )
        return empty_res, {"available": False, "engine": "trivy_sbom", "skipped": "no repository workspace"}
    try:
        res = generate_and_persist_sbom(
            db=db,
            scan_id=scan_id,
            project_id=project_id,
            repo_workdir=workdir,
        )
        meta = {
            "available": True,
            "engine": "trivy_sbom",
            "spec_version": res.spec_version,
            "component_count": res.component_count,
            "policy_violations_count": res.policy_violations_count,
        }
        return res, meta
    except Exception as exc:
        logger.warning("SBOM generation failed: %s", exc)
        empty_res = analyze_cyclonedx_sbom(
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        )
        return empty_res, {"available": False, "engine": "trivy_sbom", "error": str(exc)[:200]}
