from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

CVE_REGEX = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
GHSA_REGEX = re.compile(r"\b(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", re.IGNORECASE)
CWE_REGEX = re.compile(r"\bCWE-(\d{1,5})\b", re.IGNORECASE)

SCA_ENGINES = {"osv-scanner", "osv_scanner", "pip-audit", "pip_audit", "trivy", "trivy_sca"}
SECRET_ENGINES = {"gitleaks", "trufflehog", "detect-secrets", "detect_secrets"}
SAST_IAC_ENGINES = {
    "semgrep",
    "bandit",
    "njsscan",
    "shellcheck",
    "checkov",
    "hadolint",
    "openrouter_review",
}

SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
}

CONFIDENCE_RANK: dict[str, int] = {
    "high": 3,
    "medium": 2,
    "low": 1,
}


class CorrelatedFinding(dict):
    """
    Hybrid dictionary and object that satisfies both dict-access tests (f["cve_id"])
    and normalized object access (nf.engine, nf.file_path, nf.risk_score()) used in scan_runner.
    """

    @property
    def engine(self) -> str:
        return str(self.get("engine") or "unknown")

    @engine.setter
    def engine(self, val: str) -> None:
        self["engine"] = val

    @property
    def severity(self) -> str:
        return str(self.get("severity") or "info")

    @severity.setter
    def severity(self, val: str) -> None:
        self["severity"] = val

    @property
    def vuln_family(self) -> str:
        return str(self.get("category") or self.get("vuln_family") or "other")

    @vuln_family.setter
    def vuln_family(self, val: str) -> None:
        self["vuln_family"] = val
        self["category"] = val

    @property
    def title(self) -> str:
        return str(self.get("title") or self.get("rule_id") or "Finding")

    @title.setter
    def title(self, val: str) -> None:
        self["title"] = val

    @property
    def message(self) -> str | None:
        return self.get("description") or self.get("message")

    @message.setter
    def message(self, val: str | None) -> None:
        self["message"] = val
        self["description"] = val

    @property
    def rule_id(self) -> str | None:
        return self.get("rule_id") or self.get("cve_id")

    @rule_id.setter
    def rule_id(self, val: str | None) -> None:
        self["rule_id"] = val

    @property
    def cwe(self) -> str | None:
        return self.get("cwe")

    @cwe.setter
    def cwe(self, val: str | None) -> None:
        self["cwe"] = val

    @property
    def owasp_category(self) -> str | None:
        return self.get("owasp_category") or self.get("owasp")

    @owasp_category.setter
    def owasp_category(self, val: str | None) -> None:
        self["owasp_category"] = val
        self["owasp"] = val

    @property
    def file_path(self) -> str | None:
        return self.get("file_path") or self.get("path")

    @file_path.setter
    def file_path(self, val: str | None) -> None:
        self["file_path"] = val
        self["path"] = val

    @property
    def line_start(self) -> int | None:
        return self.get("line_number") or self.get("line_start") or self.get("line")

    @line_start.setter
    def line_start(self, val: int | None) -> None:
        self["line_start"] = val
        self["line_number"] = val

    @property
    def line_end(self) -> int | None:
        return self.get("line_end")

    @line_end.setter
    def line_end(self, val: int | None) -> None:
        self["line_end"] = val

    @property
    def snippet(self) -> str | None:
        return self.get("code_snippet") or self.get("snippet")

    @snippet.setter
    def snippet(self, val: str | None) -> None:
        self["snippet"] = val
        self["code_snippet"] = val

    @property
    def raw(self) -> dict:
        return self

    @raw.setter
    def raw(self, val: Any) -> None:
        if isinstance(val, dict):
            self.update(val)

    def risk_score(self, *, criticality: str = "medium") -> float:
        score = self.get("effective_priority_score") or self.get("risk_score")
        if score is not None:
            return float(score)
        base = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0}.get(
            self.severity.lower(), 1.0
        )
        weight = {"low": 0.85, "medium": 1.0, "high": 1.15}.get((criticality or "medium").lower(), 1.0)
        return round(min(10.0, base * weight), 2)

    def fingerprint(self) -> str:
        return str(self.get("fingerprint") or self.get("canonical_fingerprint") or "")


def to_correlated_finding(item: Any) -> CorrelatedFinding:
    if isinstance(item, CorrelatedFinding):
        return item
    if isinstance(item, dict):
        return CorrelatedFinding(item)
    raw_dict = getattr(item, "raw", None)
    d = dict(raw_dict) if isinstance(raw_dict, dict) else {}
    for attr in (
        "engine",
        "vuln_family",
        "severity",
        "title",
        "message",
        "rule_id",
        "cwe",
        "owasp_category",
        "file_path",
        "line_start",
        "line_end",
        "snippet",
    ):
        val = getattr(item, attr, None)
        if val is not None and attr not in d:
            d[attr] = val
    if "vuln_family" in d and "category" not in d:
        d["category"] = d["vuln_family"]
    if "message" in d and "description" not in d:
        d["description"] = d["message"]
    if "line_start" in d and "line_number" not in d:
        d["line_number"] = d["line_start"]
    if "snippet" in d and "code_snippet" not in d:
        d["code_snippet"] = d["snippet"]
    if hasattr(item, "fingerprint") and "fingerprint" not in d:
        try:
            d["fingerprint"] = item.fingerprint()
        except Exception:
            pass
    return CorrelatedFinding(d)


@dataclass
class CorrelationSummary:
    raw_findings_count: int
    correlated_findings_count: int
    deduplicated_count: int
    multi_engine_confirmed_count: int
    findings: list[CorrelatedFinding] = field(default_factory=list)


def normalize_rel_path(file_path: str | None) -> str:
    if not file_path:
        return "unknown"
    cleaned = file_path.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip("/")
    return cleaned or "unknown"


def normalize_engine_name(engine: str | None) -> str:
    if not engine:
        return "unknown"
    return engine.strip().lower()


def normalize_severity(severity: str | None) -> str:
    if not severity:
        return "medium"
    s = severity.strip().lower()
    if s in ("critical", "crit"):
        return "critical"
    if s in ("high", "error"):
        return "high"
    if s in ("medium", "moderate", "warning", "warn"):
        return "medium"
    if s in ("low",):
        return "low"
    if s in ("info", "informational", "note"):
        return "info"
    return "medium"


def normalize_confidence(confidence: str | None) -> str:
    if not confidence:
        return "medium"
    c = confidence.strip().lower()
    if c in ("high", "confirmed", "verified"):
        return "high"
    if c in ("low",):
        return "low"
    return "medium"


def extract_primary_cve(raw: dict[str, Any]) -> str | None:
    """
    Inspect explicit fields (`cve_id`, `cve`, `rule_id`, `aliases`, `title`, `description`)
    and return the canonical uppercase `CVE-YYYY-NNNNN` if present.
    """
    candidates: list[str] = []

    for key in ("cve_id", "cve", "advisory_id", "vulnerability_id", "rule_id", "id"):
        val = raw.get(key)
        if isinstance(val, str):
            candidates.append(val)

    aliases = raw.get("aliases")
    if isinstance(aliases, (list, tuple, set)):
        for item in aliases:
            if isinstance(item, str):
                candidates.append(item)
    elif isinstance(aliases, str):
        candidates.append(aliases)

    for key in ("title", "description", "message"):
        val = raw.get(key)
        if isinstance(val, str):
            candidates.append(val)

    for text_item in candidates:
        match = CVE_REGEX.search(text_item)
        if match:
            return match.group(1).upper()

    return None


def extract_primary_advisory_id(raw: dict[str, Any]) -> str:
    cve = extract_primary_cve(raw)
    if cve:
        return cve

    candidates: list[str] = []
    for key in ("advisory_id", "vulnerability_id", "rule_id", "id", "title"):
        val = raw.get(key)
        if isinstance(val, str):
            candidates.append(val)

    aliases = raw.get("aliases")
    if isinstance(aliases, (list, tuple, set)):
        candidates.extend(str(a) for a in aliases if a)

    for text_item in candidates:
        ghsa_match = GHSA_REGEX.search(text_item)
        if ghsa_match:
            return ghsa_match.group(1).upper()

    for key in ("rule_id", "advisory_id", "id", "title"):
        val = raw.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip().upper()

    return "UNKNOWN-ADVISORY"


def extract_canonical_cwe(raw: dict[str, Any]) -> str | None:
    for key in ("cwe", "cwe_id", "rule_id", "title", "description"):
        val = raw.get(key)
        if isinstance(val, str):
            match = CWE_REGEX.search(val)
            if match:
                return f"CWE-{int(match.group(1))}"
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    match = CWE_REGEX.search(item)
                    if match:
                        return f"CWE-{int(match.group(1))}"
    return None


def infer_sca_package_coordinates(raw: dict[str, Any]) -> tuple[str, str, str]:
    """
    Returns `(ecosystem, package_name_lower, installed_version)` from structured
    fields or falls back to parsing title/description/file_path patterns.
    """
    ecosystem = str(raw.get("ecosystem") or "").strip().lower()
    pkg_name = str(
        raw.get("package_name") or raw.get("package") or raw.get("pkg_name") or ""
    ).strip().lower()
    installed_version = str(
        raw.get("installed_version") or raw.get("version") or raw.get("pkg_version") or ""
    ).strip().lower()

    file_path = normalize_rel_path(raw.get("file_path") or raw.get("path"))
    if not ecosystem:
        if file_path.endswith(("requirements.txt", "pipfile.lock", "poetry.lock", "pyproject.toml")):
            ecosystem = "pypi"
        elif file_path.endswith(("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
            ecosystem = "npm"
        elif file_path.endswith(("go.mod", "go.sum")):
            ecosystem = "go"
        elif file_path.endswith(("cargo.toml", "cargo.lock")):
            ecosystem = "cargo"
        else:
            ecosystem = "generic"

    if not pkg_name or not installed_version:
        text_blob = f"{raw.get('title', '')} {raw.get('description', '')}"
        at_match = re.search(r"\b([a-zA-Z0-9_.\-]+)@([0-9][a-zA-Z0-9_.\-+]*)\b", text_blob)
        if at_match:
            if not pkg_name:
                pkg_name = at_match.group(1).lower()
            if not installed_version:
                installed_version = at_match.group(2).lower()
        else:
            in_match = re.search(
                r"\b([a-zA-Z0-9_.\-]+)\s+\(?([0-9]+\.[0-9]+(?:\.[0-9a-zA-Z.\-]+)?)\)?",
                text_blob,
            )
            if in_match:
                if not pkg_name:
                    pkg_name = in_match.group(1).lower()
                if not installed_version:
                    installed_version = in_match.group(2).lower()

    return (
        ecosystem or "generic",
        pkg_name or "unknown-pkg",
        installed_version or "unknown-ver",
    )


def infer_secret_family(raw: dict[str, Any]) -> str:
    text_blob = " ".join(
        str(raw.get(k) or "") for k in ("secret_type", "rule_id", "title", "description")
    ).lower()
    if "aws" in text_blob:
        return "aws-credential"
    if "github" in text_blob or "ghp_" in text_blob:
        return "github-token"
    if "slack" in text_blob:
        return "slack-token"
    if "stripe" in text_blob:
        return "stripe-key"
    if "private" in text_blob and "key" in text_blob:
        return "private-key"
    if "jwt" in text_blob:
        return "jwt-secret"
    if "postgres" in text_blob or "mysql" in text_blob or "mongodb" in text_blob or "database" in text_blob:
        return "database-uri"
    return "generic-secret"


def compute_raw_fingerprint(raw: dict[str, Any]) -> str:
    """
    Preserves existing raw fingerprint if already generated by the engine runner,
    or computes a deterministic SHA-256 fingerprint.
    """
    existing = raw.get("fingerprint")
    if isinstance(existing, str) and existing.strip():
        return existing.strip()

    engine = normalize_engine_name(raw.get("engine"))
    file_path = normalize_rel_path(raw.get("file_path") or raw.get("path"))
    rule_id = str(raw.get("rule_id") or raw.get("cve_id") or raw.get("title") or "rule").strip()
    line = int(raw.get("line_number") or raw.get("line") or raw.get("start_line") or 0)
    raw_str = f"{engine}|{file_path}|{rule_id}|{line}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:32]


def compute_canonical_fingerprint(
    category: str,
    file_path: str,
    canonical_rule_or_cve: str,
    line_or_pkg: str,
) -> str:
    payload = f"{category.lower()}|{normalize_rel_path(file_path)}|{canonical_rule_or_cve.upper()}|{line_or_pkg.lower()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _classify_category(raw: dict[str, Any], engine: str) -> str:
    cat = str(raw.get("category") or "").strip().lower()
    if cat in ("sca", "dependency", "dependencies", "vuln"):
        return "sca"
    if cat in ("secret", "secrets"):
        return "secret"
    if cat in ("license", "sbom"):
        return "license"
    if cat in ("iac", "container", "dockerfile"):
        return "iac"
    if cat in ("sast", "code", "ai_review"):
        return "sast"

    if engine in SCA_ENGINES:
        return "sca"
    if engine in SECRET_ENGINES:
        return "secret"
    if engine == "trivy_license":
        return "license"
    if engine in ("checkov", "hadolint"):
        return "iac"
    return "sast"


def build_correlation_key(raw: dict[str, Any]) -> tuple[str, ...]:
    engine = normalize_engine_name(raw.get("engine"))
    category = _classify_category(raw, engine)
    file_path = normalize_rel_path(raw.get("file_path") or raw.get("path"))
    line_number = int(raw.get("line_number") or raw.get("line") or raw.get("start_line") or 0)

    if category == "sca":
        ecosystem, pkg_name, installed_ver = infer_sca_package_coordinates(raw)
        advisory_id = extract_primary_advisory_id(raw)
        return ("sca", ecosystem, pkg_name, installed_ver, advisory_id)

    if category == "secret":
        snippet = str(raw.get("code_snippet") or raw.get("snippet") or raw.get("match") or "").strip()
        if snippet and line_number > 0:
            snippet_hash = hashlib.sha256(snippet.encode("utf-8")).hexdigest()[:16]
            return ("secret_snippet", file_path, str(line_number), snippet_hash)
        secret_family = infer_secret_family(raw)
        return ("secret_loc", file_path, str(line_number), secret_family)

    if category == "license":
        ecosystem, pkg_name, installed_ver = infer_sca_package_coordinates(raw)
        rule_id = str(raw.get("rule_id") or raw.get("title") or "license").strip().lower()
        return ("license", ecosystem, pkg_name, installed_ver, rule_id)

    # SAST & IaC correlation: bucket by (file_path, line // 3, canonical_cwe_id) when CWE is known
    cwe_id = extract_canonical_cwe(raw)
    if cwe_id and line_number > 0:
        line_bucket = line_number // 3
        return ("sast_cwe", file_path, str(line_bucket), cwe_id)

    rule_id = str(raw.get("rule_id") or raw.get("title") or "generic-rule").strip().lower()
    return ("sast_rule", engine, file_path, str(line_number), rule_id)


def _merge_finding_group(
    corr_key: tuple[str, ...],
    group: list[dict[str, Any]],
    suppressed_fingerprints: set[str],
) -> dict[str, Any]:
    """
    Merges 1..N raw findings sharing `corr_key` into a single canonical finding dict.
    """
    # Sort group so highest severity and longest description come first for base selection
    sorted_group = sorted(
        group,
        key=lambda item: (
            SEVERITY_RANK.get(normalize_severity(item.get("severity")), 0),
            len(str(item.get("description") or "")),
        ),
        reverse=True,
    )
    primary = dict(sorted_group[0])

    matched_engines = sorted(
        {str(item.get("engine") or "").strip() for item in group if item.get("engine")}
    )
    if not matched_engines:
        matched_engines = ["unknown"]
    engine_count = len(matched_engines)

    # Highest severity across all engines
    best_severity = max(
        (normalize_severity(item.get("severity")) for item in group),
        key=lambda sev: SEVERITY_RANK.get(sev, 0),
    )

    # Longest, most informative description
    best_description = max(
        (str(item.get("description") or item.get("message") or "").strip() for item in group),
        key=len,
        default="",
    )

    # Combine distinct remediation guidance & fix versions
    remediations: list[str] = []
    fix_versions: set[str] = set()
    for item in sorted_group:
        rem = str(
            item.get("remediation")
            or item.get("recommendation")
            or item.get("countermeasure")
            or item.get("fix")
            or ""
        ).strip()
        if rem and rem not in remediations:
            remediations.append(rem)
        item_raw = item.get("raw") if isinstance(item.get("raw"), dict) else (item if isinstance(item, dict) else {})
        candidates = [
            item.get("fixed_version"),
            item.get("fix_version"),
            item_raw.get("FixedVersion"),
            item_raw.get("fixed_version"),
            item_raw.get("fix_version"),
        ]
        for c in candidates:
            if c and str(c).strip():
                fix_versions.add(str(c).strip())
        raw_fvs = item_raw.get("fix_versions") or item.get("fix_versions")
        if isinstance(raw_fvs, (list, set, tuple)):
            for fv in raw_fvs:
                if fv and str(fv).strip():
                    fix_versions.add(str(fv).strip())

    merged_remediation = " | ".join(remediations)
    if fix_versions:
        sorted_fixes = sorted(fix_versions)
        fix_clause = f"Upgrade to fixed version(s): {', '.join(sorted_fixes)}."
        if fix_clause not in merged_remediation:
            merged_remediation = (
                f"{merged_remediation} ({fix_clause})".strip()
                if merged_remediation
                else fix_clause
            )
        if not any(fv in best_description for fv in sorted_fixes):
            best_description = f"{best_description} (Fixed in: {', '.join(sorted_fixes)})".strip()

    # Extract CVE & CWE
    cve_id: str | None = None
    cwe_id: str | None = None
    for item in sorted_group:
        if not cve_id:
            cve_id = extract_primary_cve(item)
        if not cwe_id:
            cwe_id = extract_canonical_cwe(item)

    # Determine confidence level
    has_trufflehog_verified = any(
        normalize_engine_name(item.get("engine")) == "trufflehog"
        and (
            bool(item.get("verified"))
            or normalize_confidence(item.get("confidence_level") or item.get("confidence")) == "high"
        )
        for item in group
    )
    if engine_count >= 2 or has_trufflehog_verified or bool(primary.get("is_kev")):
        confidence_level = "high"
    else:
        confidence_level = max(
            (
                normalize_confidence(item.get("confidence_level") or item.get("confidence"))
                for item in group
            ),
            key=lambda c: CONFIDENCE_RANK.get(c, 2),
        )

    category = _classify_category(primary, matched_engines[0])
    file_path = normalize_rel_path(primary.get("file_path") or primary.get("path"))
    line_number = int(
        primary.get("line_number") or primary.get("line") or primary.get("start_line") or 0
    )

    # Build deterministic canonical fingerprint while checking all constituent raw fingerprints
    constituent_fps = {compute_raw_fingerprint(item) for item in group}
    if category == "sca":
        ecosystem, pkg_name, installed_ver = infer_sca_package_coordinates(primary)
        canonical_rule = cve_id or extract_primary_advisory_id(primary)
        line_or_pkg = f"{ecosystem}:{pkg_name}@{installed_ver}"
    elif category == "secret":
        canonical_rule = infer_secret_family(primary)
        line_or_pkg = str(line_number)
    else:
        canonical_rule = cwe_id or str(primary.get("rule_id") or primary.get("title") or "rule")
        line_or_pkg = str(line_number)

    canonical_fp = compute_canonical_fingerprint(
        category=category,
        file_path=file_path,
        canonical_rule_or_cve=canonical_rule,
        line_or_pkg=line_or_pkg,
    )

    # Backward compatibility: if only 1 engine detected the finding and it already had a fingerprint,
    # preserve its original fingerprint unless a suppression matches the canonical fingerprint.
    raw_primary_fp = compute_raw_fingerprint(primary)
    if engine_count == 1 and primary.get("fingerprint"):
        final_fingerprint = str(primary["fingerprint"])
    else:
        final_fingerprint = canonical_fp

    # If ANY constituent raw fingerprint or canonical fingerprint is in FindingSuppression,
    # mark suppressed and align fingerprint with the matched suppression record.
    matched_suppression_fp = next(
        (fp for fp in (constituent_fps | {canonical_fp, raw_primary_fp}) if fp in suppressed_fingerprints),
        None,
    )
    is_suppressed = bool(primary.get("is_suppressed") or primary.get("suppressed")) or (
        matched_suppression_fp is not None
    )
    if matched_suppression_fp:
        final_fingerprint = matched_suppression_fp

    primary["engine"] = matched_engines[0] if engine_count == 1 else ",".join(matched_engines)
    primary["category"] = category
    primary["file_path"] = file_path
    primary["line_number"] = line_number
    primary["severity"] = best_severity
    primary["description"] = best_description or str(primary.get("title") or "")
    primary["message"] = primary["description"]
    if merged_remediation:
        primary["remediation"] = merged_remediation
        primary["countermeasure"] = merged_remediation
    if cve_id:
        primary["cve_id"] = cve_id
    else:
        primary["cve_id"] = None
    if cwe_id and not primary.get("cwe"):
        primary["cwe"] = cwe_id

    primary["matched_engines"] = matched_engines
    primary["matched_engines_json"] = json.dumps(matched_engines)
    primary["engine_count"] = engine_count
    primary["confidence_level"] = confidence_level
    primary["fingerprint"] = final_fingerprint
    primary["constituent_fingerprints"] = sorted(constituent_fps | {canonical_fp})
    primary["is_suppressed"] = is_suppressed
    if is_suppressed:
        primary["status"] = "false_positive"

    return CorrelatedFinding(primary)


def correlate_findings(
    raw_findings: Iterable[Any],
    suppressed_fingerprints: set[str] | None = None,
) -> CorrelationSummary:
    """
    Entry point invoked by `ScanWorker` after all engines finish and before DB persistence.
    Groups duplicate findings across engines into canonical findings.
    """
    suppressed = suppressed_fingerprints or set()
    raw_list = [to_correlated_finding(f) for f in raw_findings]
    buckets: dict[tuple[str, ...], list[dict[str, Any]]] = {}

    for raw in raw_list:
        key = build_correlation_key(raw)
        buckets.setdefault(key, []).append(raw)

    correlated: list[CorrelatedFinding] = []
    multi_engine_count = 0

    for corr_key, group in buckets.items():
        merged = _merge_finding_group(corr_key, group, suppressed)
        if merged["engine_count"] >= 2:
            multi_engine_count += 1
        correlated.append(merged)

    return CorrelationSummary(
        raw_findings_count=len(raw_list),
        correlated_findings_count=len(correlated),
        deduplicated_count=max(0, len(raw_list) - len(correlated)),
        multi_engine_confirmed_count=multi_engine_count,
        findings=correlated,
    )
