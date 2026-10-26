from __future__ import annotations

import csv
import gzip
import io
import logging
import urllib.error
import urllib.parse
import urllib.request
import httpx
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.workspace import CveIntelCache
from app.services.correlator import (
    CorrelatedFinding,
    extract_primary_cve,
    normalize_severity,
    to_correlated_finding,
)

logger = logging.getLogger("veritas.threat_intel")

CISA_KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"
FIRST_EPSS_BULK_CSV_GZ_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

SEVERITY_BASE_SCORE: dict[str, float] = {
    "critical": 7.0,
    "high": 5.0,
    "medium": 3.0,
    "low": 1.5,
    "info": 0.5,
}

SEVERITY_SORT_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _http_get_bytes(url: str, timeout: float = 15.0) -> bytes:
    with httpx.Client(
        timeout=timeout,
        headers={
            "User-Agent": "VERITAS-DevSecOps-Platform/6.0 (+https://veritas.trackifyapp.co.in)",
            "Accept": "application/json, text/csv, application/gzip, */*",
        },
        follow_redirects=True,
    ) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.content


def compute_effective_priority_score(
    severity: str | None,
    is_kev: bool = False,
    epss_score: float | None = None,
    engine_count: int = 1,
) -> float:
    """
    Composite Priority Formula on a [0.0, 10.0] scale:
      - Base score by severity: critical=7.0, high=5.0, medium=3.0, low=1.5, info=0.5
      - If `is_kev is True`: severity floor is promoted to `critical` (7.0) and adds +2.5
      - Adds `min(1.5, (epss_score or 0.0) * 2.0)` for exploit probability
      - If `engine_count >= 2`: adds +0.5 for multi-engine confirmation
      - Clamped to [0.0, 10.0] rounded to 2 decimal places
    """
    norm_sev = "critical" if is_kev else normalize_severity(severity)
    base = SEVERITY_BASE_SCORE.get(norm_sev, 3.0)
    kev_boost = 2.5 if is_kev else 0.0
    epss_boost = min(1.5, max(0.0, float(epss_score or 0.0)) * 2.0)
    engine_boost = 0.5 if int(engine_count or 1) >= 2 else 0.0

    raw_score = base + kev_boost + epss_boost + engine_boost
    return round(min(10.0, max(0.0, raw_score)), 2)


def sync_cisa_kev_feed(db: Session, timeout: float = 15.0) -> int:
    """
    Fetches the public CISA Known Exploited Vulnerabilities JSON catalog and upserts
    entries into `CveIntelCache`. Fail-open: returns 0 on network or parse failure.
    """
    try:
        raw_bytes = _http_get_bytes(CISA_KEV_FEED_URL, timeout=timeout)
        payload = json.loads(raw_bytes.decode("utf-8"))
        vulnerabilities = payload.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return 0
    except Exception as exc:
        logger.warning("CISA KEV feed sync skipped/failed (fail-open): %s", exc)
        return 0

    now = _utcnow()
    existing_map: dict[str, CveIntelCache] = {
        row.cve_id: row for row in db.query(CveIntelCache).all()
    }

    upserted = 0
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue

        row = existing_map.get(cve_id)
        if row is None:
            row = CveIntelCache(cve_id=cve_id)
            db.add(row)
            existing_map[cve_id] = row

        row.is_kev = True
        row.kev_vendor = str(item.get("vendorProject") or "")[:255] or None
        row.kev_product = str(item.get("product") or "")[:255] or None
        row.kev_date_added = str(item.get("dateAdded") or "")[:32] or None
        row.kev_due_date = str(item.get("dueDate") or "")[:32] or None
        row.kev_ransomware_use = str(item.get("knownRansomwareCampaignUse") or "")[:64] or None
        row.updated_at = now
        upserted += 1

    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("Database commit failed during CISA KEV sync: %s", exc)
        return 0

    return upserted


def sync_epss_batch(
    db: Session,
    cve_ids: list[str],
    timeout: float = 5.0,
) -> int:
    """
    Queries the FIRST EPSS REST API in batches of up to 100 CVEs and upserts
    `epss_score` and `epss_percentile` into `CveIntelCache`. Fail-open on any error.
    """
    normalized_cves = sorted(
        {cve.strip().upper() for cve in cve_ids if cve and cve.strip().upper().startswith("CVE-")}
    )
    if not normalized_cves:
        return 0

    now = _utcnow()
    updated_count = 0
    batch_size = 100

    for idx in range(0, len(normalized_cves), batch_size):
        chunk = normalized_cves[idx : idx + batch_size]
        query_param = ",".join(chunk)
        url = f"{FIRST_EPSS_API_URL}?{urllib.parse.urlencode({'cve': query_param})}"

        try:
            raw_bytes = _http_get_bytes(url, timeout=timeout)
            payload = json.loads(raw_bytes.decode("utf-8"))
            data_rows = payload.get("data", [])
            if not isinstance(data_rows, list):
                continue
        except Exception as exc:
            logger.warning("FIRST EPSS batch query failed for %d CVEs (fail-open): %s", len(chunk), exc)
            continue

        existing_rows = {
            row.cve_id: row
            for row in db.query(CveIntelCache).filter(CveIntelCache.cve_id.in_(chunk)).all()
        }

        for entry in data_rows:
            if not isinstance(entry, dict):
                continue
            cve_id = str(entry.get("cve") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue

            try:
                epss_val = float(entry["epss"]) if entry.get("epss") is not None else None
                pct_val = float(entry["percentile"]) if entry.get("percentile") is not None else None
            except (TypeError, ValueError):
                continue

            row = existing_rows.get(cve_id)
            if row is None:
                row = CveIntelCache(cve_id=cve_id, is_kev=False)
                db.add(row)
                existing_rows[cve_id] = row

            row.epss_score = epss_val
            row.epss_percentile = pct_val
            row.updated_at = now
            updated_count += 1

    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("Database commit failed during FIRST EPSS batch sync: %s", exc)
        return 0

    return updated_count


def sync_epss_bulk_csv_for_cached_cves(db: Session, timeout: float = 15.0) -> int:
    """
    Streams `epss_scores-current.csv.gz` and updates EPSS scores for all CVEs currently
    present in `CveIntelCache` (such as KEV entries) without loading 250k rows into memory.
    Falls back to `sync_epss_batch` if the gzip stream is unreachable.
    """
    cached_cves = {row.cve_id: row for row in db.query(CveIntelCache).all()}
    if not cached_cves:
        return 0

    try:
        raw_gz = _http_get_bytes(FIRST_EPSS_BULK_CSV_GZ_URL, timeout=timeout)
        now = _utcnow()
        updated = 0
        with gzip.GzipFile(fileobj=io.BytesIO(raw_gz), mode="rb") as gz_file:
            text_stream = io.TextIOWrapper(gz_file, encoding="utf-8", errors="replace")
            reader = csv.reader(
                line for line in text_stream if line and not line.startswith("#")
            )
            header = next(reader, None)
            if not header:
                return 0
            for parts in reader:
                if len(parts) < 3:
                    continue
                cve_id = parts[0].strip().upper()
                row = cached_cves.get(cve_id)
                if row is None:
                    continue
                try:
                    row.epss_score = float(parts[1])
                    row.epss_percentile = float(parts[2])
                    row.updated_at = now
                    updated += 1
                except ValueError:
                    continue

        db.commit()
        return updated
    except Exception as exc:
        logger.info("Bulk EPSS CSV stream skipped (%s); falling back to batched API sync.", exc)
        return sync_epss_batch(db, list(cached_cves.keys()), timeout=timeout)


def sync_threat_intel_feeds(
    db: Session,
    cve_ids: list[str] | None = None,
    include_bulk_epss: bool = False,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """
    Synchronizes CISA KEV and FIRST EPSS feeds into `CveIntelCache`.
    Never raises unhandled exceptions (strictly fail-open).
    """
    kev_synced = sync_cisa_kev_feed(db, timeout=timeout)
    epss_synced = 0

    if cve_ids:
        epss_synced += sync_epss_batch(db, cve_ids, timeout=5.0)
    elif include_bulk_epss:
        epss_synced += sync_epss_bulk_csv_for_cached_cves(db, timeout=15.0)
    else:
        # Refresh EPSS for KEV CVEs missing EPSS scores
        missing_epss_cves = [
            row.cve_id
            for row in db.query(CveIntelCache)
            .filter(CveIntelCache.is_kev.is_(True), CveIntelCache.epss_score.is_(None))
            .limit(300)
            .all()
        ]
        if missing_epss_cves:
            epss_synced += sync_epss_batch(db, missing_epss_cves, timeout=5.0)

    status = get_threat_intel_status(db)
    status["kev_upserted"] = kev_synced
    status["epss_upserted"] = epss_synced
    return status


def get_threat_intel_status(db: Session) -> dict[str, Any]:
    total_cached = db.query(func.count(CveIntelCache.cve_id)).scalar() or 0
    total_kev = (
        db.query(func.count(CveIntelCache.cve_id))
        .filter(CveIntelCache.is_kev.is_(True))
        .scalar()
        or 0
    )
    last_updated: datetime | None = db.query(func.max(CveIntelCache.updated_at)).scalar()
    last_synced_iso = _ensure_aware_utc(last_updated).isoformat() if last_updated else None
    return {
        "total_cached_cves": int(total_cached),
        "total_kev_cves": int(total_kev),
        "last_synced_at": last_synced_iso,
    }


def enrich_findings_with_intel(
    db: Session,
    findings: list[Any],
    auto_fetch_missing_epss: bool = True,
    *,
    allow_network: bool | None = None,
) -> list[CorrelatedFinding]:
    """
    Enriches correlated finding dicts in-place with CISA KEV and FIRST EPSS intelligence,
    promotes KEV findings to `critical` severity, computes `effective_priority_score`,
    and sorts findings by `effective_priority_score DESC`.
    """
    if not findings:
        return []

    if allow_network is not None:
        auto_fetch_missing_epss = allow_network

    findings = [to_correlated_finding(f) for f in findings]
    now = _utcnow()
    stale_cutoff = now - timedelta(hours=24)

    # 1. If the local cache has never synced KEV or is older than 24h, attempt a background KEV sync
    latest_sync = _ensure_aware_utc(db.query(func.max(CveIntelCache.updated_at)).scalar())
    if auto_fetch_missing_epss and (latest_sync is None or latest_sync < stale_cutoff):
        sync_cisa_kev_feed(db, timeout=10.0)

    # 2. Collect all distinct CVE IDs across the scan findings
    distinct_cves: set[str] = set()
    for f in findings:
        cve = f.get("cve_id") or extract_primary_cve(f)
        if isinstance(cve, str) and cve.upper().startswith("CVE-"):
            norm_cve = cve.upper()
            f["cve_id"] = norm_cve
            distinct_cves.add(norm_cve)

    # 3. Query local CveIntelCache
    cache_map: dict[str, CveIntelCache] = {}
    if distinct_cves:
        rows = (
            db.query(CveIntelCache)
            .filter(CveIntelCache.cve_id.in_(sorted(distinct_cves)))
            .all()
        )
        cache_map = {row.cve_id: row for row in rows}

        # 4. Identify missing or stale (>24h) EPSS entries and perform one batched lookup
        if auto_fetch_missing_epss:
            missing_or_stale = [
                cve
                for cve in sorted(distinct_cves)
                if cve not in cache_map
                or cache_map[cve].epss_score is None
                or (
                    _ensure_aware_utc(cache_map[cve].updated_at) is not None
                    and _ensure_aware_utc(cache_map[cve].updated_at) < stale_cutoff
                )
            ]
            if missing_or_stale:
                sync_epss_batch(db, missing_or_stale, timeout=5.0)
                rows = (
                    db.query(CveIntelCache)
                    .filter(CveIntelCache.cve_id.in_(sorted(distinct_cves)))
                    .all()
                )
                cache_map = {row.cve_id: row for row in rows}

    # 5. Attach threat intel fields & calculate effective_priority_score
    for f in findings:
        cve_id = f.get("cve_id")
        intel = cache_map.get(cve_id) if cve_id else None

        is_kev = bool(f.get("is_kev")) or (bool(intel.is_kev) if intel else False)
        kev_due_date = f.get("kev_due_date") or (intel.kev_due_date if intel else None)
        epss_score = (
            float(intel.epss_score)
            if (intel and intel.epss_score is not None)
            else (float(f["epss_score"]) if f.get("epss_score") is not None else None)
        )
        epss_percentile = (
            float(intel.epss_percentile)
            if (intel and intel.epss_percentile is not None)
            else (float(f["epss_percentile"]) if f.get("epss_percentile") is not None else None)
        )

        if is_kev:
            f["severity"] = "critical"
            f["confidence_level"] = "high"

        engine_count = int(f.get("engine_count") or 1)
        priority_score = compute_effective_priority_score(
            severity=f.get("severity"),
            is_kev=is_kev,
            epss_score=epss_score,
            engine_count=engine_count,
        )

        f["is_kev"] = is_kev
        f["kev_due_date"] = kev_due_date
        f["epss_score"] = epss_score
        f["epss_percentile"] = epss_percentile
        f["effective_priority_score"] = priority_score

    # 6. Default sort by effective_priority_score DESC, then severity, then EPSS
    findings.sort(
        key=lambda item: (
            float(item.get("effective_priority_score") or 0.0),
            1 if item.get("is_kev") else 0,
            SEVERITY_SORT_ORDER.get(normalize_severity(item.get("severity")), 0),
            float(item.get("epss_score") or 0.0),
        ),
        reverse=True,
    )
    return findings


def build_executive_intel_context(
    raw_findings_count: int,
    correlated_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Formats threat intelligence and deduplication metrics for `services/ai_report.py`
    so the Groq Executive Summary highlights CISA KEV and high-EPSS vulnerabilities first.
    """
    correlated_count = len(correlated_findings)
    kev_findings = [f for f in correlated_findings if f.get("is_kev")]
    high_epss_findings = sorted(
        [f for f in correlated_findings if (f.get("epss_score") or 0.0) >= 0.10],
        key=lambda x: float(x.get("epss_score") or 0.0),
        reverse=True,
    )
    multi_engine_findings = [f for f in correlated_findings if int(f.get("engine_count") or 1) >= 2]

    headline = (
        f"Correlated {raw_findings_count} raw tool hits into {correlated_count} unique findings; "
        f"{len(kev_findings)} are in CISA KEV and {len(high_epss_findings)} have EPSS >= 10%."
    )

    return {
        "headline": headline,
        "raw_findings_count": raw_findings_count,
        "correlated_findings_count": correlated_count,
        "deduplicated_noise_count": max(0, raw_findings_count - correlated_count),
        "kev_count": len(kev_findings),
        "multi_engine_confirmed_count": len(multi_engine_findings),
        "kev_cves": [
            {
                "cve_id": f.get("cve_id"),
                "title": f.get("title"),
                "file_path": f.get("file_path"),
                "kev_due_date": f.get("kev_due_date"),
                "epss_score": f.get("epss_score"),
                "effective_priority_score": f.get("effective_priority_score"),
            }
            for f in kev_findings[:10]
        ],
        "top_epss_findings": [
            {
                "cve_id": f.get("cve_id"),
                "title": f.get("title"),
                "epss_score": f.get("epss_score"),
                "epss_percentile": f.get("epss_percentile"),
                "effective_priority_score": f.get("effective_priority_score"),
            }
            for f in high_epss_findings[:10]
        ],
    }
