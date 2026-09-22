from __future__ import annotations

import ipaddress
import threading
from typing import Any

import httpx

# Process-local cache so repeated events from the same IP stay fast.
_cache: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()
_TIMEOUT = 2.2


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _norm(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _provider_ip_api(client: httpx.Client, ip: str) -> dict[str, Any] | None:
    """ip-api.com — free non-HTTPS tier for educational/demo use."""
    resp = client.get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,timezone,query"},
    )
    if resp.status_code != 200:
        return None
    data = resp.json()
    if data.get("status") != "success":
        return None
    return {
        "provider": "ip-api",
        "city": _norm(data.get("city")),
        "region": _norm(data.get("regionName")),
        "country": _norm(data.get("country")),
        "country_code": _norm(data.get("countryCode")),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "isp": _norm(data.get("isp")),
        "org": _norm(data.get("org")),
        "timezone": _norm(data.get("timezone")),
    }


def _provider_ipwhois(client: httpx.Client, ip: str) -> dict[str, Any] | None:
    resp = client.get(f"https://ipwho.is/{ip}")
    if resp.status_code != 200:
        return None
    data = resp.json()
    if not data.get("success", True):
        return None
    return {
        "provider": "ipwho.is",
        "city": _norm(data.get("city")),
        "region": _norm(data.get("region")),
        "country": _norm(data.get("country")),
        "country_code": _norm(data.get("country_code")),
        "lat": (data.get("latitude") if data.get("latitude") is not None else (data.get("lat"))),
        "lon": (data.get("longitude") if data.get("longitude") is not None else (data.get("lon"))),
        "isp": _norm((data.get("connection") or {}).get("isp") or data.get("isp")),
        "org": _norm((data.get("connection") or {}).get("org") or data.get("org")),
        "timezone": _norm((data.get("timezone") or {}).get("id") if isinstance(data.get("timezone"), dict) else data.get("timezone")),
    }


def _provider_ipapi_co(client: httpx.Client, ip: str) -> dict[str, Any] | None:
    resp = client.get(f"https://ipapi.co/{ip}/json/")
    if resp.status_code != 200:
        return None
    data = resp.json()
    if data.get("error"):
        return None
    return {
        "provider": "ipapi.co",
        "city": _norm(data.get("city")),
        "region": _norm(data.get("region")),
        "country": _norm(data.get("country_name") or data.get("country")),
        "country_code": _norm(data.get("country_code") or data.get("country")),
        "lat": data.get("latitude"),
        "lon": data.get("longitude"),
        "isp": _norm(data.get("org")),
        "org": _norm(data.get("org")),
        "timezone": _norm(data.get("timezone")),
    }


_PROVIDERS = (_provider_ip_api, _provider_ipwhois, _provider_ipapi_co)


def _majority(values: list[Any]) -> Any | None:
    cleaned = [v for v in values if v not in (None, "", [])]
    if not cleaned:
        return None
    # Prefer most common string; for floats take first non-null.
    if all(isinstance(v, (int, float)) for v in cleaned):
        return cleaned[0]
    counts: dict[str, int] = {}
    for v in cleaned:
        key = str(v).strip().lower()
        counts[key] = counts.get(key, 0) + 1
    winner = max(counts, key=counts.get)
    for v in cleaned:
        if str(v).strip().lower() == winner:
            return v
    return cleaned[0]


def _consensus(results: list[dict[str, Any]]) -> dict[str, Any]:
    fields = ("city", "region", "country", "country_code", "isp", "org", "timezone", "lat", "lon")
    out: dict[str, Any] = {}
    for field in fields:
        out[field] = _majority([r.get(field) for r in results])
    parts = [p for p in (out.get("city"), out.get("region"), out.get("country")) if p]
    out["label"] = ", ".join(str(p) for p in parts) if parts else None
    out["agreement_count"] = len(results)
    return out


def lookup_ip(ip: str | None) -> dict[str, Any]:
    """Resolve approximate location via multiple free providers (best-effort, fail-open)."""
    if not ip:
        return {"skipped": True, "reason": "missing_ip"}
    if not _is_public_ip(ip):
        return {"skipped": True, "reason": "private_or_local", "ip": ip, "label": "Local / private network"}

    with _lock:
        cached = _cache.get(ip)
    if cached is not None:
        return {**cached, "cached": True}

    provider_results: list[dict[str, Any]] = []
    provider_errors: list[dict[str, str]] = []
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            for provider in _PROVIDERS:
                name = provider.__name__.replace("_provider_", "")
                try:
                    result = provider(client, ip)
                    if result:
                        provider_results.append(result)
                    else:
                        provider_errors.append({"provider": name, "error": "empty_or_failed"})
                except Exception as exc:  # noqa: BLE001 — enrichment must never break audit writes
                    provider_errors.append({"provider": name, "error": str(exc)[:120]})
    except Exception as exc:  # noqa: BLE001
        payload = {"skipped": True, "reason": "lookup_failed", "ip": ip, "error": str(exc)[:160]}
        with _lock:
            _cache[ip] = payload
        return payload

    if not provider_results:
        payload = {
            "skipped": True,
            "reason": "all_providers_failed",
            "ip": ip,
            "providers": provider_errors,
            "label": "Location unavailable",
        }
        with _lock:
            _cache[ip] = payload
        return payload

    consensus = _consensus(provider_results)
    payload = {
        "ip": ip,
        "label": consensus.get("label") or "Location partially available",
        "consensus": consensus,
        "providers": provider_results,
        "provider_errors": provider_errors,
        "cached": False,
    }
    with _lock:
        _cache[ip] = {k: v for k, v in payload.items() if k != "cached"}
    return payload
