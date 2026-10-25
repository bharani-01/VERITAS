import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import { parseUtc } from "../lib/time";

type AuditUser = {
  id?: string;
  display_name: string;
  username: string | null;
  email: string;
  role?: string;
};

type GeoProvider = {
  provider?: string;
  city?: string | null;
  region?: string | null;
  country?: string | null;
  isp?: string | null;
};

type GeoInfo = {
  skipped?: boolean;
  reason?: string;
  label?: string | null;
  providers?: GeoProvider[];
};

export type AuditEvent = {
  id: string;
  actor_user_id: string | null;
  target_user_id: string | null;
  actor: AuditUser | null;
  target: AuditUser | null;
  action: string;
  summary: string;
  status_code: number | null;
  severity?: string | null;
  payload?: string | null;
  before_state: string | null;
  after_state: string | null;
  ip_address: string | null;
  user_agent: string | null;
  location_label: string | null;
  geo: GeoInfo | null;
  created_at: string;
  who?: { actor_is_admin?: boolean };
  how?: { method?: string | null; path?: string | null; user_agent?: string | null; status_code?: number | null };
};

type AuditResponse = {
  items: AuditEvent[];
  page: number;
  page_size: number;
  total: number;
  server_time: string;
};

export type TimeframeStats = {
  total_events: number;
  http_requests: number;
  attacks_flagged: number;
  auth_failures: number;
  unique_ips: number;
};

export type AuditStatsResponse = {
  timeframe_24h: TimeframeStats;
  timeframe_7d: TimeframeStats;
  server_time: string;
};

type Category = "" | "attacks" | "api" | "auth_failures" | "auth" | "admin" | "workspace";
type SeverityFilter = "" | "info" | "low" | "medium" | "high" | "critical";

const PAGE_SIZE = 50;

const FILTERS = [
  ["", "All Events"],
  ["attacks", "Security Attacks"],
  ["api", "API Traffic"],
  ["auth_failures", "Failures & 429s"],
  ["auth", "Auth"],
  ["admin", "Admin"],
  ["workspace", "Workspace"],
] as const;

const SEVERITY_FILTERS = [
  ["", "All Severities"],
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["info", "Info"],
] as const;

function displayName(person: AuditUser | null | undefined, fallbackId: string | null) {
  if (person?.display_name) return person.display_name;
  if (person?.email) return person.email;
  if (fallbackId) return "Unknown user";
  return "System";
}

function displayHandle(person: AuditUser | null | undefined) {
  if (!person) return null;
  if (person.username) return `@${person.username}`;
  if (person.email) return person.email;
  return null;
}

function parseState(raw: string | null | undefined): string {
  if (!raw) return "";
  try {
    const o = JSON.parse(raw);
    return JSON.stringify(o, null, 2);
  } catch {
    return raw;
  }
}

function formatTime(iso: string) {
  const d = parseUtc(iso) || new Date(NaN);
  if (Number.isNaN(d.getTime())) return { relative: "—", full: "—", timeOnly: "—" };

  const now = new Date();
  const diffSec = Math.floor((now.getTime() - d.getTime()) / 1000);

  let relative = "just now";
  if (diffSec >= 60 && diffSec < 3600) {
    relative = `${Math.floor(diffSec / 60)}m ago`;
  } else if (diffSec >= 3600 && diffSec < 86400) {
    relative = `${Math.floor(diffSec / 3600)}h ago`;
  } else if (diffSec >= 86400) {
    relative = `${Math.floor(diffSec / 86400)}d ago`;
  } else if (diffSec >= 5) {
    relative = `${diffSec}s ago`;
  }

  const timeOnly = d.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });

  return {
    relative,
    full: `${d.toLocaleDateString()} ${timeOnly} UTC`,
    timeOnly,
  };
}

function parseUserAgent(ua: string | null | undefined) {
  if (!ua) return { browser: "Unknown", os: "Unknown" };
  let browser = "Browser";
  if (ua.includes("Firefox/")) browser = "Firefox";
  else if (ua.includes("Chrome/") || ua.includes("Chromium/")) browser = "Chrome";
  else if (ua.includes("Safari/") && !ua.includes("Chrome")) browser = "Safari";
  else if (ua.includes("Edge/") || ua.includes("Edg/")) browser = "Edge";
  else if (ua.includes("curl/")) browser = "cURL";
  else if (ua.includes("python-requests")) browser = "Python";
  else if (ua.includes("Postman")) browser = "Postman";
  else if (ua.includes("sqlmap")) browser = "sqlmap";

  let os = "OS";
  if (ua.includes("Windows")) os = "Windows";
  else if (ua.includes("Macintosh") || ua.includes("Mac OS")) os = "macOS";
  else if (ua.includes("Linux")) os = "Linux";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("iPhone") || ua.includes("iPad")) os = "iOS";

  return { browser, os };
}

function statusTone(code: number | null | undefined): string {
  if (!code) return "muted";
  if (code >= 200 && code < 300) return "ok";
  if (code === 429) return "rate-limited";
  if (code >= 400 && code < 500) return "client";
  if (code >= 500) return "server";
  return "muted";
}

function statusCodeLabel(code: number | null | undefined): string {
  if (!code) return "—";
  if (code === 200) return "200 OK";
  if (code === 201) return "201 Created";
  if (code === 202) return "202 Accepted";
  if (code === 204) return "204 No Content";
  if (code === 400) return "400 Bad Request";
  if (code === 401) return "401 Unauthorized";
  if (code === 403) return "403 Forbidden";
  if (code === 404) return "404 Not Found";
  if (code === 429) return "429 Rate Limited";
  if (code === 500) return "500 Server Error";
  return String(code);
}

function severityTone(sev: string | null | undefined): string {
  const s = (sev || "info").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "info";
}

function getInitials(name: string, fallback = "U"): string {
  if (!name || name === "—") return fallback;
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 2) return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

export function AdminAuditPage() {
  const [items, setItems] = useState<AuditEvent[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<AuditStatsResponse | null>(null);

  // Filters
  const [category, setCategory] = useState<Category>("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("");
  const [actionFilter, setActionFilter] = useState("");

  // Live Stream & State
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement | null>(null);
  const sentinelRef = useRef<HTMLDivElement | null>(null);
  const categoryRef = useRef(category);
  const severityRef = useRef(severityFilter);
  const actionRef = useRef(actionFilter);
  const loadingMoreRef = useRef(false);

  categoryRef.current = category;
  severityRef.current = severityFilter;
  actionRef.current = actionFilter;

  const hasMore = items.length < total;

  const copyText = useCallback((text: string, field: string) => {
    if (!text) return;
    void navigator.clipboard?.writeText(text);
    setCopiedField(field);
    window.setTimeout(() => setCopiedField((curr) => (curr === field ? null : curr)), 2000);
  }, []);

  const buildQuery = useCallback((pageNum: number) => {
    const params = new URLSearchParams();
    params.set("page", String(pageNum));
    params.set("page_size", String(PAGE_SIZE));
    if (categoryRef.current) params.set("category", categoryRef.current);
    if (severityRef.current) params.set("severity", severityRef.current);
    if (actionRef.current.trim()) params.set("action", actionRef.current.trim());
    return `/admin/audit-events?${params.toString()}`;
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const data = await api<AuditStatsResponse>("/admin/audit-stats");
      setStats(data);
    } catch {
      // transient
    }
  }, []);

  const resetAndLoad = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSelected(null);
    setPage(1);
    try {
      const [eventsData, statsData] = await Promise.all([
        api<AuditResponse>(buildQuery(1)),
        api<AuditStatsResponse>("/admin/audit-stats").catch(() => null),
      ]);
      setItems(eventsData.items);
      setTotal(eventsData.total);
      if (statsData) setStats(statsData);
    } catch (err) {
      setError((err as Error).message);
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [buildQuery]);

  useEffect(() => {
    void resetAndLoad();
  }, [category, severityFilter, actionFilter, resetAndLoad]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => {
      void fetchStats();
    }, 15000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, fetchStats]);

  // WebSocket Live Stream
  useEffect(() => {
    if (!autoRefresh) {
      setWsConnected(false);
      return;
    }

    let socket: WebSocket | null = null;
    let pingTimer: number | undefined;
    let isDisposed = false;

    function connect() {
      if (isDisposed) return;
      try {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/admin/audit-events/ws`;
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
          if (isDisposed) {
            socket?.close();
            return;
          }
          setWsConnected(true);
          pingTimer = window.setInterval(() => {
            if (socket?.readyState === WebSocket.OPEN) {
              socket.send("ping");
            }
          }, 20000);
        };

        socket.onmessage = (event) => {
          if (isDisposed) return;
          try {
            const data = JSON.parse(event.data);
            if (data.type === "audit_event" && data.event) {
              const newEvent: AuditEvent = data.event;

              // Increment KPI stats in real time: ONLY true attacks (not normal api_request)
              const isRealAttack =
                (newEvent.action.startsWith("api_") && newEvent.action !== "api_request") ||
                newEvent.action === "rate_limited";

              const isAuthFailure =
                ["login_failed", "login_blocked_status", "rate_limited", "api_auth_anomaly"].includes(newEvent.action);

              setStats((prev) => {
                if (!prev) return prev;
                const updateBucket = (b: TimeframeStats): TimeframeStats => ({
                  ...b,
                  total_events: b.total_events + 1,
                  http_requests: b.http_requests + 1,
                  attacks_flagged: b.attacks_flagged + (isRealAttack ? 1 : 0),
                  auth_failures: b.auth_failures + (isAuthFailure ? 1 : 0),
                });

                return {
                  ...prev,
                  timeframe_24h: updateBucket(prev.timeframe_24h),
                  timeframe_7d: updateBucket(prev.timeframe_7d),
                };
              });

              const cat = categoryRef.current;
              const matchesCat =
                !cat ||
                (cat === "attacks" &&
                  ((newEvent.action.startsWith("api_") && newEvent.action !== "api_request") ||
                    ["login_failed", "login_blocked_status", "rate_limited"].includes(newEvent.action))) ||
                (cat === "api" && newEvent.action === "api_request") ||
                (cat === "auth_failures" &&
                  ["login_failed", "login_blocked_status", "rate_limited", "api_auth_anomaly"].includes(newEvent.action)) ||
                (cat === "auth" &&
                  [
                    "login_succeeded",
                    "login_failed",
                    "login_blocked_status",
                    "logout",
                    "user_signed_up",
                    "email_verified",
                    "verification_resent",
                    "password_reset_requested",
                    "password_reset_completed",
                  ].includes(newEvent.action)) ||
                (cat === "admin" &&
                  (newEvent.action.startsWith("user_") || ["fs_list", "fs_download"].includes(newEvent.action))) ||
                (cat === "workspace" &&
                  [
                    "project_created",
                    "project_updated",
                    "project_deleted",
                    "scan_started",
                    "github_connected",
                    "github_disconnected",
                    "github_oauth_failed",
                    "github_repo_attached",
                    "github_repo_rejected",
                  ].includes(newEvent.action));

              const sev = severityRef.current;
              const matchesSev = !sev || (newEvent.severity || "info").toLowerCase() === sev.toLowerCase();

              const act = actionRef.current.trim().toLowerCase();
              const matchesAct =
                !act ||
                newEvent.action.toLowerCase().includes(act) ||
                (newEvent.how?.path && newEvent.how.path.toLowerCase().includes(act)) ||
                (newEvent.ip_address && newEvent.ip_address.includes(act));

              if (matchesCat && matchesSev && matchesAct) {
                setItems((prev) => [newEvent, ...prev.filter((e) => e.id !== newEvent.id)]);
                setTotal((t) => t + 1);
              }
            }
          } catch {
            // ignore non-json
          }
        };

        socket.onclose = () => {
          setWsConnected(false);
          window.clearInterval(pingTimer);
        };
      } catch {
        setWsConnected(false);
      }
    }

    connect();

    return () => {
      isDisposed = true;
      window.clearInterval(pingTimer);
      socket?.close();
    };
  }, [autoRefresh]);

  // Infinite Scroll Handler
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasMore && !loading && !loadingMoreRef.current) {
          loadingMoreRef.current = true;
          setLoadingMore(true);
          const nextPage = page + 1;
          api<AuditResponse>(buildQuery(nextPage))
            .then((data) => {
              setItems((prev) => {
                const existingIds = new Set(prev.map((e) => e.id));
                const fresh = data.items.filter((e) => !existingIds.has(e.id));
                return [...prev, ...fresh];
              });
              setPage(nextPage);
              setTotal(data.total);
            })
            .catch(() => {
              // ignore
            })
            .finally(() => {
              loadingMoreRef.current = false;
              setLoadingMore(false);
            });
        }
      },
      { threshold: 0.1 }
    );

    if (sentinelRef.current) {
      observer.observe(sentinelRef.current);
    }

    return () => observer.disconnect();
  }, [hasMore, loading, page, buildQuery]);

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(items, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `veritas_audit_export_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const hasActiveFilters = Boolean(category || severityFilter || actionFilter.trim());
  const clearFilters = () => {
    setCategory("");
    setSeverityFilter("");
    setActionFilter("");
  };

  // Modal extraction helpers
  const actorName = selected ? displayName(selected.actor, selected.actor_user_id) : "";
  const targetName = selected ? displayName(selected.target, selected.target_user_id) : "";
  const uaInfo = parseUserAgent(selected?.user_agent ?? selected?.how?.user_agent);
  const method = (selected?.how?.method || "HTTP").toUpperCase();

  return (
    <main className="admin-main audit-console-container" tabIndex={-1}>
      {/* 1. Header Banner */}
      <header className="audit-console-head">
        <div className="audit-console-titles">
          <nav className="audit-breadcrumb" aria-label="Breadcrumb">
            <Link to="/admin">Admin</Link>
            <span className="audit-sep">/</span>
            <span>Security &amp; Compliance</span>
          </nav>
          <div className="audit-title-row">
            <h1 className="audit-console-title">Audit Logs</h1>
            <div className={`sec-live-badge ${wsConnected && autoRefresh ? "active" : ""}`}>
              <span className="sec-pulse-dot" />
              <span>{autoRefresh ? (wsConnected ? "Live (WebSocket)" : "Connecting…") : "Stream Paused"}</span>
            </div>
          </div>
          <p className="audit-console-subtitle">
            Tamper-evident, real-time audit ledger tracking authentication, administrative operations, and API telemetry.
          </p>
        </div>

        <div className="audit-console-actions">
          <button
            type="button"
            className="sec-btn-outline"
            onClick={() => setAutoRefresh(!autoRefresh)}
            title={autoRefresh ? "Pause incoming live stream" : "Resume live streaming"}
          >
            {autoRefresh ? (
              <>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
                  <rect x="6" y="4" width="4" height="16" rx="1" />
                  <rect x="14" y="4" width="4" height="16" rx="1" />
                </svg>
                <span>Pause Stream</span>
              </>
            ) : (
              <>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
                  <polygon points="5 3 19 12 5 21 5 3" />
                </svg>
                <span>Resume Stream</span>
              </>
            )}
          </button>

          <button
            type="button"
            className="sec-btn-outline"
            onClick={exportJson}
            disabled={!items.length}
            title="Download displayed records as JSON"
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            <span>Export JSON</span>
          </button>

          <button
            type="button"
            className="btn secondary audit-btn-refresh"
            onClick={() => void resetAndLoad()}
            disabled={loading}
          >
            <svg className={loading ? "spin" : ""} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M23 4v6h-6" />
              <path d="M1 20v-6h6" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            <span>{loading ? "Refreshing…" : "Refresh"}</span>
          </button>
        </div>
      </header>

      {/* 2. Top Metrics Ribbon */}
      <section className="audit-kpi-ribbon" aria-label="Operational Metrics">
        <div className="audit-kpi-pill">
          <div className="audit-kpi-head">
            <span className="audit-kpi-pill-label">Total Events (24h)</span>
            <span className="audit-kpi-ico total">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
              </svg>
            </span>
          </div>
          <span className="audit-kpi-pill-val">{stats?.timeframe_24h.total_events?.toLocaleString() ?? total.toLocaleString()}</span>
          <span className="audit-kpi-pill-sub">Recorded audit entries</span>
        </div>

        <div className="audit-kpi-pill alert">
          <div className="audit-kpi-head">
            <span className="audit-kpi-pill-label">Flagged Threats</span>
            <span className="audit-kpi-ico alert">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
            </span>
          </div>
          <span className="audit-kpi-pill-val">{stats?.timeframe_24h.attacks_flagged?.toLocaleString() ?? 0}</span>
          <span className="audit-kpi-pill-sub">SQLi, XSS, SSRF &amp; scanners</span>
        </div>

        <div className="audit-kpi-pill warn">
          <div className="audit-kpi-head">
            <span className="audit-kpi-pill-label">Auth Failures / 429s</span>
            <span className="audit-kpi-ico warn">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </span>
          </div>
          <span className="audit-kpi-pill-val">{stats?.timeframe_24h.auth_failures?.toLocaleString() ?? 0}</span>
          <span className="audit-kpi-pill-sub">Rate throttles &amp; bad logins</span>
        </div>

        <div className="audit-kpi-pill info">
          <div className="audit-kpi-head">
            <span className="audit-kpi-pill-label">Unique Client IPs</span>
            <span className="audit-kpi-ico info">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="2" y1="12" x2="22" y2="12" />
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
              </svg>
            </span>
          </div>
          <span className="audit-kpi-pill-val">{stats?.timeframe_24h.unique_ips?.toLocaleString() ?? 0}</span>
          <span className="audit-kpi-pill-sub">Distinct client origins</span>
        </div>
      </section>

      {/* 3. Two-Tier Filter & Search Toolbar */}
      <section className="audit-toolbar-box">
        {/* Tier 1: Category Filter Tabs */}
        <div className="audit-cat-tabs" role="tablist" aria-label="Event Categories">
          {FILTERS.map(([id, label]) => (
            <button
              key={id || "all"}
              type="button"
              role="tab"
              aria-selected={category === id}
              className={`audit-cat-tab ${category === id ? "active" : ""}`}
              onClick={() => setCategory(id)}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Tier 2: Subbar with Severity filter, count, search & reset */}
        <div className="audit-subbar">
          <div className="audit-subbar-left">
            <div className="audit-select-wrap">
              <select
                id="audit-severity-select"
                className="audit-select"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
                aria-label="Filter by Severity"
              >
                {SEVERITY_FILTERS.map(([id, label]) => (
                  <option key={id || "all-sev"} value={id}>
                    {label === "All Severities" ? "All Severities" : `Severity: ${label}`}
                  </option>
                ))}
              </select>
            </div>

            <span className="audit-results-count">
              Showing <b>{items.length}</b> {total > 0 && <>of <b>{total.toLocaleString()}</b></>} events
            </span>
          </div>

          <div className="audit-subbar-right">
            <div className="audit-search-wrap">
              <svg className="audit-search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <input
                type="search"
                className="audit-search-input"
                placeholder="Search action, actor, path, or IP…"
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                aria-label="Filter audit events"
              />
              {actionFilter && (
                <button
                  type="button"
                  className="audit-search-clear"
                  onClick={() => setActionFilter("")}
                  aria-label="Clear search"
                >
                  ×
                </button>
              )}
            </div>

            {hasActiveFilters && (
              <button type="button" className="audit-clear-link" onClick={clearFilters}>
                Reset Filters
              </button>
            )}
          </div>
        </div>
      </section>

      {/* Error state */}
      {error && (
        <div className="form-error" role="alert">
          {error}
        </div>
      )}

      {/* 4. Master Ledger Table */}
      <section className="audit-table-card">
        {loading && !items.length ? (
          <div className="sec-loading-state">
            <LoadingMark />
            <span>Loading audit ledger…</span>
          </div>
        ) : !items.length ? (
          <div className="sec-empty-state">
            <p>No audit events match your current filters.</p>
            {hasActiveFilters && (
              <button type="button" className="btn secondary" onClick={clearFilters}>
                Clear all filters
              </button>
            )}
          </div>
        ) : (
          <div className="table-wrap sec-table-wrap" ref={scrollRef}>
            <table className="audit-table">
              <thead>
                <tr>
                  <th style={{ width: "130px" }}>Timestamp</th>
                  <th style={{ width: "170px" }}>Actor</th>
                  <th style={{ width: "150px" }}>Target</th>
                  <th>Action &amp; Summary</th>
                  <th style={{ width: "95px" }}>Severity</th>
                  <th style={{ width: "260px" }}>Endpoint &amp; Status</th>
                  <th style={{ width: "180px" }}>Origin IP</th>
                  <th style={{ width: "80px", textAlign: "right" }}>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {items.map((event) => {
                  const t = formatTime(event.created_at);
                  const aName = displayName(event.actor, event.actor_user_id);
                  const tName = displayName(event.target, event.target_user_id);
                  const evMethod = (event.how?.method || "HTTP").toUpperCase();
                  const isThreat =
                    (event.action.startsWith("api_") && event.action !== "api_request") ||
                    ["rate_limited", "login_failed", "login_blocked_status"].includes(event.action);

                  return (
                    <tr
                      key={event.id}
                      className={isThreat ? "sec-row-flag" : ""}
                      onClick={() => setSelected(event)}
                    >
                      <td>
                        <span className="audit-time" title={t.full}>
                          <b>{t.relative}</b>
                          <small>{t.timeOnly} UTC</small>
                        </span>
                      </td>
                      <td>
                        {event.actor ? (
                          <div className="audit-principal-cell">
                            <div className="audit-avatar-tiny">{getInitials(aName, "U")}</div>
                            <div className="audit-person">
                              <span className="audit-person-name-row">
                                <b>{aName}</b>
                                {(event.who?.actor_is_admin || event.actor?.role === "admin") && (
                                  <span className="audit-role-badge admin">admin</span>
                                )}
                              </span>
                              <small>{displayHandle(event.actor)}</small>
                            </div>
                          </div>
                        ) : (
                          <span className="audit-system-pill">⚙ System</span>
                        )}
                      </td>
                      <td>
                        {event.target ? (
                          <div className="audit-principal-cell">
                            <div className="audit-avatar-tiny target">{getInitials(tName, "T")}</div>
                            <div className="audit-person">
                              <b>{tName}</b>
                              <small>{displayHandle(event.target)}</small>
                            </div>
                          </div>
                        ) : (
                          <span className="audit-system-pill muted">System scope</span>
                        )}
                      </td>
                      <td>
                        <span className="audit-action-cell">
                          <b className="audit-action-title">{event.action}</b>
                          <small className="audit-action-desc">{event.summary}</small>
                        </span>
                      </td>
                      <td>
                        <span className={`audit-sev sev-${severityTone(event.severity)}`}>
                          {(event.severity || "info").toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <div className="sec-cell-req">
                          <span className={`audit-method-tag method-${evMethod.toLowerCase()}`}>{evMethod}</span>
                          <code className="audit-path-code" title={event.how?.path || ""}>
                            {event.how?.path || "—"}
                          </code>
                          <span className={`audit-status status-${statusTone(event.status_code ?? event.how?.status_code)}`}>
                            {statusCodeLabel(event.status_code ?? event.how?.status_code)}
                          </span>
                        </div>
                      </td>
                      <td>
                        <div className="sec-ip-cell">
                          <code className="sec-ip-code">{event.ip_address || "—"}</code>
                          {event.location_label && (
                            <span className="sec-ip-loc" title={event.location_label}>
                              📍 {event.location_label}
                            </span>
                          )}
                        </div>
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          type="button"
                          className="sec-btn-inspect"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelected(event);
                          }}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {/* Infinite Scroll Sentinel */}
            <div ref={sentinelRef} className="sec-sentinel" aria-hidden="true" />
            {loadingMore && <div className="sec-load-more">Loading older events…</div>}
            {!hasMore && items.length > 0 && <div className="sec-load-more end">All {total.toLocaleString()} events loaded</div>}
          </div>
        )}
      </section>

      {/* 5. Deep Event Inspector Modal */}
      {selected &&
        createPortal(
          <div className="audit-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="modal-action-title">
            <div className="audit-modal-box">
              <div className="audit-modal-header">
                <div className="audit-modal-title-col">
                  <div className="audit-modal-kicker">Security & Audit Event Inspector</div>
                  <h3 id="modal-action-title" className="audit-modal-action-title">
                    {selected.action}
                  </h3>
                  <div className="audit-modal-chips-row">
                    <span className={`audit-sev sev-${severityTone(selected.severity)}`}>
                      {(selected.severity || "info").toUpperCase()}
                    </span>
                    <span className={`audit-status status-${statusTone(selected.status_code ?? selected.how?.status_code)}`}>
                      {statusCodeLabel(selected.status_code ?? selected.how?.status_code)}
                    </span>
                    {selected.ip_address && (
                      <span className="audit-chip-outline">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <circle cx="12" cy="12" r="10" />
                          <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20M2 12h20" />
                        </svg>
                        {selected.ip_address}
                      </span>
                    )}
                  </div>
                </div>
                <button type="button" className="modal-close" aria-label="Close" onClick={() => setSelected(null)}>
                  ×
                </button>
              </div>

              <div className="audit-modal-body">
                <div className="audit-cards-grid">
                  <div className="audit-card">
                    <div className="audit-card-label">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
                        <circle cx="12" cy="7" r="4" />
                      </svg>
                      Actor (Initiated by)
                    </div>
                    <div className="audit-principal-box">
                      <div className="audit-avatar-circle actor">{getInitials(actorName, "A")}</div>
                      <div className="audit-principal-info">
                        <div className="audit-principal-name-row">
                          <b>{actorName}</b>
                          {(selected.who?.actor_is_admin || selected.actor?.role === "admin") && (
                            <span className="audit-role-badge admin">admin</span>
                          )}
                        </div>
                        <div className="audit-principal-sub">
                          <span>{displayHandle(selected.actor) || "No handle"}</span>
                          {selected.actor_user_id && (
                            <code className="audit-sub-id" title={selected.actor_user_id}>
                              ID: {selected.actor_user_id.slice(0, 8)}…
                            </code>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="audit-card">
                    <div className="audit-card-label">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="12" y1="8" x2="12" y2="12" />
                        <line x1="12" y1="16" x2="12.01" y2="16" />
                      </svg>
                      Target Resource / Principal
                    </div>
                    <div className="audit-principal-box">
                      <div className="audit-avatar-circle target">{getInitials(targetName, "T")}</div>
                      <div className="audit-principal-info">
                        <div className="audit-principal-name-row">
                          <b>{targetName}</b>
                          {selected.target?.role === "admin" && <span className="audit-role-badge admin">admin</span>}
                        </div>
                        <div className="audit-principal-sub">
                          <span>{displayHandle(selected.target) || "System scope"}</span>
                          {selected.target_user_id && (
                            <code className="audit-sub-id" title={selected.target_user_id}>
                              ID: {selected.target_user_id.slice(0, 8)}…
                            </code>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* HTTP Telemetry */}
                <div className="audit-card">
                  <div className="audit-card-label">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
                      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
                      <line x1="6" y1="6" x2="6.01" y2="6" />
                      <line x1="6" y1="18" x2="6.01" y2="18" />
                    </svg>
                    HTTP & Network Telemetry
                  </div>
                  <div className="audit-network-grid">
                    <div>
                      <span className="audit-item-kicker">Request endpoint</span>
                      <div className="audit-method-row">
                        <span className={`audit-method-tag method-${method.toLowerCase()}`}>{method}</span>
                        <code className="audit-path-code">{selected.how?.path || "—"}</code>
                      </div>
                    </div>
                    <div>
                      <span className="audit-item-kicker">Response status</span>
                      <div className="audit-val-row">
                        <span className={`audit-status status-${statusTone(selected.status_code ?? selected.how?.status_code)}`}>
                          {statusCodeLabel(selected.status_code ?? selected.how?.status_code)}
                        </span>
                      </div>
                    </div>
                    <div>
                      <span className="audit-item-kicker">Client origin IP</span>
                      <div className="audit-val-row">
                        <code className="audit-mono">{selected.ip_address || "—"}</code>
                      </div>
                    </div>
                    <div>
                      <span className="audit-item-kicker">Client environment</span>
                      <div className="audit-val-row">
                        <span>
                          {uaInfo.browser} on {uaInfo.os}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Payload JSON */}
                {selected.payload && (
                  <div className="audit-card">
                    <div className="audit-ua-top">
                      <span className="audit-item-kicker">Request Payload & Attack Parameters</span>
                      <button
                        type="button"
                        className="audit-copy-btn"
                        onClick={() => copyText(parseState(selected.payload), "payload")}
                      >
                        {copiedField === "payload" ? "Copied!" : "Copy Payload"}
                      </button>
                    </div>
                    <pre className="audit-diff-pre audit-payload-pre">{parseState(selected.payload)}</pre>
                  </div>
                )}

                {/* State Transition Diffs */}
                {(selected.before_state || (selected.after_state && selected.after_state !== selected.payload)) && (
                  <div className="audit-cards-grid">
                    {selected.before_state && (
                      <div className="audit-card">
                        <div className="audit-ua-top">
                          <span className="audit-item-kicker">State before change</span>
                          <button
                            type="button"
                            className="audit-copy-btn"
                            onClick={() => copyText(parseState(selected.before_state), "before")}
                          >
                            {copiedField === "before" ? "Copied!" : "Copy"}
                          </button>
                        </div>
                        <pre className="audit-diff-pre">{parseState(selected.before_state)}</pre>
                      </div>
                    )}
                    {selected.after_state && selected.after_state !== selected.payload && (
                      <div className="audit-card">
                        <div className="audit-ua-top">
                          <span className="audit-item-kicker">State after change</span>
                          <button
                            type="button"
                            className="audit-copy-btn"
                            onClick={() => copyText(parseState(selected.after_state), "after")}
                          >
                            {copiedField === "after" ? "Copied!" : "Copy"}
                          </button>
                        </div>
                        <pre className="audit-diff-pre">{parseState(selected.after_state)}</pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>,
          document.body
        )}
    </main>
  );
}
