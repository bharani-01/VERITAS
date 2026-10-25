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

type Category = "" | "auth" | "auth_failures" | "admin" | "workspace" | "api";
type SeverityFilter = "" | "info" | "low" | "medium" | "high" | "critical";

const PAGE_SIZE = 40;

const FILTERS = [
  ["", "All"],
  ["auth_failures", "Failures"],
  ["auth", "Auth"],
  ["admin", "Admin"],
  ["workspace", "Workspace"],
  ["api", "API Calls"],
] as const;

const SEVERITY_FILTERS = [
  ["", "Any severity"],
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
  return "—";
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
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

function actionTone(action: string): "ok" | "bad" | "warn" | "info" {
  if (action.includes("failed") || action.includes("rejected") || action.includes("blocked") || action === "rate_limited")
    return "bad";
  if (action.includes("deactivated") || action.includes("logout")) return "warn";
  if (action.includes("succeeded") || action.includes("approved") || action.includes("connected")) return "ok";
  return "info";
}

function statusTone(code: number | null | undefined): "ok" | "redirect" | "client" | "server" | "muted" {
  if (code == null) return "muted";
  if (code >= 200 && code < 300) return "ok";
  if (code >= 300 && code < 400) return "redirect";
  if (code >= 400 && code < 500) return "client";
  if (code >= 500) return "server";
  return "muted";
}

function severityTone(sev: string | null | undefined): string {
  const s = (sev || "info").toLowerCase();
  if (s === "critical" || s === "high") return s;
  if (s === "medium" || s === "warn") return "medium";
  if (s === "low") return "low";
  return "info";
}

function statusCodeLabel(code: number | null | undefined): string {
  if (code == null) return "—";
  const messages: Record<number, string> = {
    200: "200 OK",
    201: "201 Created",
    204: "204 No Content",
    301: "301 Moved",
    302: "302 Found",
    400: "400 Bad Request",
    401: "401 Unauthorized",
    403: "403 Forbidden",
    404: "404 Not Found",
    422: "422 Unprocessable",
    429: "429 Rate Limited",
    500: "500 Server Error",
    502: "502 Bad Gateway",
    503: "503 Unavailable",
  };
  return messages[code] || String(code);
}

function parseUserAgent(ua: string | null | undefined): { browser: string; os: string } {
  if (!ua) return { browser: "Unknown client", os: "Unknown OS" };
  let os = "Unknown OS";
  if (/windows nt 10/i.test(ua)) os = "Windows 10/11";
  else if (/windows nt/i.test(ua)) os = "Windows";
  else if (/macintosh|mac os x/i.test(ua)) os = "macOS";
  else if (/android/i.test(ua)) os = "Android";
  else if (/iphone|ipad|ipod/i.test(ua)) os = "iOS";
  else if (/linux/i.test(ua)) os = "Linux";

  let browser = "Web Browser";
  if (/edg\//i.test(ua)) browser = "Microsoft Edge";
  else if (/chrome\//i.test(ua)) browser = "Google Chrome";
  else if (/firefox\//i.test(ua)) browser = "Mozilla Firefox";
  else if (/safari\//i.test(ua) && !/chrome\//i.test(ua)) browser = "Apple Safari";
  else if (/postman/i.test(ua)) browser = "Postman";
  else if (/curl/i.test(ua)) browser = "cURL";
  else if (/python-requests/i.test(ua)) browser = "Python Requests";

  return { browser, os };
}

function getInitials(name: string | null | undefined, fallback: string = "U"): string {
  if (!name || name === "—") return fallback;
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return name.slice(0, 2).toUpperCase();
}

function formatTime(iso: string) {
  const d = parseUtc(iso) || new Date(NaN);
  return {
    date: Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString(undefined, { day: "numeric", month: "short" }),
    time: Number.isNaN(d.getTime())
      ? "—"
      : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }),
    full: Number.isNaN(d.getTime()) ? "—" : d.toLocaleString(),
  };
}

/** Admin audit console — table + detail modal. */
export function AdminAuditPage() {
  const [items, setItems] = useState<AuditEvent[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [category, setCategory] = useState<Category>("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("");
  const [actionFilter, setActionFilter] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const copyText = useCallback((text: string, field: string) => {
    if (!text) return;
    void navigator.clipboard?.writeText(text);
    setCopiedField(field);
    window.setTimeout(() => setCopiedField((curr) => (curr === field ? null : curr)), 2000);
  }, []);

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

  const buildQuery = useCallback((pageNum: number) => {
    const params = new URLSearchParams();
    params.set("page", String(pageNum));
    params.set("page_size", String(PAGE_SIZE));
    if (categoryRef.current) params.set("category", categoryRef.current);
    if (severityRef.current) params.set("severity", severityRef.current);
    if (actionRef.current.trim()) params.set("action", actionRef.current.trim());
    return `/admin/audit-events?${params.toString()}`;
  }, []);

  const resetAndLoad = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSelected(null);
    setPage(1);
    try {
      const data = await api<AuditResponse>(buildQuery(1));
      setItems(data.items);
      setTotal(data.total);
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

  // Real-time automatic polling when on first page and autoRefresh is active
  useEffect(() => {
    if (!autoRefresh || page !== 1) return;
    const timer = window.setInterval(async () => {
      try {
        const data = await api<AuditResponse>(buildQuery(1));
        setItems((prev) => {
          if (
            prev.length === data.items.length &&
            prev[0]?.id === data.items[0]?.id &&
            prev[prev.length - 1]?.id === data.items[data.items.length - 1]?.id
          ) {
            return prev;
          }
          return data.items;
        });
        setTotal(data.total);
      } catch {
        // Silently skip transient errors during background poll
      }
    }, 3500);

    return () => window.clearInterval(timer);
  }, [autoRefresh, page, buildQuery]);

  const loadMore = useCallback(async () => {
    if (loadingMoreRef.current || loading || !hasMore) return;
    loadingMoreRef.current = true;
    setLoadingMore(true);
    const next = page + 1;
    try {
      const data = await api<AuditResponse>(buildQuery(next));
      setItems((prev) => {
        const seen = new Set(prev.map((e) => e.id));
        return [...prev, ...data.items.filter((e) => !seen.has(e.id))];
      });
      setTotal(data.total);
      setPage(next);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      loadingMoreRef.current = false;
      setLoadingMore(false);
    }
  }, [buildQuery, hasMore, loading, page]);

  useEffect(() => {
    const node = sentinelRef.current;
    const root = scrollRef.current;
    if (!node || !root) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) void loadMore();
      },
      { root, rootMargin: "160px", threshold: 0 }
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [loadMore, items.length, hasMore]);

  useEffect(() => {
    if (!selected) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setSelected(null);
    }
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [selected]);

  const modal =
    selected &&
    createPortal(
      <div className="modal-root audit-modal-root" role="presentation">
        <button type="button" className="modal-backdrop" aria-label="Close" onClick={() => setSelected(null)} />
        <div className="modal-panel audit-modal" role="dialog" aria-modal="true" aria-labelledby="audit-detail-title">
          {(() => {
            const uaInfo = parseUserAgent(selected.user_agent);
            const ispName =
              selected.geo?.providers?.find((p) => p.isp)?.isp ||
              (selected.location_label?.includes("·") ? selected.location_label.split("·")[1]?.trim() : null);
            const providerList = selected.geo?.providers?.length ? selected.geo.providers : null;
            const actorName = displayName(selected.actor, selected.actor_user_id);
            const targetName = displayName(selected.target, selected.target_user_id);
            const method = (selected.how?.method || "HTTP").toUpperCase();

            return (
              <>
                <div className="audit-modal-head">
                  <div className="audit-modal-head-main">
                    <div className="audit-modal-kicker-row">
                      <span className="modal-kicker">Event details</span>
                      <span className="audit-modal-dot" />
                      <span className="audit-modal-time">{formatTime(selected.created_at).full}</span>
                    </div>
                    <h2 id="audit-detail-title">{selected.summary || selected.action.replace(/_/g, " ")}</h2>
                    <div className="audit-modal-chips">
                      <span className={`audit-tone tone-${actionTone(selected.action)}`}>{selected.action}</span>
                      <span className={`audit-sev sev-${severityTone(selected.severity)}`}>
                        {(selected.severity || "info").toUpperCase()}
                      </span>
                      <span className={`audit-status status-${statusTone(selected.status_code ?? selected.how?.status_code)}`}>
                        {statusCodeLabel(selected.status_code ?? selected.how?.status_code)}
                      </span>
                      {selected.ip_address && (
                        <span className="audit-chip-outline">
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
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
                  {/* 1. Identity & Principals Card Grid */}
                  <div className="audit-cards-grid">
                    <div className="audit-card">
                      <div className="audit-card-label">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                          <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
                          <circle cx="12" cy="7" r="4" />
                        </svg>
                        Actor (Initiated by)
                      </div>
                      <div className="audit-principal-box">
                        <div className="audit-avatar-circle actor">
                          {getInitials(actorName, "A")}
                        </div>
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
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                          <circle cx="12" cy="12" r="10" />
                          <circle cx="12" cy="12" r="4" />
                        </svg>
                        Target (Subject)
                      </div>
                      <div className="audit-principal-box">
                        <div className="audit-avatar-circle target">
                          {getInitials(targetName, "T")}
                        </div>
                        <div className="audit-principal-info">
                          <div className="audit-principal-name-row">
                            <b>{targetName}</b>
                            {selected.actor_user_id && selected.actor_user_id === selected.target_user_id && (
                              <span className="audit-role-badge self">self</span>
                            )}
                          </div>
                          <div className="audit-principal-sub">
                            <span>{displayHandle(selected.target) || "No handle"}</span>
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

                  {/* 2. Request & Client Details */}
                  <div className="audit-card">
                    <div className="audit-card-label">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                        <path d="M4 17l6-6-6-6M12 19h8" />
                      </svg>
                      Request & Client Details
                    </div>

                    <div className="audit-request-bar">
                      <div className="audit-request-endpoint">
                        <span className={`audit-method-tag method-${method.toLowerCase()}`}>
                          {method}
                        </span>
                        <code className="audit-request-path">
                          {selected.how?.path || "Direct operation"}
                        </code>
                      </div>
                      <div className="audit-request-code-pill">
                        <span className="audit-request-code-label">Response</span>
                        <span className={`audit-status status-${statusTone(selected.status_code ?? selected.how?.status_code)}`}>
                          {statusCodeLabel(selected.status_code ?? selected.how?.status_code)}
                        </span>
                      </div>
                    </div>

                    <div className="audit-client-split">
                      <div className="audit-client-col">
                        <span className="audit-item-kicker">Device & Browser</span>
                        <b className="audit-item-val">{uaInfo.browser} on {uaInfo.os}</b>
                      </div>
                      <div className="audit-client-col">
                        <span className="audit-item-kicker">Severity Classification</span>
                        <div>
                          <span className={`audit-sev sev-${severityTone(selected.severity)}`}>
                            {(selected.severity || "info").toUpperCase()}
                          </span>
                        </div>
                      </div>
                    </div>

                    {selected.user_agent && (
                      <div className="audit-ua-box">
                        <div className="audit-ua-top">
                          <span className="audit-item-kicker">User-Agent String</span>
                          <button
                            type="button"
                            className="audit-copy-btn"
                            onClick={() => copyText(selected.user_agent!, "ua")}
                          >
                            {copiedField === "ua" ? "Copied!" : "Copy UA"}
                          </button>
                        </div>
                        <code className="audit-ua-text">{selected.user_agent}</code>
                      </div>
                    )}
                  </div>

                  {/* 3. Network & Location Intelligence */}
                  <div className="audit-card">
                    <div className="audit-card-label">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                        <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z" />
                        <circle cx="12" cy="10" r="3" />
                      </svg>
                      Network & Location Intelligence
                    </div>

                    <div className="audit-geo-grid">
                      <div className="audit-geo-cell">
                        <span className="audit-item-kicker">IP Address</span>
                        <div className="audit-cell-val-row">
                          <b className="audit-mono audit-ip-main">{selected.ip_address || "Not captured"}</b>
                          {selected.ip_address && (
                            <button
                              type="button"
                              className="audit-copy-btn"
                              onClick={() => copyText(selected.ip_address!, "ip")}
                            >
                              {copiedField === "ip" ? "Copied!" : "Copy"}
                            </button>
                          )}
                        </div>
                      </div>

                      <div className="audit-geo-cell">
                        <span className="audit-item-kicker">Geographic Location</span>
                        <b className="audit-item-val">{selected.location_label || "Location unavailable"}</b>
                      </div>

                      <div className="audit-geo-cell">
                        <span className="audit-item-kicker">Network / ISP</span>
                        <b className="audit-item-val">{ispName || "Internal / Private network"}</b>
                      </div>

                      <div className="audit-geo-cell">
                        <span className="audit-item-kicker">Provider Verification</span>
                        <div className="audit-provider-tags">
                          {providerList ? (
                            providerList.map((p) => (
                              <span key={p.provider} className="audit-provider-tag" title={p.provider}>
                                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
                                  <polyline points="20 6 9 17 4 12" />
                                </svg>
                                {p.provider}
                              </span>
                            ))
                          ) : (
                            <span className="audit-provider-tag">
                              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
                                <polyline points="20 6 9 17 4 12" />
                              </svg>
                              GeoIP
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* 4. Captured Request & Event Payload (if present) */}
                  {selected.payload && (
                    <div className="audit-card audit-payload-card">
                      <div className="audit-ua-top">
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span className="audit-item-kicker">Captured Request & Event Payload</span>
                          <span className="audit-chip-outline" style={{ fontSize: "11px", padding: "2px 8px" }}>
                            Redacted
                          </span>
                        </div>
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

                  {/* 5. State Transition Diffs (if present) */}
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
                              {copiedField === "before" ? "Copied!" : "Copy JSON"}
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
                              {copiedField === "after" ? "Copied!" : "Copy JSON"}
                            </button>
                          </div>
                          <pre className="audit-diff-pre">{parseState(selected.after_state)}</pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Footer */}
                <div className="audit-modal-footer">
                  <div className="audit-footer-id-box">
                    <span className="audit-item-kicker">Event ID</span>
                    <button
                      type="button"
                      className="audit-id-copy"
                      onClick={() => copyText(selected.id, "id")}
                      title="Click to copy full event ID"
                    >
                      <code className="audit-mono">{selected.id}</code>
                      <span className="audit-copy-tag">{copiedField === "id" ? "Copied!" : "Copy"}</span>
                    </button>
                  </div>
                  <div className="audit-footer-actions">
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() => copyText(JSON.stringify(selected, null, 2), "json")}
                    >
                      {copiedField === "json" ? "JSON Copied!" : "Copy Event JSON"}
                    </button>
                    <button type="button" className="btn primary" onClick={() => setSelected(null)}>
                      Close
                    </button>
                  </div>
                </div>
              </>
            );
          })()}
        </div>
      </div>,
      document.body
    );

  return (
    <main className="admin-main audit-console">
      <header className="audit-console-head">
        <div>
          <div className="eyebrow">Monitoring</div>
          <h1>Audit log</h1>
        </div>
        <div className="audit-console-actions">
          <button
            type="button"
            className={`audit-live-btn ${autoRefresh ? "active" : ""}`}
            onClick={() => setAutoRefresh((prev) => !prev)}
            title={autoRefresh ? "Auto-refresh active (3.5s). Click to pause." : "Auto-refresh paused. Click to resume."}
          >
            <span className={`audit-live-dot ${autoRefresh ? "pulse" : ""}`} />
            <span>{autoRefresh ? "Live (3.5s)" : "Paused"}</span>
          </button>
          <button type="button" className="btn ghost" onClick={() => void resetAndLoad()} disabled={loading}>
            Refresh
          </button>
          <Link className="btn ghost" to="/admin/">
            Overview
          </Link>
        </div>
      </header>

      <div className="audit-console-toolbar">
        <div className="audit-seg" role="group" aria-label="Category">
          {FILTERS.map(([id, label]) => (
            <button
              key={id || "all"}
              type="button"
              aria-pressed={category === id}
              className={category === id ? "active" : ""}
              onClick={() => setCategory(id)}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="audit-seg" role="group" aria-label="Severity">
          {SEVERITY_FILTERS.map(([id, label]) => (
            <button
              key={id || "sev-all"}
              type="button"
              aria-pressed={severityFilter === id}
              className={severityFilter === id ? "active" : ""}
              onClick={() => setSeverityFilter(id)}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="audit-console-toolbar-right">
          <input
            type="search"
            className="audit-search-input"
            placeholder="Filter action…"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            aria-label="Filter action"
          />
          <span className="audit-count">
            {items.length} of {total}
          </span>
        </div>
      </div>

      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}

      {loading ? (
        <LoadingMark label="Loading audit events…" />
      ) : !items.length ? (
        <div className="empty-state">
          <strong>No events yet</strong>
          Activity will appear here as users sign in and use the workspace.
        </div>
      ) : (
        <div className="audit-console-panel">
          <div className="audit-scroll" ref={scrollRef} role="feed" aria-busy={loadingMore}>
            <table className="audit-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Severity</th>
                  <th>Code</th>
                  <th>Target</th>
                  <th>Location</th>
                  <th>Client</th>
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((event) => {
                  const t = formatTime(event.created_at);
                  const tone = actionTone(event.action);
                  const actorHandle = displayHandle(event.actor);
                  const targetHandle = displayHandle(event.target);
                  return (
                    <tr key={event.id}>
                      <td>
                        <span className="audit-time">
                          <b>{t.time}</b>
                          <small>{t.date}</small>
                        </span>
                      </td>
                      <td>
                        <span className="audit-person">
                          <b>{displayName(event.actor, event.actor_user_id)}</b>
                          <small>
                            {actorHandle || "—"}
                            {event.who?.actor_is_admin || event.actor?.role === "admin" ? " · admin" : ""}
                          </small>
                        </span>
                      </td>
                      <td>
                        <span className="audit-action-cell">
                          <span className={`audit-tone tone-${tone}`}>{event.summary}</span>
                          <span style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                            <code>{event.action}</code>
                            {event.payload && (
                              <span
                                className="audit-chip-outline"
                                style={{ fontSize: "10px", padding: "1px 5px", lineHeight: "1.2" }}
                                title="Contains captured request/event payload"
                              >
                                Payload
                              </span>
                            )}
                          </span>
                        </span>
                      </td>
                      <td>
                        <span className={`audit-sev sev-${severityTone(event.severity)}`}>
                          {(event.severity || "info").toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <span className={`audit-status status-${statusTone(event.status_code)}`}>
                          {event.status_code ?? "—"}
                        </span>
                      </td>
                      <td>
                        <span className="audit-person">
                          <b>{displayName(event.target, event.target_user_id)}</b>
                          <small>{targetHandle || "—"}</small>
                        </span>
                      </td>
                      <td>
                        <span className="audit-person">
                          <b className="audit-mono">{event.ip_address || "—"}</b>
                          <small>{event.location_label || "Local / unknown"}</small>
                        </span>
                      </td>
                      <td>
                        <span className="audit-person">
                          <b className="audit-mono">
                            {event.how?.method && event.how?.path
                              ? `${event.how.method} ${event.how.path}`
                              : "—"}
                          </b>
                          <small title={event.user_agent || undefined}>
                            {event.user_agent
                              ? event.user_agent.length > 34
                                ? `${event.user_agent.slice(0, 33)}…`
                                : event.user_agent
                              : "—"}
                          </small>
                        </span>
                      </td>
                      <td>
                        <button type="button" className="btn ghost small" onClick={() => setSelected(event)}>
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <div ref={sentinelRef} className="audit-sentinel" aria-hidden="true" />
            {loadingMore ? <p className="audit-loading-more">Loading more…</p> : null}
            {!hasMore ? <p className="audit-end">End of log</p> : null}
          </div>
        </div>
      )}

      {modal}
    </main>
  );
}
