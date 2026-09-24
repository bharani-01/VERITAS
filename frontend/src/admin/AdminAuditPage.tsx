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

type Category = "" | "auth" | "auth_failures" | "admin" | "workspace";
type SeverityFilter = "" | "info" | "low" | "medium" | "high" | "critical";

const PAGE_SIZE = 40;

const FILTERS = [
  ["", "All"],
  ["auth_failures", "Failures"],
  ["auth", "Auth"],
  ["admin", "Admin"],
  ["workspace", "Workspace"],
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

function parseState(raw: string | null): string {
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
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);

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
      <div className="modal-root" role="presentation">
        <button type="button" className="modal-backdrop" aria-label="Close" onClick={() => setSelected(null)} />
        <div className="modal-panel audit-modal" role="dialog" aria-modal="true" aria-labelledby="audit-detail-title">
          <div className="modal-head">
            <div>
              <div className="modal-kicker">Event details</div>
              <h2 id="audit-detail-title">{selected.summary || selected.action.replace(/_/g, " ")}</h2>
              <p className="audit-modal-sub">
                <span className={`audit-tone tone-${actionTone(selected.action)}`}>{selected.action}</span>
                <span className={`audit-sev sev-${severityTone(selected.severity)}`}>
                  {(selected.severity || "info").toUpperCase()}
                </span>
                <span className={`audit-status status-${statusTone(selected.status_code ?? selected.how?.status_code)}`}>
                  {selected.status_code ?? selected.how?.status_code ?? "—"}
                </span>
                <span>{formatTime(selected.created_at).full}</span>
              </p>
            </div>
            <button type="button" className="modal-close" aria-label="Close" onClick={() => setSelected(null)}>
              ×
            </button>
          </div>

          <div className="audit-modal-body">
            <div className="audit-detail-rows">
              <div className="audit-detail-row">
                <div className="audit-detail-label">Severity</div>
                <div className="audit-detail-value">
                  <span className={`audit-sev sev-${severityTone(selected.severity)}`}>
                    {(selected.severity || "info").toUpperCase()}
                  </span>
                </div>
              </div>

              <div className="audit-detail-row">
                <div className="audit-detail-label">Response code</div>
                <div className="audit-detail-value">
                  <b className={`audit-status status-${statusTone(selected.status_code ?? selected.how?.status_code)}`}>
                    {selected.status_code ?? selected.how?.status_code ?? "—"}
                  </b>
                </div>
              </div>

              <div className="audit-detail-row">
                <div className="audit-detail-label">Actor</div>
                <div className="audit-detail-value">
                  <b>{displayName(selected.actor, selected.actor_user_id)}</b>
                  <span>
                    {displayHandle(selected.actor) || "No handle"}
                    {selected.who?.actor_is_admin || selected.actor?.role === "admin" ? " · admin" : ""}
                  </span>
                </div>
              </div>

              <div className="audit-detail-row">
                <div className="audit-detail-label">Target</div>
                <div className="audit-detail-value">
                  <b>{displayName(selected.target, selected.target_user_id)}</b>
                  <span>{displayHandle(selected.target) || "No handle"}</span>
                </div>
              </div>

              <div className="audit-detail-row">
                <div className="audit-detail-label">IP address</div>
                <div className="audit-detail-value">
                  <b className="audit-mono">{selected.ip_address || "Not captured"}</b>
                </div>
              </div>

              <div className="audit-detail-row">
                <div className="audit-detail-label">Location</div>
                <div className="audit-detail-value">
                  <b>{selected.location_label || "Not available"}</b>
                </div>
              </div>

              <div className="audit-detail-row">
                <div className="audit-detail-label">Request</div>
                <div className="audit-detail-value">
                  <b className="audit-mono">
                    {selected.how?.method && selected.how?.path
                      ? `${selected.how.method} ${selected.how.path}`
                      : "HTTP request"}
                    {selected.status_code != null || selected.how?.status_code != null
                      ? ` → ${selected.status_code ?? selected.how?.status_code}`
                      : ""}
                  </b>
                  <span className="audit-ua">{selected.user_agent || "User-agent not captured"}</span>
                </div>
              </div>

              {selected.geo?.providers?.map((p) => (
                <div className="audit-detail-row" key={`${selected.id}-${p.provider}`}>
                  <div className="audit-detail-label">{p.provider}</div>
                  <div className="audit-detail-value">
                    <span>
                      {[p.city, p.region, p.country].filter(Boolean).join(", ") || "No place data"}
                      {p.isp ? ` · ${p.isp}` : ""}
                    </span>
                  </div>
                </div>
              ))}

              {selected.before_state ? (
                <div className="audit-detail-row audit-detail-row-stack">
                  <div className="audit-detail-label">Before</div>
                  <div className="audit-detail-value">
                    <pre>{parseState(selected.before_state)}</pre>
                  </div>
                </div>
              ) : null}

              {selected.after_state ? (
                <div className="audit-detail-row audit-detail-row-stack">
                  <div className="audit-detail-label">After</div>
                  <div className="audit-detail-value">
                    <pre>{parseState(selected.after_state)}</pre>
                  </div>
                </div>
              ) : null}
            </div>
          </div>

          <div className="modal-actions">
            <button type="button" className="modal-btn-primary" onClick={() => setSelected(null)}>
              Close
            </button>
          </div>
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
                          <code>{event.action}</code>
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
