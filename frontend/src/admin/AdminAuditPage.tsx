import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";
import Chart from "react-apexcharts";
import type { ApexOptions } from "apexcharts";
import { api } from "../lib/api";
import { parseUtc } from "../lib/time";

export type AuditUser = {
  id?: string;
  display_name: string;
  username: string | null;
  email: string;
  role?: string;
};

export type GeoProvider = {
  provider?: string;
  city?: string | null;
  region?: string | null;
  country?: string | null;
  isp?: string | null;
};

export type GeoInfo = {
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

type Overview = {
  status: "safe" | "warning" | "critical";
  reason: string;
  window_minutes: number;
  totals_15m: {
    requests: number;
    suspicious: number;
    by_severity: Record<string, number>;
    by_classification: Record<string, number>;
  };
  volume_60m: { t: string; count: number }[];
  server_time: string;
};

type AiSuggestion = {
  title: string;
  family: string;
  priority: string;
  steps: string[];
};

type AiAnalyze = {
  status: string;
  summary: string;
  suggestions: AiSuggestion[];
  model?: string;
  provider?: string;
  sample_size?: number;
};

export type WidgetId = "posture" | "kpi" | "velocity_chart" | "threat_vectors" | "ai_copilot" | "audit_ledger";
export type WidgetColSpan = 4 | 5 | 6 | 7 | 8 | 12;
export type WidgetHeight = "compact" | "normal" | "tall";

export type WidgetState = {
  id: WidgetId;
  title: string;
  span: WidgetColSpan;
  height: WidgetHeight;
  visible: boolean;
  collapsed: boolean;
};

const DEFAULT_WIDGETS: WidgetState[] = [
  { id: "posture", title: "Threat Posture & Health", span: 4, height: "normal", visible: true, collapsed: false },
  { id: "kpi", title: "Operational Metric Horizon", span: 8, height: "normal", visible: true, collapsed: false },
  { id: "velocity_chart", title: "60m Attack Velocity Curve", span: 7, height: "normal", visible: true, collapsed: false },
  { id: "threat_vectors", title: "Attack Classification Matrix", span: 5, height: "normal", visible: true, collapsed: false },
  { id: "ai_copilot", title: "AI Security Copilot & Remediation", span: 12, height: "normal", visible: true, collapsed: false },
  { id: "audit_ledger", title: "Live Security & Audit Ledger", span: 12, height: "tall", visible: true, collapsed: false },
];

const STORAGE_KEY = "veritas_draggable_dashboard_v3";

type Category = "" | "attacks" | "api" | "auth_failures" | "auth" | "admin" | "workspace";
type SeverityFilter = "" | "info" | "low" | "medium" | "high" | "critical";

const PAGE_SIZE = 50;

const FILTERS = [
  ["", "All"],
  ["attacks", "Attacks"],
  ["api", "API Calls"],
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

const CLASS_META: { key: string; label: string; color: string }[] = [
  { key: "clean", label: "Clean", color: "#94a3b8" },
  { key: "sqli", label: "SQLi", color: "#dc2626" },
  { key: "xss", label: "XSS", color: "#ea580c" },
  { key: "cmd_inject", label: "Cmd", color: "#b91c1c" },
  { key: "path_traversal", label: "LFI", color: "#c2410c" },
  { key: "ssrf", label: "SSRF", color: "#a16207" },
  { key: "ssti", label: "SSTI", color: "#854d0e" },
  { key: "open_redirect", label: "Redirect", color: "#ca8a04" },
  { key: "header_abuse", label: "Headers", color: "#7c3aed" },
  { key: "csrf", label: "CSRF", color: "#d97706" },
  { key: "scanner", label: "Scanner", color: "#0369a1" },
  { key: "auth_anomaly", label: "Auth", color: "#0284c7" },
  { key: "weak_headers", label: "Weak resp", color: "#64748b" },
];

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
  if (
    action.includes("failed") ||
    action.includes("rejected") ||
    action.includes("blocked") ||
    action === "rate_limited" ||
    action.startsWith("api_")
  )
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
  else if (/linux/i.test(ua)) os = "Linux";
  else if (/iphone|ipad|ipod/i.test(ua)) os = "iOS";

  let browser = "Unknown browser";
  if (/edg\//i.test(ua)) browser = "Microsoft Edge";
  else if (/chrome|crios/i.test(ua)) browser = "Google Chrome";
  else if (/firefox|fxios/i.test(ua)) browser = "Mozilla Firefox";
  else if (/safari/i.test(ua) && !/chrome/i.test(ua)) browser = "Apple Safari";
  else if (/python-requests/i.test(ua)) browser = "Python Requests";
  else if (/curl/i.test(ua)) browser = "cURL client";

  return { browser, os };
}

function getInitials(name: string, fallback: string = "?"): string {
  const parts = name.trim().split(/\s+/);
  if (!parts.length || !parts[0]) return fallback;
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function formatTime(iso: string) {
  const d = parseUtc(iso) || new Date(iso);
  if (Number.isNaN(d.getTime())) return { relative: "—", full: "—", timeOnly: "—" };
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  let relative = "just now";
  if (diffSec >= 60 && diffSec < 3600) relative = `${Math.floor(diffSec / 60)}m ago`;
  else if (diffSec >= 3600 && diffSec < 86400) relative = `${Math.floor(diffSec / 3600)}h ago`;
  else if (diffSec >= 86400) relative = `${Math.floor(diffSec / 86400)}d ago`;

  return {
    relative,
    full: d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" }),
    timeOnly: d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  };
}

/**
 * Supreme Interactive Security & Audit Dashboard with Draggable & Resizable Widgets.
 */
export function AdminAuditPage() {
  // Widget Grid Configuration
  const [widgets, setWidgets] = useState<WidgetState[]>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          // Merge with defaults to pick up any new fields
          return DEFAULT_WIDGETS.map((def) => {
            const found = parsed.find((p: WidgetState) => p.id === def.id);
            return found ? { ...def, ...found } : def;
          });
        }
      }
    } catch {
      // fallback
    }
    return DEFAULT_WIDGETS;
  });

  const [isEditMode, setIsEditMode] = useState(false);
  const [draggedWidgetId, setDraggedWidgetId] = useState<WidgetId | null>(null);
  const [dragOverWidgetId, setDragOverWidgetId] = useState<WidgetId | null>(null);
  const [addWidgetOpen, setAddWidgetOpen] = useState(false);

  // Timeframe and Telemetry States
  const [timeframe, setTimeframe] = useState<"24h" | "7d">("24h");
  const [items, setItems] = useState<AuditEvent[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<AuditStatsResponse | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);

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

  // AI Copilot
  const [ai, setAi] = useState<AiAnalyze | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Persist widgets layout whenever changed
  const saveWidgets = useCallback((next: WidgetState[]) => {
    setWidgets(next);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // ignore
    }
  }, []);

  const resetLayout = useCallback(() => {
    setWidgets(DEFAULT_WIDGETS);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(DEFAULT_WIDGETS));
    } catch {
      // ignore
    }
  }, []);

  // Drag and drop handlers
  const handleDragStart = (id: WidgetId) => {
    setDraggedWidgetId(id);
  };

  const handleDragOver = (e: React.DragEvent, id: WidgetId) => {
    e.preventDefault();
    if (draggedWidgetId && draggedWidgetId !== id) {
      setDragOverWidgetId(id);
    }
  };

  const handleDrop = (targetId: WidgetId) => {
    if (!draggedWidgetId || draggedWidgetId === targetId) {
      setDraggedWidgetId(null);
      setDragOverWidgetId(null);
      return;
    }

    const current = [...widgets];
    const fromIndex = current.findIndex((w) => w.id === draggedWidgetId);
    const toIndex = current.findIndex((w) => w.id === targetId);

    if (fromIndex !== -1 && toIndex !== -1) {
      const [moved] = current.splice(fromIndex, 1);
      current.splice(toIndex, 0, moved);
      saveWidgets(current);
    }

    setDraggedWidgetId(null);
    setDragOverWidgetId(null);
  };

  const handleDragEnd = () => {
    setDraggedWidgetId(null);
    setDragOverWidgetId(null);
  };

  // Widget Actions: Resize, Collapse, Remove, Reorder
  const updateWidgetSpan = (id: WidgetId, span: WidgetColSpan) => {
    saveWidgets(widgets.map((w) => (w.id === id ? { ...w, span } : w)));
  };

  const updateWidgetHeight = (id: WidgetId, height: WidgetHeight) => {
    saveWidgets(widgets.map((w) => (w.id === id ? { ...w, height } : w)));
  };

  const toggleWidgetCollapse = (id: WidgetId) => {
    saveWidgets(widgets.map((w) => (w.id === id ? { ...w, collapsed: !w.collapsed } : w)));
  };

  const hideWidget = (id: WidgetId) => {
    saveWidgets(widgets.map((w) => (w.id === id ? { ...w, visible: false } : w)));
  };

  const showWidget = (id: WidgetId) => {
    saveWidgets(widgets.map((w) => (w.id === id ? { ...w, visible: true } : w)));
  };

  const moveWidget = (id: WidgetId, direction: "prev" | "next") => {
    const current = [...widgets];
    const idx = current.findIndex((w) => w.id === id);
    if (idx === -1) return;
    const targetIdx = direction === "prev" ? idx - 1 : idx + 1;
    if (targetIdx < 0 || targetIdx >= current.length) return;
    const temp = current[idx];
    current[idx] = current[targetIdx];
    current[targetIdx] = temp;
    saveWidgets(current);
  };

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

  const fetchStats = useCallback(async () => {
    try {
      const data = await api<AuditStatsResponse>("/admin/audit-stats");
      setStats(data);
    } catch {
      // transient
    }
  }, []);

  const fetchOverview = useCallback(async () => {
    try {
      const data = await api<Overview>("/admin/security-overview");
      setOverview(data);
    } catch {
      // transient
    }
  }, []);

  const runAi = useCallback(async () => {
    setAiLoading(true);
    setAiError(null);
    try {
      const result = await api<AiAnalyze>("/admin/security-analyze", { method: "POST", body: "{}" });
      setAi(result);
      if (result.status === "skipped_no_key") {
        setAiError(result.summary);
      }
    } catch (err) {
      setAiError((err as Error).message);
    } finally {
      setAiLoading(false);
    }
  }, []);

  const resetAndLoad = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSelected(null);
    setPage(1);
    try {
      const [eventsData, statsData, overviewData] = await Promise.all([
        api<AuditResponse>(buildQuery(1)),
        api<AuditStatsResponse>("/admin/audit-stats").catch(() => null),
        api<Overview>("/admin/security-overview").catch(() => null),
      ]);
      setItems(eventsData.items);
      setTotal(eventsData.total);
      if (statsData) setStats(statsData);
      if (overviewData) setOverview(overviewData);
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
      void fetchOverview();
    }, 15000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, fetchStats, fetchOverview]);

  // WebSocket Live Stream
  useEffect(() => {
    if (!autoRefresh) {
      setWsConnected(false);
      return;
    }

    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;
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

              // Increment KPI stats in real time
              setStats((prev) => {
                if (!prev) return prev;
                const isAttack =
                  newEvent.action.startsWith("api_") ||
                  ["login_failed", "login_blocked_status", "rate_limited"].includes(newEvent.action);
                const isAuthFailure =
                  ["login_failed", "login_blocked_status", "rate_limited", "api_auth_anomaly"].includes(newEvent.action);

                const updateBucket = (b: TimeframeStats): TimeframeStats => ({
                  ...b,
                  total_events: b.total_events + 1,
                  http_requests: b.http_requests + 1,
                  attacks_flagged: b.attacks_flagged + (isAttack ? 1 : 0),
                  auth_failures: b.auth_failures + (isAuthFailure ? 1 : 0),
                });

                return {
                  ...prev,
                  timeframe_24h: updateBucket(prev.timeframe_24h),
                  timeframe_7d: updateBucket(prev.timeframe_7d),
                };
              });

              setOverview((prev) => {
                if (!prev) return prev;
                const isAttack =
                  newEvent.action.startsWith("api_") ||
                  ["login_failed", "login_blocked_status", "rate_limited"].includes(newEvent.action);

                return {
                  ...prev,
                  totals_15m: {
                    ...prev.totals_15m,
                    requests: prev.totals_15m.requests + 1,
                    suspicious: prev.totals_15m.suspicious + (isAttack ? 1 : 0),
                  },
                };
              });

              const cat = categoryRef.current;
              const matchesCat =
                !cat ||
                (cat === "attacks" &&
                  (newEvent.action.startsWith("api_") ||
                    ["login_failed", "login_blocked_status", "rate_limited"].includes(newEvent.action))) ||
                (cat === "api" && newEvent.action.startsWith("api_")) ||
                (cat === "auth_failures" &&
                  (["login_failed", "login_blocked_status", "rate_limited"].includes(newEvent.action) ||
                    newEvent.action.startsWith("api_"))) ||
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
              const matchesSev = !sev || newEvent.severity === sev;
              const act = actionRef.current.trim().toLowerCase();
              const matchesAct = !act || newEvent.action.toLowerCase().includes(act);

              if (matchesCat && matchesSev && matchesAct) {
                setItems((prev) => {
                  const filtered = prev.filter((e) => e.id !== newEvent.id);
                  return [newEvent, ...filtered].slice(0, 300);
                });
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
          if (!isDisposed && autoRefresh) {
            reconnectTimer = window.setTimeout(connect, 2500);
          }
        };

        socket.onerror = () => {
          socket?.close();
        };
      } catch {
        setWsConnected(false);
      }
    }

    connect();

    return () => {
      isDisposed = true;
      window.clearInterval(pingTimer);
      window.clearTimeout(reconnectTimer);
      socket?.close();
      setWsConnected(false);
    };
  }, [autoRefresh]);

  // Infinite Scroll
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

  // Key handling for modal
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

  // Visual calculations
  const peakVolume = useMemo(
    () => Math.max(0, ...(overview?.volume_60m || []).map((b) => b.count)),
    [overview?.volume_60m]
  );

  const cleanPercentage = useMemo(() => {
    const req = overview?.totals_15m.requests || 0;
    if (!req) return 100;
    const clean = overview?.totals_15m.by_classification.clean || 0;
    return Math.round((clean / req) * 100);
  }, [overview]);

  // Circumference for the radial gauge (radius = 38)
  const gaugeCircumference = 2 * Math.PI * 38;
  const gaugeOffset = gaugeCircumference - (cleanPercentage / 100) * gaugeCircumference;

  const volumeOptions: ApexOptions = useMemo(() => {
    const max = Math.max(1, ...(overview?.volume_60m || []).map((b) => b.count));
    return {
      chart: {
        type: "area",
        toolbar: { show: false },
        animations: { enabled: true, speed: 300 },
        zoom: { enabled: false },
        fontFamily: "inherit",
        background: "transparent",
      },
      dataLabels: { enabled: false },
      stroke: { curve: "smooth", width: 2.5 },
      markers: {
        size: max <= 3 ? 3 : 0,
        colors: ["#0d9488"],
        strokeColors: "#fff",
        strokeWidth: 2,
        hover: { size: 5 },
      },
      fill: {
        type: "gradient",
        gradient: { shadeIntensity: 1, opacityFrom: 0.45, opacityTo: 0.05, stops: [0, 85, 100] },
      },
      colors: ["#0d9488"],
      grid: {
        borderColor: "#e2e8f0",
        strokeDashArray: 3,
        padding: { left: 4, right: 8, top: 12, bottom: 0 },
      },
      xaxis: {
        categories: (overview?.volume_60m || []).map((b) => {
          const d = parseUtc(b.t) || new Date(b.t);
          return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
        }),
        labels: { show: true, rotate: 0, hideOverlappingLabels: true, style: { colors: "#94a3b8", fontSize: "10px" } },
        axisBorder: { show: false },
        axisTicks: { show: false },
        tickAmount: 6,
      },
      yaxis: {
        min: 0,
        max: Math.max(4, Math.ceil(max * 1.25)),
        forceNiceScale: true,
        tickAmount: 4,
        labels: {
          style: { colors: "#94a3b8", fontSize: "10px" },
          formatter: (v) => String(Math.round(v)),
        },
      },
      tooltip: { theme: "light", y: { formatter: (v) => `${v} req/min` } },
    };
  }, [overview?.volume_60m]);

  const volumeSeries = useMemo(
    () => [{ name: "Requests / min", data: (overview?.volume_60m || []).map((b) => b.count) }],
    [overview?.volume_60m]
  );

  const activeClasses = useMemo(() => {
    const counts = overview?.totals_15m.by_classification || {};
    return CLASS_META.filter((m) => (counts[m.key] || 0) > 0);
  }, [overview]);

  const donutOptions: ApexOptions = useMemo(() => {
    const active = activeClasses.length ? activeClasses : CLASS_META.slice(0, 5);
    return {
      chart: {
        type: "donut",
        fontFamily: "inherit",
        animations: { enabled: true },
        background: "transparent",
      },
      labels: active.map((m) => m.label),
      colors: active.map((m) => m.color),
      legend: { position: "bottom", fontSize: "11px", markers: { size: 4 }, itemMargin: { horizontal: 6 } },
      dataLabels: { enabled: false },
      plotOptions: {
        pie: {
          donut: {
            size: "72%",
            labels: {
              show: true,
              total: {
                show: true,
                showAlways: true,
                label: "Requests",
                fontSize: "11px",
                fontWeight: 650,
                color: "#64748b",
                formatter: () => String(overview?.totals_15m.requests || 0),
              },
            },
          },
        },
      },
      stroke: { width: 2, colors: ["#fff"] },
    };
  }, [activeClasses, overview?.totals_15m.requests]);

  const donutSeries = useMemo(() => {
    const counts = overview?.totals_15m.by_classification || {};
    const active = activeClasses.length ? activeClasses : CLASS_META.slice(0, 5);
    return active.map((m) => counts[m.key] || 0);
  }, [activeClasses, overview?.totals_15m.by_classification]);

  const currentStats = stats ? (timeframe === "24h" ? stats.timeframe_24h : stats.timeframe_7d) : null;
  const status = overview?.status || "safe";
  const hiddenWidgets = widgets.filter((w) => !w.visible);

  // Deep Event Detail Inspector Modal
  const detailModal =
    selected &&
    createPortal(
      <div className="modal-root audit-modal-root" role="presentation">
        <button type="button" className="modal-backdrop" aria-label="Close" onClick={() => setSelected(null)} />
        <div className="modal-panel audit-modal" role="dialog" aria-modal="true" aria-labelledby="audit-detail-title">
          {(() => {
            const uaInfo = parseUserAgent(selected.user_agent);
            const actorName = displayName(selected.actor, selected.actor_user_id);
            const targetName = displayName(selected.target, selected.target_user_id);
            const method = (selected.how?.method || "HTTP").toUpperCase();

            return (
              <>
                <div className="audit-modal-head">
                  <div className="audit-modal-head-main">
                    <div className="audit-modal-kicker-row">
                      <span className="modal-kicker">Security telemetry inspector</span>
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

  // Render individual visual widgets
  const renderWidgetContent = (widget: WidgetState) => {
    switch (widget.id) {
      case "posture":
        return (
          <div className={`sec-widget-posture sec-posture-${status}`}>
            <div className="sec-gauge-wrap">
              <svg className="sec-radial-gauge" viewBox="0 0 96 96">
                <circle className="sec-gauge-bg" cx="48" cy="48" r="38" />
                <circle
                  className={`sec-gauge-progress sec-gauge-${status}`}
                  cx="48"
                  cy="48"
                  r="38"
                  strokeDasharray={gaugeCircumference}
                  strokeDashoffset={gaugeOffset}
                />
              </svg>
              <div className="sec-gauge-center">
                <span className="sec-gauge-val">{cleanPercentage}%</span>
                <span className="sec-gauge-sub">Clean</span>
              </div>
            </div>

            <div className="sec-posture-details">
              <div className="sec-posture-badge-row">
                <span className={`sec-posture-badge sec-posture-badge-${status}`}>
                  <span className="sec-posture-dot" />
                  {status.toUpperCase()}
                </span>
                <span className="sec-posture-tag">{overview?.totals_15m.requests ?? 0} req / 15m</span>
              </div>
              <p className="sec-posture-desc">{overview?.reason || "Operational telemetry stream nominal."}</p>
              <div className="sec-posture-mini-meta">
                <span>Suspicious: <b>{overview?.totals_15m.suspicious ?? 0}</b></span>
                <span>Peak: <b>{peakVolume}/min</b></span>
              </div>
            </div>
          </div>
        );

      case "kpi":
        return (
          <div className="sec-widget-kpi">
            <div className="sec-kpi-subhead-row">
              <span className="sec-kpi-subtext">
                {timeframe === "24h" ? "Real-time rolling 24-hour baseline" : "Aggregated 7-day threat history"}
              </span>
              <div className="audit-kpi-toggle-group">
                <button
                  type="button"
                  className={`audit-kpi-toggle-btn ${timeframe === "24h" ? "active" : ""}`}
                  onClick={() => setTimeframe("24h")}
                >
                  24h
                </button>
                <button
                  type="button"
                  className={`audit-kpi-toggle-btn ${timeframe === "7d" ? "active" : ""}`}
                  onClick={() => setTimeframe("7d")}
                >
                  7d
                </button>
              </div>
            </div>

            <div className="sec-kpi-quad-grid">
              <div className="sec-kpi-tile">
                <div className="sec-kpi-tile-top">
                  <span>TOTAL REQUESTS</span>
                  <div className="audit-kpi-icon icon-blue">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="2" y1="12" x2="22" y2="12" />
                    </svg>
                  </div>
                </div>
                <strong className="sec-kpi-tile-num">{currentStats ? currentStats.http_requests.toLocaleString() : "—"}</strong>
                <small>HTTP telemetry & API calls</small>
              </div>

              <div className="sec-kpi-tile">
                <div className="sec-kpi-tile-top">
                  <span>FLAGGED THREATS</span>
                  <div className="audit-kpi-icon icon-red">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    </svg>
                  </div>
                </div>
                <strong className="sec-kpi-tile-num text-red">
                  {currentStats ? currentStats.attacks_flagged.toLocaleString() : "—"}
                </strong>
                <small>SQLi, XSS, SSRF, LFI, Cmd</small>
              </div>

              <div className="sec-kpi-tile">
                <div className="sec-kpi-tile-top">
                  <span>AUTH FAILURES</span>
                  <div className="audit-kpi-icon icon-amber">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    </svg>
                  </div>
                </div>
                <strong className="sec-kpi-tile-num text-amber">
                  {currentStats ? currentStats.auth_failures.toLocaleString() : "—"}
                </strong>
                <small>Failed logins & probes</small>
              </div>

              <div className="sec-kpi-tile">
                <div className="sec-kpi-tile-top">
                  <span>UNIQUE CLIENT IPS</span>
                  <div className="audit-kpi-icon icon-emerald">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                      <circle cx="9" cy="7" r="4" />
                    </svg>
                  </div>
                </div>
                <strong className="sec-kpi-tile-num text-emerald">
                  {currentStats ? currentStats.unique_ips.toLocaleString() : "—"}
                </strong>
                <small>Active monitored endpoints</small>
              </div>
            </div>
          </div>
        );

      case "velocity_chart":
        return (
          <div className="sec-widget-chart-wrap">
            <div className="sec-chart-meta-bar">
              <span>Rolling 60m request frequency & attack spikes</span>
              <span className="sec-badge-tag">{peakVolume}/min peak</span>
            </div>
            <Chart options={volumeOptions} series={volumeSeries} type="area" height={210} />
          </div>
        );

      case "threat_vectors":
        return (
          <div className="sec-widget-vectors-wrap">
            <Chart options={donutOptions} series={donutSeries} type="donut" height={190} />
            <div className="sec-class-quick-filters">
              {CLASS_META.map((m) => {
                const count = overview?.totals_15m.by_classification[m.key] || 0;
                return (
                  <button
                    key={m.key}
                    type="button"
                    className={`sec-class-chip ${actionFilter.includes(m.key) ? "active" : ""}`}
                    onClick={() => {
                      setCategory(m.key === "clean" ? "" : "attacks");
                      setActionFilter(m.key === "clean" ? "" : `api_${m.key}`);
                    }}
                    title={`Filter by ${m.label} (${count})`}
                  >
                    <span className="sec-class-dot" style={{ background: m.color }} />
                    <span>{m.label}</span>
                    {count > 0 && <b>{count}</b>}
                  </button>
                );
              })}
            </div>
          </div>
        );

      case "ai_copilot":
        return (
          <div className="sec-widget-ai-wrap">
            <div className="sec-ai-top-bar">
              <span className="sec-ai-desc">
                Automated threat signature correlation and tailored defensive playbooks.
              </span>
              <button type="button" className="btn primary" onClick={() => void runAi()} disabled={aiLoading}>
                {aiLoading ? "Analyzing Telemetry…" : ai ? "Re-evaluate" : "Analyze Active Threats"}
              </button>
            </div>

            {aiError && <p className="sec-ai-msg warning">{aiError}</p>}
            {aiLoading && !ai && <p className="sec-ai-msg">AI Copilot is inspecting incoming traffic signatures…</p>}

            {ai && ai.status !== "skipped_no_key" && (
              <div className="sec-ai-body">
                <div className="sec-ai-summary-box">
                  <p className="sec-ai-summary">{ai.summary}</p>
                  {ai.model && <span className="sec-ai-meta">Model: {ai.model}</span>}
                </div>

                {ai.suggestions && ai.suggestions.length > 0 ? (
                  <div className="sec-cm-grid">
                    {ai.suggestions.map((item) => (
                      <div className="sec-cm-card" key={`${item.title}-${item.family}`}>
                        <div className="sec-cm-top">
                          <b>{item.title}</b>
                          <span className={`audit-sev sev-${severityTone(item.priority)}`}>
                            {item.priority.toUpperCase()}
                          </span>
                        </div>
                        <span className="sec-cm-family">Family: {item.family}</span>
                        <ul className="sec-cm-steps">
                          {item.steps.map((s, idx) => (
                            <li key={idx}>{s}</li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="sec-ai-msg">No countermeasures needed. Traffic signatures are currently nominal.</p>
                )}
              </div>
            )}

            {!ai && !aiLoading && !aiError && (
              <div className="sec-ai-empty">
                <span>Click "Analyze Active Threats" to produce intelligent triage recommendations.</span>
              </div>
            )}
          </div>
        );

      case "audit_ledger":
        return (
          <div className="sec-widget-ledger-wrap">
            {/* Ledger Toolbar */}
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
                  placeholder="Filter by action or endpoint…"
                  value={actionFilter}
                  onChange={(e) => setActionFilter(e.target.value)}
                  aria-label="Filter audit events"
                />
              </div>
            </div>

            {/* Ledger Table */}
            <div className="table-wrap sec-table-wrap" ref={scrollRef}>
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Principal (Actor)</th>
                    <th>Target</th>
                    <th>Action</th>
                    <th>Severity</th>
                    <th>Endpoint & Status</th>
                    <th>Origin IP</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((event) => {
                    const t = formatTime(event.created_at);
                    const actorName = displayName(event.actor, event.actor_user_id);
                    const targetName = displayName(event.target, event.target_user_id);
                    const method = (event.how?.method || "HTTP").toUpperCase();

                    return (
                      <tr
                        key={event.id}
                        className={event.action.startsWith("api_") ? "sec-row-flag" : ""}
                        onClick={() => setSelected(event)}
                      >
                        <td>
                          <span className="audit-time" title={t.full}>
                            <b>{t.relative}</b>
                            <small>{t.timeOnly}</small>
                          </span>
                        </td>
                        <td>
                          <span className="audit-person">
                            <b>{actorName}</b>
                            <small>{displayHandle(event.actor) || "System"}</small>
                          </span>
                        </td>
                        <td>
                          <span className="audit-person">
                            <b>{targetName}</b>
                            <small>{displayHandle(event.target) || "—"}</small>
                          </span>
                        </td>
                        <td>
                          <span className={`audit-tone tone-${actionTone(event.action)}`}>{event.action}</span>
                        </td>
                        <td>
                          <span className={`audit-sev sev-${severityTone(event.severity)}`}>
                            {(event.severity || "info").toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <div className="sec-cell-req">
                            <span className={`audit-method-tag method-${method.toLowerCase()}`}>{method}</span>
                            <span className="sec-req-path">{event.how?.path || "—"}</span>
                            <span className={`audit-status status-${statusTone(event.status_code ?? event.how?.status_code)}`}>
                              {event.status_code ?? event.how?.status_code ?? "—"}
                            </span>
                          </div>
                        </td>
                        <td>
                          <span className="audit-mono">{event.ip_address || "—"}</span>
                        </td>
                        <td>
                          <button
                            type="button"
                            className="btn ghost sec-inspect-row-btn"
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

              <div ref={sentinelRef} className="sec-sentinel" aria-hidden="true" />
              {loadingMore && <p className="sec-load-more">Loading more audit records…</p>}
              {!hasMore && items.length > 0 && <p className="sec-load-more">End of audit records</p>}
              {items.length === 0 && !loading && (
                <p className="sec-empty">No security or audit events match your selected filters.</p>
              )}
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <main className="admin-main sec-command-canvas">
      {/* Top Header Bar */}
      <header className="sec-canvas-head">
        <div>
          <div className="eyebrow">Interactive Security Workspace</div>
          <h1>Security Command Center & Audit Canvas</h1>
        </div>

        <div className="sec-canvas-actions">
          {/* Live WebSocket Status Toggle */}
          <button
            type="button"
            className={`audit-live-btn ${wsConnected ? "active ws" : autoRefresh ? "active" : ""}`}
            onClick={() => setAutoRefresh((prev) => !prev)}
            title={
              wsConnected
                ? "Live WebSocket connected. Instant updates active. Click to pause."
                : autoRefresh
                ? "Live polling active. Click to pause."
                : "Live updates paused. Click to resume."
            }
          >
            <span className={`audit-live-dot ${wsConnected || autoRefresh ? "pulse" : ""}`} />
            <span>{autoRefresh ? "Live" : "Paused"}</span>
          </button>

          {/* Toggle Edit / Layout Mode */}
          <button
            type="button"
            className={`btn ${isEditMode ? "primary" : "ghost"} sec-edit-mode-btn`}
            onClick={() => setIsEditMode((prev) => !prev)}
            title="Toggle Drag & Drop and Resizing mode"
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 20h9" />
              <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
            </svg>
            <span>{isEditMode ? "Done Customizing" : "Customize Layout"}</span>
          </button>

          {/* Add Widget Shelf Dropdown */}
          {hiddenWidgets.length > 0 && (
            <div className="sec-add-widget-wrap">
              <button
                type="button"
                className="btn ghost"
                onClick={() => setAddWidgetOpen((prev) => !prev)}
              >
                + Add Widget ({hiddenWidgets.length})
              </button>
              {addWidgetOpen && (
                <div className="sec-add-widget-dropdown">
                  {hiddenWidgets.map((hw) => (
                    <button
                      key={hw.id}
                      type="button"
                      className="sec-add-widget-opt"
                      onClick={() => {
                        showWidget(hw.id);
                        setAddWidgetOpen(false);
                      }}
                    >
                      <span>+ {hw.title}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Reset Canvas to Defaults */}
          {isEditMode && (
            <button
              type="button"
              className="btn ghost"
              onClick={resetLayout}
              title="Reset widgets to default layout"
            >
              Reset Canvas
            </button>
          )}

          {/* Manual Refresh */}
          <button type="button" className="btn ghost" onClick={() => void resetAndLoad()} disabled={loading}>
            Refresh
          </button>

          <Link className="btn ghost" to="/admin/">
            Overview
          </Link>
        </div>
      </header>

      {error && (
        <div className="notice error" role="alert">
          {error}
        </div>
      )}

      {/* Editing Mode Indicator Banner */}
      {isEditMode && (
        <div className="sec-edit-banner">
          <div className="sec-edit-banner-left">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <span>
              <b>Customization Active:</b> Drag widgets by their grip handle to reorder. Use the width controls to resize from 1/3 to Full width.
            </span>
          </div>
          <button type="button" className="btn primary sec-banner-done-btn" onClick={() => setIsEditMode(false)}>
            Finish Editing
          </button>
        </div>
      )}

      {/* 12-Column Interactive Drag & Drop / Resize Widget Grid */}
      <div className={`sec-widget-grid ${isEditMode ? "edit-mode-active" : ""}`}>
        {widgets
          .filter((w) => w.visible)
          .map((widget, index) => {
            const isDragging = draggedWidgetId === widget.id;
            const isDragOver = dragOverWidgetId === widget.id;

            return (
              <div
                key={widget.id}
                className={`sec-widget-card sec-col-${widget.span} sec-height-${widget.height} ${
                  isDragging ? "is-dragging" : ""
                } ${isDragOver ? "is-drag-over" : ""} ${widget.collapsed ? "is-collapsed" : ""}`}
                onDragOver={(e) => isEditMode && handleDragOver(e, widget.id)}
                onDrop={() => isEditMode && handleDrop(widget.id)}
              >
                {/* Widget Header with Drag Handle & Resize Tools */}
                <div className="sec-widget-header">
                  <div className="sec-widget-title-area">
                    {/* Drag Handle */}
                    {isEditMode && (
                      <div
                        className="sec-drag-handle"
                        draggable
                        onDragStart={() => handleDragStart(widget.id)}
                        onDragEnd={handleDragEnd}
                        title="Drag to reorder"
                      >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                          <circle cx="9" cy="5" r="1.5" />
                          <circle cx="15" cy="5" r="1.5" />
                          <circle cx="9" cy="12" r="1.5" />
                          <circle cx="15" cy="12" r="1.5" />
                          <circle cx="9" cy="19" r="1.5" />
                          <circle cx="15" cy="19" r="1.5" />
                        </svg>
                      </div>
                    )}
                    <h2 className="sec-widget-title">{widget.title}</h2>
                  </div>

                  {/* Widget Control Actions */}
                  <div className="sec-widget-controls">
                    {/* Width Resize Selector (Visible in Edit Mode) */}
                    {isEditMode && (
                      <div className="sec-size-segmented" title="Change widget width">
                        <button
                          type="button"
                          className={widget.span === 4 ? "active" : ""}
                          onClick={() => updateWidgetSpan(widget.id, 4)}
                          title="1/3 Width"
                        >
                          1/3
                        </button>
                        <button
                          type="button"
                          className={widget.span === 6 ? "active" : ""}
                          onClick={() => updateWidgetSpan(widget.id, 6)}
                          title="Half Width"
                        >
                          1/2
                        </button>
                        <button
                          type="button"
                          className={widget.span === 8 ? "active" : ""}
                          onClick={() => updateWidgetSpan(widget.id, 8)}
                          title="2/3 Width"
                        >
                          2/3
                        </button>
                        <button
                          type="button"
                          className={widget.span === 12 ? "active" : ""}
                          onClick={() => updateWidgetSpan(widget.id, 12)}
                          title="Full Width"
                        >
                          Full
                        </button>
                      </div>
                    )}

                    {/* Height Toggle (in Edit Mode) */}
                    {isEditMode && (
                      <button
                        type="button"
                        className="sec-ctrl-btn"
                        onClick={() =>
                          updateWidgetHeight(
                            widget.id,
                            widget.height === "normal" ? "tall" : widget.height === "tall" ? "compact" : "normal"
                          )
                        }
                        title={`Height: ${widget.height}. Click to cycle.`}
                      >
                        {widget.height === "compact" ? "S" : widget.height === "normal" ? "M" : "L"}
                      </button>
                    )}

                    {/* Move Left / Right Buttons */}
                    {isEditMode && (
                      <>
                        <button
                          type="button"
                          className="sec-ctrl-btn"
                          disabled={index === 0}
                          onClick={() => moveWidget(widget.id, "prev")}
                          title="Move Left / Up"
                        >
                          ←
                        </button>
                        <button
                          type="button"
                          className="sec-ctrl-btn"
                          disabled={index === widgets.filter((w) => w.visible).length - 1}
                          onClick={() => moveWidget(widget.id, "next")}
                          title="Move Right / Down"
                        >
                          →
                        </button>
                      </>
                    )}

                    {/* Collapse Button */}
                    <button
                      type="button"
                      className="sec-ctrl-btn"
                      onClick={() => toggleWidgetCollapse(widget.id)}
                      title={widget.collapsed ? "Expand widget" : "Collapse widget"}
                    >
                      {widget.collapsed ? "+" : "—"}
                    </button>

                    {/* Hide Widget Button */}
                    {isEditMode && (
                      <button
                        type="button"
                        className="sec-ctrl-btn sec-close-btn"
                        onClick={() => hideWidget(widget.id)}
                        title="Remove widget from canvas"
                      >
                        ✕
                      </button>
                    )}
                  </div>
                </div>

                {/* Widget Body Content */}
                {!widget.collapsed && <div className="sec-widget-body">{renderWidgetContent(widget)}</div>}
              </div>
            );
          })}
      </div>

      {detailModal}
    </main>
  );
}
