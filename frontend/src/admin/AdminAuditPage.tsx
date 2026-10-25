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

type HttpItem = {
  id: string;
  method: string;
  path: string;
  status_code: number;
  duration_ms: number;
  ip_address: string | null;
  classification: string;
  severity: string;
  signals: string[];
  created_at: string;
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
  recent_suspicious?: HttpItem[];
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

export type DashboardWidgetsConfig = {
  showPosture: boolean;
  showKpi: boolean;
  showVelocityChart: boolean;
  showClassification: boolean;
  showAiAgent: boolean;
  showLiveStream: boolean;
  showAuditTable: boolean;
  density: "comfortable" | "compact";
  defaultTimeframe: "24h" | "7d";
};

const DEFAULT_CONFIG: DashboardWidgetsConfig = {
  showPosture: true,
  showKpi: true,
  showVelocityChart: true,
  showClassification: true,
  showAiAgent: true,
  showLiveStream: true,
  showAuditTable: true,
  density: "comfortable",
  defaultTimeframe: "24h",
};

const STORAGE_KEY = "veritas_security_audit_dashboard_v2";

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

const PRESETS: Record<string, { label: string; desc: string; config: Partial<DashboardWidgetsConfig> }> = {
  soc: {
    label: "All-in-One SOC",
    desc: "Complete operational defense console with all telemetry and ledger widgets active.",
    config: {
      showPosture: true,
      showKpi: true,
      showVelocityChart: true,
      showClassification: true,
      showAiAgent: true,
      showLiveStream: true,
      showAuditTable: true,
    },
  },
  hunter: {
    label: "Threat Hunter",
    desc: "Optimized for threat hunting: velocity spikes, attack vectors, AI triage, and live stream.",
    config: {
      showPosture: true,
      showKpi: true,
      showVelocityChart: true,
      showClassification: true,
      showAiAgent: true,
      showLiveStream: true,
      showAuditTable: false,
    },
  },
  audit: {
    label: "Audit & Compliance",
    desc: "Focus on user actions, security ledger, state diffs, and compliance verification.",
    config: {
      showPosture: true,
      showKpi: true,
      showVelocityChart: false,
      showClassification: false,
      showAiAgent: false,
      showLiveStream: false,
      showAuditTable: true,
    },
  },
  live: {
    label: "Live Monitor",
    desc: "High-throughput live event ticker and primary KPI metrics.",
    config: {
      showPosture: true,
      showKpi: true,
      showVelocityChart: true,
      showClassification: true,
      showAiAgent: false,
      showLiveStream: true,
      showAuditTable: false,
    },
  },
};

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

/** Unified Security Command Center & Audit Intelligence Console. */
export function AdminAuditPage() {
  // Widget configuration with localStorage persistence
  const [widgets, setWidgets] = useState<DashboardWidgetsConfig>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) return { ...DEFAULT_CONFIG, ...JSON.parse(saved) };
    } catch {
      // ignore JSON errors
    }
    return DEFAULT_CONFIG;
  });

  const [customizerOpen, setCustomizerOpen] = useState(false);
  const [timeframe, setTimeframe] = useState<"24h" | "7d">(widgets.defaultTimeframe || "24h");

  // Core Data States
  const [items, setItems] = useState<AuditEvent[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<AuditStatsResponse | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);

  // Filters
  const [category, setCategory] = useState<Category>("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("");
  const [actionFilter, setActionFilter] = useState("");

  // Live Stream & Interaction
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // AI Security Agent
  const [ai, setAi] = useState<AiAnalyze | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Persistence handler
  const updateWidgets = useCallback((next: Partial<DashboardWidgetsConfig>) => {
    setWidgets((prev) => {
      const merged = { ...prev, ...next };
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
      } catch {
        // ignore storage quota
      }
      return merged;
    });
  }, []);

  const applyPreset = useCallback(
    (key: string) => {
      const preset = PRESETS[key];
      if (preset) updateWidgets(preset.config);
    },
    [updateWidgets]
  );

  const resetWidgetsToDefault = useCallback(() => {
    setWidgets(DEFAULT_CONFIG);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(DEFAULT_CONFIG));
    } catch {
      // ignore
    }
  }, []);

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

  // Fetch Telemetry & Stats
  const fetchStats = useCallback(async () => {
    try {
      const data = await api<AuditStatsResponse>("/admin/audit-stats");
      setStats(data);
    } catch {
      // transient poll error
    }
  }, []);

  const fetchOverview = useCallback(async () => {
    try {
      const data = await api<Overview>("/admin/security-overview");
      setOverview(data);
    } catch {
      // transient poll error
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

  // Periodic polling for stats & overview
  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => {
      void fetchStats();
      void fetchOverview();
    }, 15000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, fetchStats, fetchOverview]);

  // Real-time instant WebSocket live stream
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

              // Optimistically bump stats in real time
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

              // Also bump overview in real time
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
                  // Keep up to 300 live items in buffer so user can see all 300-500 requests as they stream in!
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

  // Infinite scroll loader
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

  // Modal keyboard handling
  useEffect(() => {
    if (!selected && !customizerOpen) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setSelected(null);
        setCustomizerOpen(false);
      }
    }
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [selected, customizerOpen]);

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

  const volumeOptions: ApexOptions = useMemo(() => {
    const max = Math.max(1, ...(overview?.volume_60m || []).map((b) => b.count));
    return {
      chart: {
        type: "area",
        toolbar: { show: false },
        animations: { enabled: true, speed: 350 },
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
  const activeWidgetCount = [
    widgets.showPosture,
    widgets.showKpi,
    widgets.showVelocityChart,
    widgets.showClassification,
    widgets.showAiAgent,
    widgets.showLiveStream,
    widgets.showAuditTable,
  ].filter(Boolean).length;

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

  // Customizer Drawer / Modal
  const customizerModal =
    customizerOpen &&
    createPortal(
      <div className="modal-root audit-modal-root" role="presentation">
        <button type="button" className="modal-backdrop" aria-label="Close" onClick={() => setCustomizerOpen(false)} />
        <div
          className="modal-panel sec-customizer-modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="customizer-modal-title"
        >
          <div className="audit-modal-head">
            <div className="audit-modal-head-main">
              <span className="modal-kicker">Dashboard Personalization</span>
              <h2 id="customizer-modal-title">Customize Security & Audit Workspace</h2>
              <p className="sec-customizer-desc">
                Enable or rearrange widgets, tune display density, and select operational presets for your console.
              </p>
            </div>
            <button
              type="button"
              className="modal-close"
              aria-label="Close"
              onClick={() => setCustomizerOpen(false)}
            >
              ×
            </button>
          </div>

          <div className="sec-customizer-body">
            {/* Presets */}
            <div className="sec-customizer-block">
              <h3 className="sec-customizer-heading">Operational Presets</h3>
              <div className="sec-preset-grid">
                {Object.entries(PRESETS).map(([key, item]) => (
                  <button
                    key={key}
                    type="button"
                    className="sec-preset-card"
                    onClick={() => applyPreset(key)}
                  >
                    <b>{item.label}</b>
                    <small>{item.desc}</small>
                  </button>
                ))}
              </div>
            </div>

            {/* Widgets Toggles */}
            <div className="sec-customizer-block">
              <h3 className="sec-customizer-heading">Active Dashboard Widgets</h3>
              <div className="sec-widget-toggle-list">
                <label className="sec-widget-toggle-item">
                  <div className="sec-toggle-info">
                    <b>System Threat Posture Banner</b>
                    <small>Real-time Safe / Warning / Critical threat diagnosis and clean traffic ratio.</small>
                  </div>
                  <input
                    type="checkbox"
                    checked={widgets.showPosture}
                    onChange={(e) => updateWidgets({ showPosture: e.target.checked })}
                  />
                </label>

                <label className="sec-widget-toggle-item">
                  <div className="sec-toggle-info">
                    <b>KPI Intelligence Metric Cards (24h / 7d)</b>
                    <small>Requests, attacks flagged, auth failures, and unique origin IP counters.</small>
                  </div>
                  <input
                    type="checkbox"
                    checked={widgets.showKpi}
                    onChange={(e) => updateWidgets({ showKpi: e.target.checked })}
                  />
                </label>

                <label className="sec-widget-toggle-item">
                  <div className="sec-toggle-info">
                    <b>Traffic Volume & Attack Velocity Chart</b>
                    <small>60-minute rolling request volume and attack surge curves.</small>
                  </div>
                  <input
                    type="checkbox"
                    checked={widgets.showVelocityChart}
                    onChange={(e) => updateWidgets({ showVelocityChart: e.target.checked })}
                  />
                </label>

                <label className="sec-widget-toggle-item">
                  <div className="sec-toggle-info">
                    <b>Threat Vector & Classification Breakdown</b>
                    <small>Interactive distribution of attack families (SQLi, XSS, SSRF, LFI, Cmd).</small>
                  </div>
                  <input
                    type="checkbox"
                    checked={widgets.showClassification}
                    onChange={(e) => updateWidgets({ showClassification: e.target.checked })}
                  />
                </label>

                <label className="sec-widget-toggle-item">
                  <div className="sec-toggle-info">
                    <b>AI Security Agent & Countermeasures</b>
                    <small>LLM/Groq-assisted threat classification and step-by-step mitigation advice.</small>
                  </div>
                  <input
                    type="checkbox"
                    checked={widgets.showAiAgent}
                    onChange={(e) => updateWidgets({ showAiAgent: e.target.checked })}
                  />
                </label>

                <label className="sec-widget-toggle-item">
                  <div className="sec-toggle-info">
                    <b>Real-Time Live Security Event Stream</b>
                    <small>Instant WebSocket event ticker streaming live traffic and attack probes.</small>
                  </div>
                  <input
                    type="checkbox"
                    checked={widgets.showLiveStream}
                    onChange={(e) => updateWidgets({ showLiveStream: e.target.checked })}
                  />
                </label>

                <label className="sec-widget-toggle-item">
                  <div className="sec-toggle-info">
                    <b>Audit Ledger & Deep Event Explorer</b>
                    <small>Complete tabular ledger with search, category filters, and deep inspector.</small>
                  </div>
                  <input
                    type="checkbox"
                    checked={widgets.showAuditTable}
                    onChange={(e) => updateWidgets({ showAuditTable: e.target.checked })}
                  />
                </label>
              </div>
            </div>

            {/* Display Density & Defaults */}
            <div className="sec-customizer-grid-2">
              <div className="sec-customizer-block">
                <h3 className="sec-customizer-heading">Display Density</h3>
                <div className="sec-customizer-radio-group">
                  <label className={`sec-radio-card ${widgets.density === "comfortable" ? "active" : ""}`}>
                    <input
                      type="radio"
                      name="density"
                      value="comfortable"
                      checked={widgets.density === "comfortable"}
                      onChange={() => updateWidgets({ density: "comfortable" })}
                    />
                    <span>Comfortable</span>
                  </label>
                  <label className={`sec-radio-card ${widgets.density === "compact" ? "active" : ""}`}>
                    <input
                      type="radio"
                      name="density"
                      value="compact"
                      checked={widgets.density === "compact"}
                      onChange={() => updateWidgets({ density: "compact" })}
                    />
                    <span>Compact (SOC view)</span>
                  </label>
                </div>
              </div>

              <div className="sec-customizer-block">
                <h3 className="sec-customizer-heading">Default Timeframe</h3>
                <div className="sec-customizer-radio-group">
                  <label className={`sec-radio-card ${widgets.defaultTimeframe === "24h" ? "active" : ""}`}>
                    <input
                      type="radio"
                      name="defaultTimeframe"
                      value="24h"
                      checked={widgets.defaultTimeframe === "24h"}
                      onChange={() => {
                        updateWidgets({ defaultTimeframe: "24h" });
                        setTimeframe("24h");
                      }}
                    />
                    <span>Last 24 Hours</span>
                  </label>
                  <label className={`sec-radio-card ${widgets.defaultTimeframe === "7d" ? "active" : ""}`}>
                    <input
                      type="radio"
                      name="defaultTimeframe"
                      value="7d"
                      checked={widgets.defaultTimeframe === "7d"}
                      onChange={() => {
                        updateWidgets({ defaultTimeframe: "7d" });
                        setTimeframe("7d");
                      }}
                    />
                    <span>Last 7 Days</span>
                  </label>
                </div>
              </div>
            </div>
          </div>

          <div className="audit-modal-footer">
            <button type="button" className="btn ghost" onClick={resetWidgetsToDefault}>
              Reset to Defaults
            </button>
            <button type="button" className="btn primary" onClick={() => setCustomizerOpen(false)}>
              Done
            </button>
          </div>
        </div>
      </div>,
      document.body
    );

  return (
    <main className={`admin-main sec-command-center ${widgets.density === "compact" ? "sec-density-compact" : ""}`}>
      {/* Header */}
      <header className="sec-dash-head">
        <div>
          <div className="eyebrow">Monitoring & Threat Defense</div>
          <h1>Security Command Center & Audit Intelligence</h1>
        </div>
        <div className="sec-dash-actions">
          {/* Live Stream Status Toggle */}
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

          {/* Customize Button */}
          <button
            type="button"
            className="btn ghost sec-customize-btn"
            onClick={() => setCustomizerOpen(true)}
            title="Configure widgets, density, and presets"
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
            <span>Customize</span>
            <span className="sec-customizer-badge">{activeWidgetCount}/7</span>
          </button>

          {/* AI Analyze Trigger */}
          <button
            type="button"
            className="btn ghost"
            onClick={() => void runAi()}
            disabled={aiLoading}
            title="Analyze active threats using AI security agent"
          >
            {aiLoading ? "Analyzing…" : "AI Triage"}
          </button>

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

      {/* WIDGET 1: System Posture & KPI Intelligence */}
      {(widgets.showPosture || widgets.showKpi) && (
        <section className="sec-posture-kpi-row" aria-label="Security Posture and KPI Metrics">
          {/* Posture Card */}
          {widgets.showPosture && (
            <div className={`sec-posture-card sec-posture-${status}`}>
              <div className="sec-posture-top">
                <span className="sec-posture-label">System Posture</span>
                <span className={`sec-posture-badge sec-posture-badge-${status}`}>
                  <span className="sec-posture-dot" />
                  {status.toUpperCase()}
                </span>
              </div>
              <div className="sec-posture-reason">{overview?.reason || "Operational telemetry stream nominal."}</div>
              <div className="sec-posture-bar-wrap">
                <div className="sec-posture-bar-label">
                  <span>Clean traffic ratio</span>
                  <b>{cleanPercentage}%</b>
                </div>
                <div className="sec-posture-bar">
                  <div
                    className={`sec-posture-bar-fill ${cleanPercentage < 80 ? "warn" : ""}`}
                    style={{ width: `${cleanPercentage}%` }}
                  />
                </div>
              </div>
              <div className="sec-posture-meta">
                <span>15m requests: {overview?.totals_15m.requests ?? 0}</span>
                <span>Flagged: {overview?.totals_15m.suspicious ?? 0}</span>
              </div>
            </div>
          )}

          {/* 4 KPI Cards with 24h / 7d toggle */}
          {widgets.showKpi && (
            <div className="audit-kpi-section sec-kpi-flexible">
              <div className="audit-kpi-header">
                <div className="audit-kpi-title-box">
                  <span className="audit-kpi-title">Traffic & Exploits Horizon</span>
                  <span className="audit-kpi-subhead">
                    {timeframe === "24h"
                      ? "Real-time rolling metrics for past 24 hours"
                      : "Aggregated activity across past 7 days"}
                  </span>
                </div>
                <div className="audit-kpi-toggle-group" role="group" aria-label="Metric timeframe">
                  <button
                    type="button"
                    className={`audit-kpi-toggle-btn ${timeframe === "24h" ? "active" : ""}`}
                    onClick={() => setTimeframe("24h")}
                  >
                    Last 24 Hours
                  </button>
                  <button
                    type="button"
                    className={`audit-kpi-toggle-btn ${timeframe === "7d" ? "active" : ""}`}
                    onClick={() => setTimeframe("7d")}
                  >
                    Last 7 Days
                  </button>
                </div>
              </div>

              <div className="audit-kpi-grid">
                <div className="audit-kpi-card">
                  <div className="audit-kpi-top">
                    <span className="audit-kpi-label">Total Requests</span>
                    <div className="audit-kpi-icon icon-blue">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="2" y1="12" x2="22" y2="12" />
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                      </svg>
                    </div>
                  </div>
                  <div className="audit-kpi-value">
                    {currentStats ? currentStats.http_requests.toLocaleString() : "—"}
                  </div>
                  <div className="audit-kpi-sub">
                    <span>Peak {peakVolume}/min in last hour</span>
                  </div>
                </div>

                <div className="audit-kpi-card">
                  <div className="audit-kpi-top">
                    <span className="audit-kpi-label">Threats & Exploits</span>
                    <div className="audit-kpi-icon icon-red">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                        <line x1="12" y1="9" x2="12" y2="13" />
                        <line x1="12" y1="17" x2="12.01" y2="17" />
                      </svg>
                    </div>
                  </div>
                  <div className="audit-kpi-value text-red">
                    {currentStats ? currentStats.attacks_flagged.toLocaleString() : "—"}
                  </div>
                  <div className="audit-kpi-sub">
                    <span>SQLi, XSS, SSRF, LFI, SSTI, Cmd</span>
                  </div>
                </div>

                <div className="audit-kpi-card">
                  <div className="audit-kpi-top">
                    <span className="audit-kpi-label">Auth Failures</span>
                    <div className="audit-kpi-icon icon-amber">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                      </svg>
                    </div>
                  </div>
                  <div className="audit-kpi-value text-amber">
                    {currentStats ? currentStats.auth_failures.toLocaleString() : "—"}
                  </div>
                  <div className="audit-kpi-sub">
                    <span>Failed logins & probe errors</span>
                  </div>
                </div>

                <div className="audit-kpi-card">
                  <div className="audit-kpi-top">
                    <span className="audit-kpi-label">Unique IPs</span>
                    <div className="audit-kpi-icon icon-emerald">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                        <circle cx="9" cy="7" r="4" />
                        <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                        <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                      </svg>
                    </div>
                  </div>
                  <div className="audit-kpi-value text-emerald">
                    {currentStats ? currentStats.unique_ips.toLocaleString() : "—"}
                  </div>
                  <div className="audit-kpi-sub">
                    <span>Monitored client origins</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {/* WIDGET 2 & 3: Visual Analytics Row */}
      {(widgets.showVelocityChart || widgets.showClassification) && (
        <section className="sec-charts-grid" aria-label="Visual Security Analytics">
          {widgets.showVelocityChart && (
            <div className="sec-panel sec-chart-wide">
              <div className="sec-panel-head">
                <div>
                  <h2 className="sec-panel-title">Request Volume & Surge Velocity</h2>
                  <span className="sec-panel-sub">60-minute rolling HTTP request activity</span>
                </div>
                <span className="sec-badge-tag">{peakVolume}/min peak</span>
              </div>
              <Chart options={volumeOptions} series={volumeSeries} type="area" height={220} />
            </div>
          )}

          {widgets.showClassification && (
            <div className="sec-panel sec-chart-side">
              <div className="sec-panel-head">
                <div>
                  <h2 className="sec-panel-title">Threat Classification</h2>
                  <span className="sec-panel-sub">15-minute attack vectors distribution</span>
                </div>
                <span className="sec-badge-tag">{overview?.totals_15m.requests || 0} req</span>
              </div>
              <Chart options={donutOptions} series={donutSeries} type="donut" height={200} />
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
          )}
        </section>
      )}

      {/* WIDGET 4: AI Security Agent & Countermeasures */}
      {widgets.showAiAgent && (
        <section className="sec-panel sec-ai-section" aria-label="AI Threat Triage and Countermeasures">
          <div className="sec-panel-head">
            <div>
              <h2 className="sec-panel-title">AI Threat Agent & Countermeasures</h2>
              <span className="sec-panel-sub">
                Heuristic and model-guided threat classification with tailored defensive steps.
              </span>
            </div>
            <button type="button" className="btn primary" onClick={() => void runAi()} disabled={aiLoading}>
              {aiLoading ? "Analyzing Telemetry…" : ai ? "Re-analyze" : "Analyze Active Traffic"}
            </button>
          </div>

          {aiError && <p className="sec-ai-msg warning">{aiError}</p>}
          {aiLoading && !ai && <p className="sec-ai-msg">Agent is evaluating recent attack vectors and patterns…</p>}

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
                <p className="sec-ai-msg">No specific countermeasures needed. Current traffic contains no anomalous payloads.</p>
              )}
            </div>
          )}

          {!ai && !aiLoading && !aiError && (
            <div className="sec-ai-empty">
              <span>Run the AI security agent to evaluate incoming simulator and API traffic against threat intelligence rules.</span>
            </div>
          )}
        </section>
      )}

      {/* WIDGET 5: Real-Time Live Security Stream Ticker */}
      {widgets.showLiveStream && (
        <section className="sec-panel sec-stream-section" aria-label="Live Security Stream">
          <div className="sec-panel-head">
            <div className="sec-stream-head-title">
              <span className="audit-live-dot pulse" />
              <h2 className="sec-panel-title">Real-Time Security Event Stream</h2>
            </div>
            <span className="sec-badge-tag">{items.length} events buffered</span>
          </div>

          <div className="sec-stream-list">
            {items.slice(0, 8).map((evt) => {
              const method = (evt.how?.method || "HTTP").toUpperCase();
              return (
                <div className="sec-stream-row" key={`stream-${evt.id}`} onClick={() => setSelected(evt)}>
                  <span className="sec-stream-time">{formatTime(evt.created_at).timeOnly}</span>
                  <span className={`audit-method-tag method-${method.toLowerCase()}`}>{method}</span>
                  <code className="sec-stream-path">{evt.how?.path || evt.summary || evt.action}</code>
                  <span className={`audit-tone tone-${actionTone(evt.action)}`}>{evt.action}</span>
                  <span className={`audit-sev sev-${severityTone(evt.severity)}`}>
                    {(evt.severity || "info").toUpperCase()}
                  </span>
                  <span className={`audit-status status-${statusTone(evt.status_code ?? evt.how?.status_code)}`}>
                    {evt.status_code ?? evt.how?.status_code ?? "—"}
                  </span>
                  <span className="sec-stream-ip">{evt.ip_address || "—"}</span>
                  <button type="button" className="sec-stream-btn">
                    Inspect
                  </button>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* WIDGET 6: Audit Ledger & Deep Event Explorer */}
      {widgets.showAuditTable && (
        <section className="sec-panel sec-ledger-section" aria-label="Comprehensive Audit Ledger">
          <div className="sec-panel-head">
            <div>
              <h2 className="sec-panel-title">Audit Ledger & Security Explorer</h2>
              <span className="sec-panel-sub">Search, filter, and inspect detailed security records.</span>
            </div>
            <span className="sec-badge-tag">{total.toLocaleString()} total logged</span>
          </div>

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
        </section>
      )}

      {detailModal}
      {customizerModal}
    </main>
  );
}
