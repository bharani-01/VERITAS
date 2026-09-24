import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import Chart from "react-apexcharts";
import type { ApexOptions } from "apexcharts";
import { LoadingMark } from "../components/LoadingMark";
import { useDocumentTitle } from "../lib/documentTitle";
import { api } from "../lib/api";
import { parseUtc } from "../lib/time";

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
  recent_suspicious: HttpItem[];
  countermeasures: Record<string, string[]>;
  server_time: string;
};

type TrafficResponse = {
  items: HttpItem[];
  total: number;
};

type Scope = "all" | "flagged";
type ClassFilter = "" | "clean" | "sqli" | "xss" | "csrf" | "auth_anomaly";
type SevFilter = "" | "info" | "low" | "medium" | "high" | "critical";

const POLL_MS = 4000;

const STATUS_LABEL: Record<Overview["status"], string> = {
  safe: "Safe",
  warning: "Warning",
  critical: "Critical",
};

const DEFAULT_TIPS: Record<string, string[]> = {
  sqli: [
    "Use parameterized queries — never concatenate user input into SQL.",
    "Validate IDs and filters; reject unexpected characters.",
  ],
  xss: [
    "Encode output for HTML/JS contexts; prefer framework auto-escaping.",
    "Set a strict Content-Security-Policy.",
  ],
  csrf: [
    "Verify Origin/Referer on state-changing cookie-authenticated requests.",
    "Use SameSite cookies and anti-CSRF tokens for mutations.",
  ],
  auth_anomaly: [
    "Rate-limit auth endpoints and review failed sign-in audit events.",
    "Alert on bursts of 401/403/429 from a single IP.",
  ],
};

function formatTime(iso: string) {
  const d = parseUtc(iso) || new Date(NaN);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function classLabel(c: string) {
  if (c === "sqli") return "SQLi";
  if (c === "xss") return "XSS";
  if (c === "csrf") return "CSRF";
  if (c === "auth_anomaly") return "Auth anomaly";
  return "Clean";
}

function statusTone(code: number): string {
  if (code >= 200 && code < 300) return "ok";
  if (code >= 400 && code < 500) return "client";
  if (code >= 500) return "server";
  return "muted";
}

/** Admin Security dashboard — live HTTP telemetry + ApexCharts. */
export function AdminSecurityPage() {
  useDocumentTitle("Security");
  const [data, setData] = useState<Overview | null>(null);
  const [traffic, setTraffic] = useState<HttpItem[]>([]);
  const [trafficTotal, setTrafficTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [scope, setScope] = useState<Scope>("all");
  const [classFilter, setClassFilter] = useState<ClassFilter>("");
  const [sevFilter, setSevFilter] = useState<SevFilter>("");
  const [pathQuery, setPathQuery] = useState("");

  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      params.set("page", "1");
      params.set("page_size", "50");
      if (classFilter) params.set("classification", classFilter);
      if (sevFilter) params.set("severity", sevFilter);

      const [overview, feed] = await Promise.all([
        api<Overview>("/admin/security-overview"),
        api<TrafficResponse>(`/admin/http-requests?${params.toString()}`),
      ]);

      setData(overview);
      setTraffic(feed.items);
      setTrafficTotal(feed.total);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [classFilter, sevFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => void load(), POLL_MS);
    return () => window.clearInterval(timer);
  }, [autoRefresh, load]);

  const visibleTraffic = useMemo(() => {
    let items = traffic;
    if (scope === "flagged") {
      items = items.filter((r) => r.classification !== "clean");
    }
    const q = pathQuery.trim().toLowerCase();
    if (q) {
      items = items.filter((r) => `${r.method} ${r.path}`.toLowerCase().includes(q));
    }
    return items;
  }, [traffic, scope, pathQuery]);

  const peak = useMemo(() => Math.max(0, ...(data?.volume_60m || []).map((b) => b.count)), [data?.volume_60m]);
  const cleanPct = useMemo(() => {
    const req = data?.totals_15m.requests || 0;
    if (!req) return 100;
    const clean = data?.totals_15m.by_classification.clean || 0;
    return Math.round((clean / req) * 100);
  }, [data]);

  const classTotal = useMemo(() => classSeriesSum(data), [data]);

  const volumeOptions: ApexOptions = useMemo(
    () => ({
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
      fill: {
        type: "gradient",
        gradient: { shadeIntensity: 1, opacityFrom: 0.32, opacityTo: 0.04, stops: [0, 85, 100] },
      },
      colors: ["#0d9488"],
      grid: {
        borderColor: "#e8edf2",
        strokeDashArray: 3,
        padding: { left: 4, right: 8, top: 8 },
      },
      xaxis: {
        categories: (data?.volume_60m || []).map((b) => {
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
        forceNiceScale: true,
        labels: { style: { colors: "#94a3b8", fontSize: "10px" } },
      },
      tooltip: { theme: "light", y: { formatter: (v) => `${v} req` } },
    }),
    [data?.volume_60m]
  );

  const volumeSeries = useMemo(
    () => [{ name: "Requests / min", data: (data?.volume_60m || []).map((b) => b.count) }],
    [data?.volume_60m]
  );

  const classOptions: ApexOptions = useMemo(
    () => ({
      chart: { type: "donut", fontFamily: "inherit", animations: { enabled: true }, background: "transparent" },
      labels: ["Clean", "SQLi", "XSS", "CSRF", "Auth"],
      colors: ["#94a3b8", "#dc2626", "#ea580c", "#ca8a04", "#0284c7"],
      legend: { position: "bottom", fontSize: "11px", markers: { size: 5 }, itemMargin: { horizontal: 6 } },
      dataLabels: { enabled: false },
      plotOptions: {
        pie: {
          donut: {
            size: "72%",
            labels: {
              show: true,
              name: { show: false },
              value: { show: false },
              total: {
                show: true,
                showAlways: true,
                label: "requests",
                fontSize: "11px",
                fontWeight: 600,
                color: "#64748b",
                formatter: () => String(classTotal),
              },
            },
          },
        },
      },
      stroke: { width: 2, colors: ["#fff"] },
      tooltip: { y: { formatter: (v) => `${v}` } },
    }),
    [classTotal]
  );

  const classSeries = useMemo(() => {
    const c = data?.totals_15m.by_classification || {};
    return [c.clean || 0, c.sqli || 0, c.xss || 0, c.csrf || 0, c.auth_anomaly || 0];
  }, [data?.totals_15m.by_classification]);

  const sevOptions: ApexOptions = useMemo(
    () => ({
      chart: { type: "bar", toolbar: { show: false }, fontFamily: "inherit", animations: { enabled: true }, background: "transparent" },
      plotOptions: { bar: { borderRadius: 4, columnWidth: "52%", distributed: true } },
      colors: ["#94a3b8", "#0284c7", "#ca8a04", "#ea580c", "#dc2626"],
      dataLabels: { enabled: false },
      legend: { show: false },
      grid: { borderColor: "#e8edf2", strokeDashArray: 3, padding: { left: 0, right: 0 } },
      xaxis: {
        categories: ["Info", "Low", "Med", "High", "Crit"],
        labels: { style: { colors: "#94a3b8", fontSize: "10px" } },
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      yaxis: {
        min: 0,
        forceNiceScale: true,
        labels: { style: { colors: "#94a3b8", fontSize: "10px" } },
      },
      tooltip: { theme: "light" },
    }),
    []
  );

  const sevSeries = useMemo(() => {
    const s = data?.totals_15m.by_severity || {};
    return [
      {
        name: "Count",
        data: [s.info || 0, s.low || 0, s.medium || 0, s.high || 0, s.critical || 0],
      },
    ];
  }, [data?.totals_15m.by_severity]);

  if (loading && !data) {
    return (
      <main className="admin-main sec-dash">
        <LoadingMark label="Loading security overview…" />
      </main>
    );
  }

  const status = data?.status || "safe";
  const cmEntries = Object.entries(data?.countermeasures || {});
  const tipEntries = cmEntries.length ? cmEntries : Object.entries(DEFAULT_TIPS).slice(0, 2);

  return (
    <main className="admin-main sec-dash">
      <header className="sec-dash-head">
        <div>
          <div className="eyebrow">Monitoring</div>
          <h1>Security</h1>
        </div>
        <div className="sec-dash-actions">
          <span className={`sec-live-pill sec-live-${status}`}>
            <span className="sec-live-dot" aria-hidden="true" />
            {STATUS_LABEL[status]}
          </span>
          <label className="sec-auto">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            Live
          </label>
          <button type="button" className="btn ghost" onClick={() => void load()} disabled={loading}>
            Refresh
          </button>
          <Link className="btn ghost" to="/admin/audit">
            Audit log
          </Link>
        </div>
      </header>

      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}

      <section className="sec-metrics" aria-label="Key metrics">
        <article>
          <small>Status</small>
          <b className={`sec-metric-status sec-metric-${status}`}>{STATUS_LABEL[status]}</b>
          <span>{data?.reason || "—"}</span>
        </article>
        <article>
          <small>Requests · 15m</small>
          <b>{data?.totals_15m.requests ?? 0}</b>
          <span>Peak {peak}/min · last hour</span>
        </article>
        <article>
          <small>Flagged · 15m</small>
          <b>{data?.totals_15m.suspicious ?? 0}</b>
          <span>
            SQLi {data?.totals_15m.by_classification.sqli ?? 0} · XSS {data?.totals_15m.by_classification.xss ?? 0} · CSRF{" "}
            {data?.totals_15m.by_classification.csrf ?? 0}
          </span>
        </article>
        <article>
          <small>Clean rate</small>
          <b>{cleanPct}%</b>
          <span>{data?.totals_15m.by_classification.clean ?? 0} clean of {data?.totals_15m.requests ?? 0}</span>
        </article>
      </section>

      <section className="sec-charts">
        <div className="sec-panel sec-chart-wide">
          <div className="sec-panel-head">
            <h2>Request volume</h2>
            <span>Last 60 minutes</span>
          </div>
          <Chart options={volumeOptions} series={volumeSeries} type="area" height={228} />
        </div>
        <div className="sec-chart-side">
          <div className="sec-panel">
            <div className="sec-panel-head">
              <h2>Classification</h2>
              <span>{classTotal} · 15m</span>
            </div>
            <Chart options={classOptions} series={classSeries} type="donut" height={210} />
          </div>
          <div className="sec-panel">
            <div className="sec-panel-head">
              <h2>Severity</h2>
              <span>15m</span>
            </div>
            <Chart options={sevOptions} series={sevSeries} type="bar" height={188} />
          </div>
        </div>
      </section>

      <section className="sec-countermeasures">
        <div className="sec-panel-head">
          <h2>Countermeasures</h2>
          <span>{cmEntries.length ? "Active families" : "Baseline playbooks"}</span>
        </div>
        <div className="sec-cm-grid">
          {tipEntries.map(([family, tips]) => (
            <article key={family} className="sec-cm-card">
              <b>{classLabel(family)}</b>
              <ul>
                {tips.slice(0, 2).map((tip) => (
                  <li key={tip}>{tip}</li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>

      <section className="sec-traffic">
        <div className="sec-traffic-toolbar">
          <div className="sec-panel-head">
            <h2>HTTP traffic</h2>
            <span>
              {visibleTraffic.length} shown · {trafficTotal} total
            </span>
          </div>
          <div className="sec-filters">
            <div className="audit-seg" role="group" aria-label="Scope">
              <button type="button" className={scope === "all" ? "active" : ""} onClick={() => setScope("all")}>
                All
              </button>
              <button type="button" className={scope === "flagged" ? "active" : ""} onClick={() => setScope("flagged")}>
                Flagged
              </button>
            </div>
            <select
              className="sec-select"
              aria-label="Classification"
              value={classFilter}
              onChange={(e) => setClassFilter(e.target.value as ClassFilter)}
            >
              <option value="">Any class</option>
              <option value="clean">Clean</option>
              <option value="sqli">SQLi</option>
              <option value="xss">XSS</option>
              <option value="csrf">CSRF</option>
              <option value="auth_anomaly">Auth anomaly</option>
            </select>
            <select
              className="sec-select"
              aria-label="Severity"
              value={sevFilter}
              onChange={(e) => setSevFilter(e.target.value as SevFilter)}
            >
              <option value="">Any severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <input
              type="search"
              className="sec-search"
              placeholder="Filter path…"
              value={pathQuery}
              onChange={(e) => setPathQuery(e.target.value)}
              aria-label="Filter path"
            />
          </div>
        </div>

        {!visibleTraffic.length ? (
          <p className="sec-empty">No requests match the current filters.</p>
        ) : (
          <div className="table-wrap sec-table-wrap">
            <table className="audit-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Request</th>
                  <th>Code</th>
                  <th>ms</th>
                  <th>Class</th>
                  <th>Severity</th>
                  <th>IP</th>
                </tr>
              </thead>
              <tbody>
                {visibleTraffic.map((row) => (
                  <tr key={row.id} className={row.classification !== "clean" ? "sec-row-flag" : undefined}>
                    <td>
                      <span className="audit-time">
                        <b>{formatTime(row.created_at)}</b>
                      </span>
                    </td>
                    <td>
                      <span className="audit-person">
                        <b className="audit-mono">
                          {row.method} {row.path}
                        </b>
                        <small>{row.signals?.[0] || "—"}</small>
                      </span>
                    </td>
                    <td>
                      <span className={`audit-status status-${statusTone(row.status_code)}`}>{row.status_code}</span>
                    </td>
                    <td>
                      <span className="audit-mono">{row.duration_ms}</span>
                    </td>
                    <td>
                      <span className={`sec-class sec-class-${row.classification}`}>{classLabel(row.classification)}</span>
                    </td>
                    <td>
                      <span className={`audit-sev sev-${row.severity}`}>{row.severity.toUpperCase()}</span>
                    </td>
                    <td>
                      <b className="audit-mono">{row.ip_address || "—"}</b>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}

function classSeriesSum(data: Overview | null) {
  const c = data?.totals_15m.by_classification || {};
  return (c.clean || 0) + (c.sqli || 0) + (c.xss || 0) + (c.csrf || 0) + (c.auth_anomaly || 0);
}
