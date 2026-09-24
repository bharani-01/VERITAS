import { useEffect, useMemo, useState } from "react";
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
  modules: {
    user_system: { users: number; audit_events_15m: number };
    http_collection: { requests_15m: number; requests_60m: number };
    detection: { suspicious_15m: number };
  };
  server_time: string;
};

const POLL_MS = 4000;

const STATUS_LABEL: Record<Overview["status"], string> = {
  safe: "Safe",
  warning: "Warning",
  critical: "Critical",
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

/** Admin Security dashboard — live HTTP telemetry + ApexCharts. */
export function AdminSecurityPage() {
  useDocumentTitle("Security");
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    let timer: number | null = null;

    async function load() {
      try {
        const next = await api<Overview>("/admin/security-overview");
        if (cancelled) return;
        setData(next);
        setError(null);
      } catch (err) {
        if (cancelled) return;
        setError((err as Error).message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();
    timer = window.setInterval(() => void load(), POLL_MS);
    return () => {
      cancelled = true;
      if (timer != null) window.clearInterval(timer);
    };
  }, []);

  const volumeOptions: ApexOptions = useMemo(
    () => ({
      chart: {
        type: "area",
        toolbar: { show: false },
        animations: { enabled: true, speed: 400 },
        zoom: { enabled: false },
        fontFamily: "inherit",
      },
      dataLabels: { enabled: false },
      stroke: { curve: "smooth", width: 2 },
      fill: {
        type: "gradient",
        gradient: { shadeIntensity: 1, opacityFrom: 0.35, opacityTo: 0.05, stops: [0, 90, 100] },
      },
      colors: ["#0f766e"],
      grid: { borderColor: "#e2e8f0", strokeDashArray: 3 },
      xaxis: {
        categories: (data?.volume_60m || []).map((b) => {
          const d = parseUtc(b.t) || new Date(b.t);
          return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
        }),
        labels: { show: true, rotate: 0, hideOverlappingLabels: true, style: { colors: "#64748b", fontSize: "10px" } },
        axisBorder: { show: false },
        axisTicks: { show: false },
        tickAmount: 6,
      },
      yaxis: {
        min: 0,
        forceNiceScale: true,
        labels: { style: { colors: "#64748b", fontSize: "11px" } },
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
      chart: { type: "donut", fontFamily: "inherit", animations: { enabled: true } },
      labels: ["Clean", "SQLi", "XSS", "CSRF", "Auth anomaly"],
      colors: ["#94a3b8", "#dc2626", "#ea580c", "#ca8a04", "#0369a1"],
      legend: { position: "bottom", fontSize: "12px" },
      dataLabels: { enabled: false },
      plotOptions: { pie: { donut: { size: "68%" } } },
      stroke: { width: 0 },
      tooltip: { y: { formatter: (v) => `${v}` } },
    }),
    []
  );

  const classSeries = useMemo(() => {
    const c = data?.totals_15m.by_classification || {};
    return [c.clean || 0, c.sqli || 0, c.xss || 0, c.csrf || 0, c.auth_anomaly || 0];
  }, [data?.totals_15m.by_classification]);

  const sevOptions: ApexOptions = useMemo(
    () => ({
      chart: { type: "bar", toolbar: { show: false }, fontFamily: "inherit", animations: { enabled: true } },
      plotOptions: { bar: { borderRadius: 4, columnWidth: "55%", distributed: true } },
      colors: ["#94a3b8", "#0369a1", "#ca8a04", "#ea580c", "#dc2626"],
      dataLabels: { enabled: false },
      legend: { show: false },
      grid: { borderColor: "#e2e8f0", strokeDashArray: 3 },
      xaxis: {
        categories: ["Info", "Low", "Medium", "High", "Critical"],
        labels: { style: { colors: "#64748b", fontSize: "11px" } },
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      yaxis: {
        min: 0,
        forceNiceScale: true,
        labels: { style: { colors: "#64748b", fontSize: "11px" } },
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

  return (
    <main className="admin-main sec-dash">
      <header className="sec-dash-head">
        <div>
          <div className="eyebrow">Monitoring</div>
          <h1>Security</h1>
          <p className="sec-dash-lede">
            Live HTTP collection, classification, and risk for VERITAS API traffic. Polls every {POLL_MS / 1000}s.
          </p>
        </div>
        <div className="sec-dash-actions">
          <Link className="btn ghost" to="/admin/audit">
            Audit log
          </Link>
          <Link className="btn ghost" to="/admin/directory">
            Users
          </Link>
        </div>
      </header>

      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}

      <section className={`sec-status sec-status-${status}`} aria-live="polite">
        <div className="sec-status-badge">{STATUS_LABEL[status]}</div>
        <div className="sec-status-body">
          <strong>Live status</strong>
          <p>{data?.reason || "Collecting telemetry…"}</p>
        </div>
        <div className="sec-status-meta">
          <span>{data?.totals_15m.requests ?? 0} requests · 15m</span>
          <span>{data?.totals_15m.suspicious ?? 0} suspicious</span>
        </div>
      </section>

      <section className="sec-modules" aria-label="Security modules">
        <article>
          <small>1. User &amp; system</small>
          <b>{data?.modules.user_system.users ?? 0} users</b>
          <span>{data?.modules.user_system.audit_events_15m ?? 0} audit events · 15m</span>
          <Link to="/admin/directory">Directory →</Link>
        </article>
        <article>
          <small>2. HTTP collection</small>
          <b>{data?.modules.http_collection.requests_15m ?? 0} req · 15m</b>
          <span>{data?.modules.http_collection.requests_60m ?? 0} in last hour</span>
        </article>
        <article>
          <small>3–4. Detection / SQLi·XSS·CSRF</small>
          <b>{data?.modules.detection.suspicious_15m ?? 0} flagged</b>
          <span>
            SQLi {data?.totals_15m.by_classification.sqli ?? 0} · XSS {data?.totals_15m.by_classification.xss ?? 0} · CSRF{" "}
            {data?.totals_15m.by_classification.csrf ?? 0}
          </span>
        </article>
        <article>
          <small>5–6. Risk &amp; classification</small>
          <b className={`sec-inline-status sec-inline-${status}`}>{STATUS_LABEL[status]}</b>
          <span>
            Crit {data?.totals_15m.by_severity.critical ?? 0} · High {data?.totals_15m.by_severity.high ?? 0} · Med{" "}
            {data?.totals_15m.by_severity.medium ?? 0}
          </span>
        </article>
      </section>

      <section className="sec-charts">
        <div className="sec-chart-card">
          <h2>Request volume · 60m</h2>
          <Chart options={volumeOptions} series={volumeSeries} type="area" height={240} />
        </div>
        <div className="sec-chart-card">
          <h2>Classification · 15m</h2>
          <Chart options={classOptions} series={classSeries} type="donut" height={240} />
        </div>
        <div className="sec-chart-card">
          <h2>Severity · 15m</h2>
          <Chart options={sevOptions} series={sevSeries} type="bar" height={240} />
        </div>
      </section>

      {cmEntries.length ? (
        <section className="sec-countermeasures">
          <h2>7. Countermeasure recommendations</h2>
          <div className="sec-cm-grid">
            {cmEntries.map(([family, tips]) => (
              <article key={family}>
                <b>{classLabel(family)}</b>
                <ul>
                  {tips.map((tip) => (
                    <li key={tip}>{tip}</li>
                  ))}
                </ul>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <section className="sec-countermeasures is-quiet">
          <h2>7. Countermeasure recommendations</h2>
          <p>No active threat families — playbooks appear when SQLi, XSS, CSRF, or auth anomalies are detected.</p>
        </section>
      )}

      <section className="sec-traffic">
        <div className="sec-traffic-head">
          <h2>Recent suspicious traffic</h2>
          <span className="sec-live-dot" aria-hidden="true" />
          <span>Live</span>
        </div>
        {!data?.recent_suspicious.length ? (
          <div className="empty-state">
            <strong>All clear</strong>
            No elevated HTTP signals in the last 15 minutes.
          </div>
        ) : (
          <div className="table-wrap">
            <table className="audit-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Request</th>
                  <th>Code</th>
                  <th>Class</th>
                  <th>Severity</th>
                  <th>IP</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_suspicious.map((row) => (
                  <tr key={row.id}>
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
                      <span className="audit-status">{row.status_code}</span>
                    </td>
                    <td>{classLabel(row.classification)}</td>
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
