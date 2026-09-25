import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import type { ApexOptions } from "apexcharts";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { User } from "../lib/api";
import { formatStatus } from "../lib/avatars";
import { formatLocalDateTime } from "../lib/time";
import type { WorkspaceDashboard } from "../lib/workspace";

const Chart = lazy(() => import("react-apexcharts"));

type ShellContext = { user: User };

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_COLORS = ["#dc2626", "#ea580c", "#ca8a04", "#0284c7", "#94a3b8"];
const SEV_LABELS = ["Critical", "High", "Medium", "Low", "Info"];

/** User home — workspace summary + scan comparison graphs. */
export function UserDashboardPage() {
  const { user } = useOutletContext<ShellContext>();
  const [data, setData] = useState<WorkspaceDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<WorkspaceDashboard>("/workspace/dashboard")
      .then(setData)
      .catch((err: Error) => setError(err.message));
  }, []);

  const charts = data?.charts;
  const runs = charts?.runs || [];

  const runCategories = useMemo(
    () =>
      runs.map((r) => {
        const when = r.created_at ? formatLocalDateTime(r.created_at).split(",")[0] : "";
        return r.label || when || "run";
      }),
    [runs]
  );

  const runSeries = useMemo(
    () =>
      SEV_ORDER.map((sev, i) => ({
        name: SEV_LABELS[i],
        data: runs.map((r) => Number(r.by_severity?.[sev] || 0)),
      })),
    [runs]
  );

  const runTotalSeries = useMemo(
    () => [{ name: "Findings", data: runs.map((r) => Number(r.findings_count || 0)) }],
    [runs]
  );

  const runOptions: ApexOptions = useMemo(
    () => ({
      chart: {
        type: "bar",
        stacked: true,
        toolbar: { show: false },
        fontFamily: "inherit",
        animations: { enabled: true },
        background: "transparent",
      },
      colors: [...SEV_COLORS],
      plotOptions: { bar: { borderRadius: 3, columnWidth: "58%" } },
      dataLabels: { enabled: false },
      stroke: { width: 0 },
      legend: {
        position: "top",
        horizontalAlign: "left",
        fontSize: "11px",
        markers: { size: 5 },
        itemMargin: { horizontal: 8 },
      },
      grid: {
        borderColor: "#e8edf2",
        strokeDashArray: 3,
        padding: { left: 4, right: 8, top: 0, bottom: 0 },
      },
      xaxis: {
        categories: runCategories,
        labels: {
          rotate: runs.length > 6 ? -35 : 0,
          style: { colors: "#94a3b8", fontSize: "10px" },
          trim: true,
        },
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      yaxis: {
        min: 0,
        forceNiceScale: true,
        labels: {
          style: { colors: "#94a3b8", fontSize: "10px" },
          formatter: (v) => String(Math.round(v)),
        },
      },
      tooltip: {
        theme: "light",
        y: { formatter: (v) => `${v} finding${v === 1 ? "" : "s"}` },
      },
    }),
    [runCategories, runs.length]
  );

  const trendOptions: ApexOptions = useMemo(
    () => ({
      chart: {
        type: "area",
        toolbar: { show: false },
        fontFamily: "inherit",
        animations: { enabled: true },
        background: "transparent",
        sparkline: { enabled: false },
      },
      colors: ["#2563eb"],
      stroke: { curve: "smooth", width: 2 },
      fill: {
        type: "gradient",
        gradient: { shadeIntensity: 1, opacityFrom: 0.35, opacityTo: 0.04, stops: [0, 90, 100] },
      },
      dataLabels: { enabled: false },
      legend: { show: false },
      grid: {
        borderColor: "#e8edf2",
        strokeDashArray: 3,
        padding: { left: 4, right: 8, top: 8, bottom: 0 },
      },
      xaxis: {
        categories: runCategories,
        labels: {
          rotate: runs.length > 6 ? -35 : 0,
          style: { colors: "#94a3b8", fontSize: "10px" },
          trim: true,
        },
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      yaxis: {
        min: 0,
        forceNiceScale: true,
        labels: {
          style: { colors: "#94a3b8", fontSize: "10px" },
          formatter: (v) => String(Math.round(v)),
        },
      },
      tooltip: { theme: "light", y: { formatter: (v) => `${v} total` } },
    }),
    [runCategories, runs.length]
  );

  const openSev = charts?.open_by_severity || {};
  const sevDonutSeries = useMemo(
    () => SEV_ORDER.map((s) => Number(openSev[s] || 0)),
    [openSev]
  );
  const sevDonutTotal = sevDonutSeries.reduce((a, b) => a + b, 0);

  const sevDonutOptions: ApexOptions = useMemo(
    () => ({
      chart: { type: "donut", fontFamily: "inherit", animations: { enabled: true }, background: "transparent" },
      labels: [...SEV_LABELS],
      colors: [...SEV_COLORS],
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
                label: "open",
                fontSize: "11px",
                fontWeight: 600,
                color: "#64748b",
                formatter: () => String(sevDonutTotal),
              },
            },
          },
        },
      },
      stroke: { width: 2, colors: ["#fff"] },
      tooltip: { y: { formatter: (v) => `${v}` } },
    }),
    [sevDonutTotal]
  );

  const familyEntries = useMemo(() => {
    const raw = charts?.open_by_family || {};
    return Object.entries(raw).sort((a, b) => b[1] - a[1]);
  }, [charts?.open_by_family]);

  const familyOptions: ApexOptions = useMemo(
    () => ({
      chart: { type: "bar", toolbar: { show: false }, fontFamily: "inherit", background: "transparent" },
      plotOptions: { bar: { horizontal: true, borderRadius: 3, barHeight: "62%", distributed: true } },
      colors: ["#2563eb", "#0d9488", "#7c3aed", "#ea580c", "#0284c7", "#ca8a04", "#64748b", "#db2777"],
      dataLabels: { enabled: false },
      legend: { show: false },
      grid: { borderColor: "#e8edf2", strokeDashArray: 3, xaxis: { lines: { show: true } }, yaxis: { lines: { show: false } } },
      xaxis: {
        categories: familyEntries.map(([k]) => k),
        labels: { style: { colors: "#94a3b8", fontSize: "10px" } },
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      yaxis: { labels: { style: { colors: "#64748b", fontSize: "11px" } } },
      tooltip: { theme: "light" },
    }),
    [familyEntries]
  );

  const familySeries = useMemo(
    () => [{ name: "Open", data: familyEntries.map(([, v]) => v) }],
    [familyEntries]
  );

  const engineEntries = useMemo(() => {
    const raw = charts?.open_by_engine || {};
    return Object.entries(raw).sort((a, b) => b[1] - a[1]);
  }, [charts?.open_by_engine]);

  const engineOptions: ApexOptions = useMemo(
    () => ({
      chart: { type: "bar", toolbar: { show: false }, fontFamily: "inherit", background: "transparent" },
      plotOptions: { bar: { borderRadius: 3, columnWidth: "48%", distributed: true } },
      colors: ["#0f172a", "#2563eb", "#0d9488", "#ea580c", "#7c3aed"],
      dataLabels: { enabled: false },
      legend: { show: false },
      grid: { borderColor: "#e8edf2", strokeDashArray: 3 },
      xaxis: {
        categories: engineEntries.map(([k]) => k),
        labels: { style: { colors: "#94a3b8", fontSize: "10px" } },
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      yaxis: {
        min: 0,
        forceNiceScale: true,
        labels: { style: { colors: "#94a3b8", fontSize: "10px" }, formatter: (v) => String(Math.round(v)) },
      },
      tooltip: { theme: "light" },
    }),
    [engineEntries]
  );

  const engineSeries = useMemo(
    () => [{ name: "Open", data: engineEntries.map(([, v]) => v) }],
    [engineEntries]
  );

  const outcomes = charts?.scan_outcomes || {};
  const outcomeKeys = useMemo(() => {
    const preferred = ["completed", "failed", "cancelled", "running", "queued"];
    const keys = preferred.filter((k) => (outcomes[k] || 0) > 0);
    for (const k of Object.keys(outcomes)) {
      if (!keys.includes(k) && (outcomes[k] || 0) > 0) keys.push(k);
    }
    return keys.length ? keys : preferred.slice(0, 3);
  }, [outcomes]);

  const outcomeOptions: ApexOptions = useMemo(
    () => ({
      chart: { type: "donut", fontFamily: "inherit", background: "transparent" },
      labels: outcomeKeys.map((k) => formatStatus(k)),
      colors: ["#059669", "#dc2626", "#64748b", "#2563eb", "#ca8a04"],
      legend: { position: "bottom", fontSize: "11px", markers: { size: 5 } },
      dataLabels: { enabled: false },
      plotOptions: {
        pie: {
          donut: {
            size: "70%",
            labels: {
              show: true,
              name: { show: false },
              value: { show: false },
              total: {
                show: true,
                showAlways: true,
                label: "scans",
                fontSize: "11px",
                fontWeight: 600,
                color: "#64748b",
                formatter: () => String(outcomeKeys.reduce((a, k) => a + (outcomes[k] || 0), 0)),
              },
            },
          },
        },
      },
      stroke: { width: 2, colors: ["#fff"] },
    }),
    [outcomeKeys, outcomes]
  );

  const outcomeSeries = useMemo(
    () => outcomeKeys.map((k) => Number(outcomes[k] || 0)),
    [outcomeKeys, outcomes]
  );

  if (error) {
    return (
      <main className="admin-main">
        <div className="notice error" role="alert">
          {error}
        </div>
      </main>
    );
  }

  if (!data) {
    return (
      <main className="admin-main">
        <LoadingMark label="Loading workspace…" />
      </main>
    );
  }

  const openFindings = data.totals.open_findings ?? 0;
  const needsGithub = data.github.configured && !data.github.connected;
  const needsProject = data.totals.projects === 0;
  const showSetup = needsGithub || needsProject;
  const recentScans = data.recent_scans.slice(0, 12);
  const projects = data.projects.slice(0, 6);

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Workspace</div>
          <h1>Welcome, {user.display_name.split(" ")[0]}</h1>
          <p>Projects, recent scans, open findings, and your GitHub connection.</p>
        </div>
        <div className="profile-actions">
          <Link className="btn" to="/user/projects/new">
            New project
          </Link>
          {needsGithub ? (
            <Link className="btn secondary" to="/user/projects/new">
              Connect GitHub
            </Link>
          ) : (
            <Link className="btn secondary" to="/user/scans">
              View scans
            </Link>
          )}
        </div>
      </header>

      <section className="dash-metrics" aria-label="Workspace summary">
        <div className="dash-metric">
          <span>Projects</span>
          <strong>{data.totals.projects}</strong>
        </div>
        <div className="dash-metric">
          <span>Scans this week</span>
          <strong>{data.totals.scans_this_week}</strong>
        </div>
        <div className={`dash-metric ${openFindings > 0 ? "emphasis" : ""}`}>
          <span>Open findings</span>
          <strong>{openFindings}</strong>
        </div>
        <div className="dash-metric">
          <span>GitHub</span>
          <strong className="metric-text">
            {data.github.connected
              ? `@${data.github.github_login}`
              : data.github.configured
                ? "Not connected"
                : "Not configured"}
          </strong>
        </div>
      </section>

      {showSetup ? (
        <section className="dash-setup" aria-label="Get started">
          {needsGithub ? (
            <div className="dash-setup-item">
              <div>
                <strong>Connect GitHub</strong>
                <p>Import a repository you own to create your first project.</p>
              </div>
              <Link className="btn secondary" to="/user/projects/new">
                Connect
              </Link>
            </div>
          ) : null}
          {needsProject ? (
            <div className="dash-setup-item">
              <div>
                <strong>Create a project</strong>
                <p>Link a repo, pick a branch, and run secrets, SCA, and SAST scans.</p>
              </div>
              <Link className="btn" to="/user/projects/new">
                New project
              </Link>
            </div>
          ) : null}
        </section>
      ) : null}

      <Suspense fallback={<LoadingMark label="Loading charts…" />}>
        <section className="dash-charts" aria-label="Scan comparison">
          <div className="dash-chart-block dash-chart-wide">
            <div className="dash-panel-head">
              <h2>Findings by run</h2>
              <span>{runs.length ? `${runs.length} recent` : "No finished scans"}</span>
            </div>
            {runs.length ? (
              <Chart options={runOptions} series={runSeries} type="bar" height={260} />
            ) : (
              <p className="dash-chart-empty">Finish a scan to compare severity across runs.</p>
            )}
          </div>
          <div className="dash-chart-side">
            <div className="dash-chart-block">
              <div className="dash-panel-head">
                <h2>Open by severity</h2>
                <span>{sevDonutTotal}</span>
              </div>
              {sevDonutTotal ? (
                <Chart options={sevDonutOptions} series={sevDonutSeries} type="donut" height={210} />
              ) : (
                <p className="dash-chart-empty">No open findings.</p>
              )}
            </div>
            <div className="dash-chart-block">
              <div className="dash-panel-head">
                <h2>Scan outcomes</h2>
                <span>All time</span>
              </div>
              {outcomeSeries.some((n) => n > 0) ? (
                <Chart options={outcomeOptions} series={outcomeSeries} type="donut" height={210} />
              ) : (
                <p className="dash-chart-empty">No scans yet.</p>
              )}
            </div>
          </div>
        </section>

        <section className="dash-charts dash-charts-secondary" aria-label="Finding breakdown">
          <div className="dash-chart-block">
            <div className="dash-panel-head">
              <h2>Finding trend</h2>
              <span>Total per run</span>
            </div>
            {runs.length ? (
              <Chart options={trendOptions} series={runTotalSeries} type="area" height={220} />
            ) : (
              <p className="dash-chart-empty">Trend appears after your first finished scan.</p>
            )}
          </div>
          <div className="dash-chart-block">
            <div className="dash-panel-head">
              <h2>Open by family</h2>
              <span>Top families</span>
            </div>
            {familyEntries.length ? (
              <Chart options={familyOptions} series={familySeries} type="bar" height={220} />
            ) : (
              <p className="dash-chart-empty">No open findings by family.</p>
            )}
          </div>
          <div className="dash-chart-block">
            <div className="dash-panel-head">
              <h2>Open by engine</h2>
              <span>Secrets · SCA · SAST</span>
            </div>
            {engineEntries.length ? (
              <Chart options={engineOptions} series={engineSeries} type="bar" height={220} />
            ) : (
              <p className="dash-chart-empty">No open findings by engine.</p>
            )}
          </div>
        </section>
      </Suspense>
      <section className="dash-panels">
        <div className="dash-panel">
          <div className="dash-panel-head">
            <h2>Recent scans</h2>
            <Link to="/user/scans">View all</Link>
          </div>
          <div className="dash-panel-body">
            {!recentScans.length ? (
              <div className="empty-state compact">
                <strong>No scans yet</strong>
                Open a project and start a scan — history will show up here.
                <div className="empty-actions">
                  <Link className="btn secondary" to={needsProject ? "/user/projects/new" : "/user/projects"}>
                    {needsProject ? "Create a project" : "Go to projects"}
                  </Link>
                </div>
              </div>
            ) : (
              <ul className="dash-list">
                {recentScans.map((scan) => {
                  const findings = scan.summary?.findings_count;
                  return (
                    <li key={scan.id}>
                      <div className="dash-list-main">
                        <div className="dash-list-top">
                          <b>
                            <Link to={`/user/projects/${scan.project_id}/scans/${scan.id}`}>{scan.target}</Link>
                          </b>
                          <span className={`badge ${scan.status}`}>{formatStatus(scan.status)}</span>
                        </div>
                        <small>
                          <Link to={`/user/projects/${scan.project_id}`}>{scan.project_name || "Project"}</Link>
                          {" · "}
                          {formatLocalDateTime(scan.created_at)}
                          {typeof findings === "number" ? ` · ${findings} finding${findings === 1 ? "" : "s"}` : ""}
                        </small>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>

        <div className="dash-panel">
          <div className="dash-panel-head">
            <h2>Projects</h2>
            <Link to="/user/projects">View all</Link>
          </div>
          <div className="dash-panel-body">
            {!projects.length ? (
              <div className="empty-state compact">
                <strong>No projects yet</strong>
                Import a GitHub repo to start scanning.
                <div className="empty-actions">
                  <Link className="btn" to="/user/projects/new">
                    New project
                  </Link>
                </div>
              </div>
            ) : (
              <ul className="dash-list">
                {projects.map((project) => (
                  <li key={project.id}>
                    <div className="dash-list-main">
                      <div className="dash-list-top">
                        <b>
                          <Link to={`/user/projects/${project.id}`}>{project.name}</Link>
                        </b>
                        <Link className="dash-list-action" to={`/user/projects/${project.id}`}>
                          Open
                        </Link>
                      </div>
                      <small>
                        {project.github_repo_full_name || "No repo linked"}
                        {project.auto_scan_on_push ? " · Auto-scan on" : ""}
                      </small>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>
    </main>
  );
}
