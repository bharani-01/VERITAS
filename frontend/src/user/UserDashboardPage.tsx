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
const PROJECT_LINE_COLORS = ["#2563eb", "#0d9488", "#ea580c", "#7c3aed", "#db2777", "#0891b2", "#ca8a04", "#334155"];

/** User home — workspace summary + scan comparison graphs. */
export function UserDashboardPage() {
  const { user } = useOutletContext<ShellContext>();
  const [data, setData] = useState<WorkspaceDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<"all" | string>("all");
  /** When All: hovered project id. When project-scoped: hovered severity key. */
  const [hoverFocus, setHoverFocus] = useState<string | null>(null);

  useEffect(() => {
    api<WorkspaceDashboard>("/workspace/dashboard")
      .then(setData)
      .catch((err: Error) => setError(err.message));
  }, []);

  useEffect(() => {
    setHoverFocus(null);
  }, [scope]);

  const charts = data?.charts;
  const allRuns = charts?.runs || [];

  const projectOptions = useMemo(() => {
    const fromProjects = (data?.projects || []).map((p) => ({ id: p.id, name: p.name }));
    const seen = new Set(fromProjects.map((p) => p.id));
    for (const run of allRuns) {
      if (run.project_id && !seen.has(run.project_id)) {
        seen.add(run.project_id);
        fromProjects.push({ id: run.project_id, name: run.project_name || "Project" });
      }
    }
    return fromProjects;
  }, [data?.projects, allRuns]);

  useEffect(() => {
    if (scope === "all") return;
    if (!projectOptions.some((p) => p.id === scope)) {
      setScope("all");
    }
  }, [scope, projectOptions]);

  const runs = useMemo(() => {
    if (scope === "all") return allRuns;
    const filtered = allRuns.filter((r) => r.project_id === scope);
    return filtered.length > 16 ? filtered.slice(-16) : filtered;
  }, [allRuns, scope]);

  const projectSeriesMeta = useMemo(() => {
    if (scope !== "all") return [] as { id: string; name: string }[];
    const order: { id: string; name: string }[] = [];
    const seen = new Set<string>();
    for (const run of allRuns) {
      if (!run.project_id || seen.has(run.project_id)) continue;
      seen.add(run.project_id);
      order.push({
        id: run.project_id,
        name: run.project_name || projectOptions.find((p) => p.id === run.project_id)?.name || "Project",
      });
    }
    return order;
  }, [allRuns, scope, projectOptions]);

  /** Per-project chronological runs (All mode) — aligned by run index, not interleaved timeline. */
  const runsByProject = useMemo(() => {
    const map = new Map<string, typeof allRuns>();
    if (scope !== "all") return map;
    for (const meta of projectSeriesMeta) {
      const list = allRuns.filter((r) => r.project_id === meta.id);
      map.set(meta.id, list.length > 16 ? list.slice(-16) : list);
    }
    return map;
  }, [allRuns, scope, projectSeriesMeta]);

  const allModeLen = useMemo(() => {
    if (scope !== "all") return 0;
    let max = 0;
    for (const list of runsByProject.values()) max = Math.max(max, list.length);
    return max;
  }, [scope, runsByProject]);

  const runCategories = useMemo(() => {
    if (scope === "all") {
      return Array.from({ length: allModeLen }, (_, i) => `Run ${i + 1}`);
    }
    return runs.map((r) => {
      const when = r.created_at ? formatLocalDateTime(r.created_at).split(",")[0] : "";
      return r.label || when || "run";
    });
  }, [scope, allModeLen, runs]);

  const runSeries = useMemo(() => {
    if (scope === "all") {
      return projectSeriesMeta.map((p) => {
        const list = runsByProject.get(p.id) || [];
        return {
          name: p.name,
          data: Array.from({ length: allModeLen }, (_, i) =>
            i < list.length ? Number(list[i].findings_count || 0) : null
          ),
        };
      });
    }
    return SEV_ORDER.map((sev, i) => ({
      name: SEV_LABELS[i],
      data: runs.map((r) => Number(r.by_severity?.[sev] || 0)),
    }));
  }, [scope, projectSeriesMeta, runsByProject, allModeLen, runs]);

  const runColors = useMemo(() => {
    if (scope === "all") {
      return projectSeriesMeta.map((p, i) => {
        const base = PROJECT_LINE_COLORS[i % PROJECT_LINE_COLORS.length];
        if (!hoverFocus || hoverFocus === p.id) return base;
        return `${base}55`;
      });
    }
    return SEV_ORDER.map((sev, i) => {
      const base = SEV_COLORS[i];
      if (!hoverFocus || hoverFocus === sev) return base;
      return `${base}55`;
    });
  }, [scope, projectSeriesMeta, hoverFocus]);

  const runStrokeWidths = useMemo(() => {
    const n = runSeries.length;
    if (!hoverFocus) return Array(n).fill(2.5) as number[];
    return runSeries.map((_, i) => {
      const key = scope === "all" ? projectSeriesMeta[i]?.id : SEV_ORDER[i];
      return key === hoverFocus ? 3.5 : 1.15;
    });
  }, [hoverFocus, runSeries, scope, projectSeriesMeta]);

  const pointCount = scope === "all" ? allModeLen : runs.length;

  const runOptions: ApexOptions = useMemo(
    () => ({
      chart: {
        type: "line",
        toolbar: { show: false },
        fontFamily: "inherit",
        animations: { enabled: true },
        background: "transparent",
        zoom: { enabled: false },
        events: {
          dataPointMouseEnter: (_e, _ctx, config) => {
            const idx = config?.seriesIndex;
            if (typeof idx !== "number" || idx < 0) return;
            if (scope === "all") {
              const id = projectSeriesMeta[idx]?.id;
              if (id) setHoverFocus(id);
            } else {
              setHoverFocus(SEV_ORDER[idx] || null);
            }
          },
          dataPointMouseLeave: () => setHoverFocus(null),
          legendClick: (_chart, seriesIndex) => {
            if (typeof seriesIndex !== "number" || seriesIndex < 0) return;
            if (scope === "all") {
              const id = projectSeriesMeta[seriesIndex]?.id;
              if (id) setHoverFocus((prev) => (prev === id ? null : id));
            } else {
              const key = SEV_ORDER[seriesIndex];
              if (key) setHoverFocus((prev) => (prev === key ? null : key));
            }
          },
        },
      },
      colors: runColors,
      stroke: {
        curve: "smooth",
        width: runStrokeWidths,
        connectNulls: false,
      },
      markers: {
        size: pointCount <= 8 ? 4 : 3,
        strokeWidth: 0,
        hover: { size: 6 },
      },
      dataLabels: { enabled: false },
      legend: {
        position: "top",
        horizontalAlign: "left",
        fontSize: "11px",
        markers: { size: 5 },
        itemMargin: { horizontal: 8 },
        onItemClick: { toggleDataSeries: false },
        onItemHover: { highlightDataSeries: true },
      },
      grid: {
        borderColor: "#e8edf2",
        strokeDashArray: 3,
        padding: { left: 4, right: 8, top: 0, bottom: 0 },
      },
      xaxis: {
        categories: runCategories,
        labels: {
          rotate: pointCount > 8 ? -20 : 0,
          style: { colors: "#94a3b8", fontSize: "10px" },
          trim: true,
          hideOverlappingLabels: true,
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
        shared: false,
        intersect: true,
        custom: ({ series, seriesIndex, dataPointIndex }) => {
          const value = series?.[seriesIndex]?.[dataPointIndex];
          if (value == null || Number.isNaN(value)) return "";
          if (scope === "all") {
            const meta = projectSeriesMeta[seriesIndex];
            const run = meta ? runsByProject.get(meta.id)?.[dataPointIndex] : undefined;
            const title = meta?.name || "Project";
            const sha = run?.label || `Run ${dataPointIndex + 1}`;
            const open =
              meta && charts?.open_by_severity_by_project?.[meta.id]
                ? charts.open_by_severity_by_project[meta.id]
                : null;
            const openBits = open
              ? SEV_ORDER.map((k) => `${k}: ${open[k] || 0}`).join(" · ")
              : "";
            return `<div class="dash-chart-tip"><strong>${title}</strong><div>${sha} · ${value} finding${
              value === 1 ? "" : "s"
            }</div>${openBits ? `<div class="muted">${openBits} open</div>` : ""}</div>`;
          }
          const sev = SEV_LABELS[seriesIndex] || "Findings";
          const run = runs[dataPointIndex];
          const sha = run?.label || `Run ${dataPointIndex + 1}`;
          return `<div class="dash-chart-tip"><strong>${sev}</strong><div>${sha} · ${value}</div></div>`;
        },
      },
      states: {
        hover: { filter: { type: "none" } },
        active: { filter: { type: "none" } },
      },
    }),
    [
      runCategories,
      pointCount,
      runColors,
      runStrokeWidths,
      scope,
      projectSeriesMeta,
      runsByProject,
      runs,
      charts?.open_by_severity_by_project,
    ]
  );

  const focusProjectId = scope === "all" ? hoverFocus || "all" : scope;

  const openSev = useMemo(() => {
    if (focusProjectId === "all") return charts?.open_by_severity || {};
    return charts?.open_by_severity_by_project?.[focusProjectId] || {};
  }, [charts?.open_by_severity, charts?.open_by_severity_by_project, focusProjectId]);

  const sevDonutSeries = useMemo(
    () => SEV_ORDER.map((s) => Number(openSev[s] || 0)),
    [openSev]
  );
  const sevDonutTotal = sevDonutSeries.reduce((a, b) => a + b, 0);

  const donutFocusName =
    focusProjectId === "all"
      ? "All projects"
      : projectOptions.find((p) => p.id === focusProjectId)?.name || "Project";

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
  const scopeLabel =
    scope === "all" ? "All projects" : projectOptions.find((p) => p.id === scope)?.name || "Project";

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
        <section className="dash-charts dash-charts-pair" aria-label="Scan comparison">
          <div className="dash-chart-block">
            <div className="dash-panel-head dash-chart-toolbar">
              <div>
                <h2>Findings by run</h2>
                <span>
                  {scope === "all"
                    ? allModeLen
                      ? `${projectSeriesMeta.length} projects · up to ${allModeLen} runs each`
                      : "No finished scans"
                    : runs.length
                      ? `${runs.length} runs · ${scopeLabel}`
                      : "No finished scans"}
                </span>
              </div>
              {projectOptions.length > 0 ? (
                <div className="audit-seg dash-chart-seg" role="group" aria-label="Chart scope">
                  <button type="button" className={scope === "all" ? "active" : ""} onClick={() => setScope("all")}>
                    All
                  </button>
                  {projectOptions.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      className={scope === p.id ? "active" : ""}
                      onClick={() => setScope(p.id)}
                      title={p.name}
                    >
                      {p.name.length > 18 ? `${p.name.slice(0, 16)}…` : p.name}
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
            {(scope === "all" ? allModeLen > 0 : runs.length > 0) ? (
              <Chart options={runOptions} series={runSeries} type="line" height={280} />
            ) : (
              <p className="dash-chart-empty">
                {scope === "all"
                  ? "Finish a scan to compare projects across runs."
                  : "No finished scans with findings for this project yet."}
              </p>
            )}
          </div>
          <div className="dash-chart-block">
            <div className="dash-panel-head">
              <h2>Open by severity</h2>
              <span>
                {sevDonutTotal}
                {scope === "all" && hoverFocus ? ` · ${donutFocusName}` : ""}
              </span>
            </div>
            {sevDonutTotal ? (
              <Chart options={sevDonutOptions} series={sevDonutSeries} type="donut" height={280} />
            ) : (
              <p className="dash-chart-empty">
                {focusProjectId === "all"
                  ? "No open findings."
                  : `No open findings for ${donutFocusName}.`}
              </p>
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
