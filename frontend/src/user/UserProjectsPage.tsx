import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import {
  findingsCountLabel,
  formatScanDuration,
  relativeTime,
  shortCommit,
} from "../lib/scanDisplay";
import type { Project, Scan } from "../lib/workspace";
import { ScanHistoryList } from "./ScanHistoryList";

function SearchIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <path d="m20 20-3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
    </svg>
  );
}

/** Flat Render-style projects index — same language as New project. */
export function UserProjectsPage() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    const [proj, scans] = await Promise.all([
      api<{ items: Project[] }>("/workspace/projects"),
      api<{ items: Scan[] }>("/workspace/scans?limit=40"),
    ]);
    setProjects(proj.items);
    setRecentScans(scans.items);
  }

  useEffect(() => {
    load()
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const active = recentScans.some((s) => s.status === "queued" || s.status === "running");
    if (!active) return;
    const id = window.setInterval(() => {
      load().catch(() => undefined);
    }, 4000);
    return () => window.clearInterval(id);
  }, [recentScans]);

  const latestByProject = useMemo(() => {
    const map = new Map<string, Scan>();
    for (const scan of recentScans) {
      if (!map.has(scan.project_id)) map.set(scan.project_id, scan);
    }
    return map;
  }, [recentScans]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return projects;
    return projects.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.github_repo_full_name || "").toLowerCase().includes(q) ||
        (p.description || "").toLowerCase().includes(q),
    );
  }, [projects, query]);

  return (
    <main className="admin-main projects-page">
      <div className="projects-wrap">
        <header className="new-project-header projects-header">
          <div className="projects-header-row">
            <div>
              <nav className="new-project-crumb" aria-label="Breadcrumb">
                <span>Workspace</span>
                <span aria-hidden="true">/</span>
                <span>Projects</span>
              </nav>
              <h1>Projects</h1>
              <p>Link a GitHub repo, run scans, and track findings as commits land.</p>
            </div>
            <Link className="btn" to="/user/projects/new">
              New project
            </Link>
          </div>
        </header>

        {error ? (
          <div className="notice error" role="alert">
            {error}
          </div>
        ) : null}

        {loading ? (
          <LoadingMark label="Loading projects…" />
        ) : !projects.length ? (
          <section className="np-block projects-empty">
            <h2 className="np-label">Get started</h2>
            <p className="np-empty">
              No projects yet. Connect GitHub and create one from a repository you own.
            </p>
            <Link className="btn" to="/user/projects/new">
              New project
            </Link>
          </section>
        ) : (
          <>
            <div className="projects-filter-bar">
              <div className="projects-search-wrap">
                <SearchIcon className="projects-search-icon" />
                <input
                  className="projects-search-input"
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search projects or repositories…"
                  autoComplete="off"
                  aria-label="Filter projects"
                />
                {query ? (
                  <button
                    type="button"
                    className="projects-search-clear"
                    onClick={() => setQuery("")}
                    aria-label="Clear search"
                  >
                    ×
                  </button>
                ) : null}
              </div>
            </div>

            <section className="scan-hist projects-hist" aria-label="Your projects">
              <div className="scan-hist-grid scan-hist-head">
                <span className="scan-hist-h-main">
                  Your projects
                  <span className="scan-hist-count">{filtered.length}</span>
                </span>
                <span className="scan-hist-h-col">Trigger</span>
                <span className="scan-hist-h-col">Findings</span>
                <span className="scan-hist-h-col">Duration</span>
                <span className="scan-hist-h-action">
                  <span className="sr-only">Actions</span>
                </span>
              </div>
              {!filtered.length ? (
                <div className="empty-state scan-hist-empty">
                  <strong>No projects found</strong>
                  {query ? `No projects match "${query}".` : "No projects yet."}
                </div>
              ) : (
                <ul className="scan-hist-list">
                  {filtered.map((project) => {
                    const latest = latestByProject.get(project.id);
                    const sha = latest ? shortCommit(latest.commit_short, latest.commit_sha) : null;
                    const scanning =
                      latest && (latest.status === "queued" || latest.status === "running");
                    const findings = latest ? findingsCountLabel(latest) : "—";
                    const duration = latest ? formatScanDuration(latest) : "—";
                    const when = latest ? relativeTime(latest.finished_at || latest.created_at) : null;
                    const href = `/user/projects/${project.id}`;

                    return (
                      <li key={project.id}>
                        <div className="scan-hist-grid scan-hist-row">
                          <Link
                            className="scan-hist-stretch"
                            to={href}
                            aria-label={`Open project: ${project.name}`}
                          />
                          <span className="scan-hist-main">
                            {scanning ? (
                              <span className="scan-hist-icon pending" aria-label="Scanning" title="Scanning">
                                <svg className="scan-hist-spinner" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                                  <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2.75" strokeOpacity="0.25" />
                                  <path d="M12 3a9 9 0 0 1 9 9" stroke="currentColor" strokeWidth="2.75" strokeLinecap="round" />
                                </svg>
                              </span>
                            ) : latest?.status === "completed" ? (
                              <span className="scan-hist-icon ok" aria-label="Completed" title="Completed">
                                <svg viewBox="0 0 24 24" aria-hidden="true">
                                  <path d="M20 6 9 17l-5-5" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                                </svg>
                              </span>
                            ) : latest?.status === "failed" ? (
                              <span className="scan-hist-icon fail" aria-label="Failed" title="Failed">
                                <svg viewBox="0 0 24 24" aria-hidden="true">
                                  <path d="M18 6 6 18M6 6l12 12" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
                                </svg>
                              </span>
                            ) : (
                              <span className="scan-hist-icon muted" aria-label="No scans" title="No scans">
                                <svg viewBox="0 0 24 24" aria-hidden="true">
                                  <path d="M8 12h8" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
                                </svg>
                              </span>
                            )}
                            <span className="scan-hist-copy">
                              <span className="scan-hist-msg">{project.name}</span>
                              <span className="scan-hist-meta">
                                {project.github_repo_full_name ? (
                                  <span className="scan-hist-project">{project.github_repo_full_name}</span>
                                ) : (
                                  <span>No repository linked</span>
                                )}
                                {sha ? (
                                  <>
                                    <span className="scan-hist-dot" aria-hidden="true">·</span>
                                    <code className="scan-hist-sha">{sha}</code>
                                  </>
                                ) : null}
                                {when ? (
                                  <>
                                    <span className="scan-hist-dot" aria-hidden="true">·</span>
                                    <span>Scanned {when}</span>
                                  </>
                                ) : null}
                              </span>
                            </span>
                          </span>

                          <span className="scan-hist-col">
                            {project.auto_scan_on_push ? (
                              <span className="project-auto-chip" title="Auto-scan on push enabled">
                                <span className="project-auto-dot" />
                                Auto · {project.auto_scan_branch || project.github_default_branch || "main"}
                              </span>
                            ) : (
                              <span>Manual</span>
                            )}
                          </span>

                          <span className="scan-hist-col scan-hist-findings">
                            {findings === "—" || findings === "…" ? (
                              findings
                            ) : (
                              <>
                                <b>{findings}</b>
                                <span className="scan-hist-findings-label"> findings</span>
                              </>
                            )}
                          </span>

                          <span className="scan-hist-col">{duration}</span>

                          <span className="scan-hist-action">
                            <button
                              type="button"
                              className="scan-hist-chevron"
                              onClick={() => navigate(href)}
                              tabIndex={-1}
                              aria-hidden="true"
                            >
                              <svg viewBox="0 0 24 24">
                                <path
                                  d="M9 6l6 6-6 6"
                                  fill="none"
                                  stroke="currentColor"
                                  strokeWidth="1.75"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                />
                              </svg>
                            </button>
                          </span>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>

            {recentScans.length ? (
              <section className="projects-recent-section">
                <ScanHistoryList
                  scans={recentScans.slice(0, 12)}
                  title="Recent scans"
                  showProjectName
                  emptyTitle="No recent scans"
                />
              </section>
            ) : null}
          </>
        )}
      </div>
    </main>
  );
}
