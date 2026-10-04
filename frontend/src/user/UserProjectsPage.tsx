import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import { findingsCountLabel, relativeTime, shortCommit } from "../lib/scanDisplay";
import type { Project, Scan } from "../lib/workspace";
import { ScanHistoryList } from "./ScanHistoryList";

function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="currentColor"
        d="M12 2C6.48 2 2 6.58 2 12.26c0 4.52 2.87 8.35 6.84 9.7.5.1.68-.22.68-.49v-1.7c-2.78.62-3.37-1.37-3.37-1.37-.45-1.18-1.11-1.5-1.11-1.5-.91-.64.07-.63.07-.63 1 .07 1.53 1.06 1.53 1.06.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.07 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.27 2.75 1.05A9.3 9.3 0 0 1 12 7.5c.85 0 1.71.12 2.51.34 1.91-1.32 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.8-4.57 5.06.36.32.68.94.68 1.9v2.81c0 .27.18.59.69.49A10.03 10.03 0 0 0 22 12.26C22 6.58 17.52 2 12 2z"
      />
    </svg>
  );
}

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
            <section className="projects-section">
              <div className="projects-toolbar">
                <div className="projects-toolbar-title">
                  <h2>Your projects</h2>
                  <span className="projects-count-pill">{projects.length}</span>
                </div>
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

              {!filtered.length ? (
                <div className="projects-card-empty">
                  <p>No projects match that filter.</p>
                </div>
              ) : (
                <div className="projects-table">
                  <div className="projects-grid projects-head">
                    <span className="projects-h-main">
                      Project <span className="projects-count-badge">{filtered.length}</span>
                    </span>
                    <span className="projects-h-col">Latest Commit</span>
                    <span className="projects-h-col">Scan Status</span>
                    <span className="projects-h-col">Activity</span>
                    <span className="projects-h-action">
                      <span className="sr-only">Actions</span>
                    </span>
                  </div>
                  <ul className="projects-list" role="list">
                    {filtered.map((project) => {
                      const latest = latestByProject.get(project.id);
                      const sha = latest ? shortCommit(latest.commit_short, latest.commit_sha) : null;
                      const scanning =
                        latest && (latest.status === "queued" || latest.status === "running");
                      const initial = (project.name || "P").trim().slice(0, 1).toUpperCase();
                      const findingsCount = latest?.summary?.findings_count;
                      const href = `/user/projects/${project.id}`;

                      return (
                        <li key={project.id} className="projects-row-wrap">
                          <div className="projects-grid projects-row">
                            <Link
                              className="projects-stretch"
                              to={href}
                              aria-label={`Open project ${project.name}`}
                            />

                            <div className="projects-col-main">
                              <div
                                className={`project-avatar ${scanning ? "is-scanning" : ""}`}
                                aria-hidden="true"
                              >
                                <span className="project-avatar-initial">{initial}</span>
                                {scanning ? <span className="project-avatar-scan-dot" /> : null}
                              </div>

                              <div className="project-info">
                                <div className="project-info-top">
                                  <span className="project-name">{project.name}</span>
                                  {project.auto_scan_on_push ? (
                                    <span className="project-auto-chip" title="Auto-scan on push enabled">
                                      <span className="project-auto-dot" />
                                      Auto · {project.auto_scan_branch || project.github_default_branch || "main"}
                                    </span>
                                  ) : null}
                                </div>

                                <div className="project-info-sub">
                                  {project.github_repo_full_name ? (
                                    <span className="project-repo-tag">
                                      <GitHubIcon className="project-github-icon" />
                                      <span>{project.github_repo_full_name}</span>
                                    </span>
                                  ) : (
                                    <span className="project-repo-tag muted">No repository linked</span>
                                  )}
                                </div>
                              </div>
                            </div>

                            <div className="projects-col-commit">
                              {sha ? (
                                <code className="projects-sha-badge" title="Latest commit">
                                  <svg viewBox="0 0 16 16" width="12" height="12" fill="currentColor" aria-hidden="true">
                                    <path d="M10.5 8a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0ZM8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0Zm0 1.5a6.5 6.5 0 0 1 5.92 3.826 3.998 3.998 0 0 0-4.42 2.174h-3a3.998 3.998 0 0 0-4.42-2.174A6.5 6.5 0 0 1 8 1.5Z" />
                                  </svg>
                                  <span>{sha}</span>
                                </code>
                              ) : (
                                <span className="projects-empty-cell">—</span>
                              )}
                            </div>

                            <div className="projects-col-status">
                              {latest ? (
                                <span
                                  className={`badge ${
                                    scanning
                                      ? "pending"
                                      : findingsCount === 0
                                      ? "ok"
                                      : "medium"
                                  }`}
                                >
                                  {scanning ? (
                                    <>
                                      <span className="badge-spinner" aria-hidden="true" />
                                      Scanning…
                                    </>
                                  ) : (
                                    findingsCountLabel(latest) + " findings"
                                  )}
                                </span>
                              ) : (
                                <span className="badge muted">No scans</span>
                              )}
                            </div>

                            <div className="projects-col-time">
                              {latest ? (
                                <span className="projects-time-text">
                                  {relativeTime(latest.finished_at || latest.created_at)}
                                </span>
                              ) : (
                                <span className="projects-empty-cell">—</span>
                              )}
                            </div>

                            <div className="projects-col-action" aria-hidden="true">
                              <span className="projects-chevron">
                                <svg viewBox="0 0 24 24" width="16" height="16">
                                  <path
                                    d="M9 18l6-6-6-6"
                                    fill="none"
                                    stroke="currentColor"
                                    strokeWidth="2"
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                  />
                                </svg>
                              </span>
                            </div>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}
            </section>

            {recentScans.length ? (
              <section className="np-block projects-recent">
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
