import { useEffect, useMemo, useState, type MouseEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import { findingsCountLabel, relativeTime, shortCommit } from "../lib/scanDisplay";
import type { Project, Scan } from "../lib/workspace";
import { ScanHistoryList } from "./ScanHistoryList";

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

  async function onDelete(id: string, e: MouseEvent) {
    e.stopPropagation();
    e.preventDefault();
    if (!confirm("Delete this project and its scans?")) return;
    try {
      await api(`/workspace/projects/${id}`, { method: "DELETE" });
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

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
            <section className="np-block">
              <h2 className="np-label">
                Your projects
                <span className="projects-count">{projects.length}</span>
              </h2>
              <input
                className="np-input"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by name or repository…"
                autoComplete="off"
                aria-label="Filter projects"
              />
              {!filtered.length ? (
                <p className="np-empty">No projects match that filter.</p>
              ) : (
                <ul className="np-repos projects-list" role="list">
                  {filtered.map((project) => {
                    const latest = latestByProject.get(project.id);
                    const sha = latest ? shortCommit(latest.commit_short, latest.commit_sha) : null;
                    const scanning =
                      latest && (latest.status === "queued" || latest.status === "running");
                    return (
                      <li key={project.id} className="project-item-row">
                        <button
                          type="button"
                          className="np-repo project-item"
                          onClick={() => navigate(`/user/projects/${project.id}`)}
                        >
                          <span className="project-item-mark" aria-hidden="true">
                            {scanning ? (
                              <span className="project-item-pulse" />
                            ) : (
                              <svg viewBox="0 0 24 24">
                                <path
                                  d="M4 7h16M4 12h10M4 17h14"
                                  fill="none"
                                  stroke="currentColor"
                                  strokeWidth="1.75"
                                  strokeLinecap="round"
                                />
                              </svg>
                            )}
                          </span>
                          <span className="np-repo-body project-item-body">
                            <span className="project-item-top">
                              <span className="np-repo-name">{project.name}</span>
                              {project.auto_scan_on_push ? (
                                <span className="project-chip">
                                  Auto · {project.auto_scan_branch || project.github_default_branch || "branch"}
                                </span>
                              ) : null}
                            </span>
                            <span className="np-repo-meta project-item-meta">
                              {project.github_repo_full_name ? (
                                <span className="project-repo">{project.github_repo_full_name}</span>
                              ) : (
                                <span>No repository linked</span>
                              )}
                              {latest ? (
                                <>
                                  <span aria-hidden="true">·</span>
                                  {sha ? <code>{sha}</code> : null}
                                  {sha ? <span aria-hidden="true">·</span> : null}
                                  <span>
                                    {findingsCountLabel(latest)} findings ·{" "}
                                    {relativeTime(latest.finished_at || latest.created_at)}
                                  </span>
                                </>
                              ) : (
                                <>
                                  <span aria-hidden="true">·</span>
                                  <span>No scans yet — open to run one</span>
                                </>
                              )}
                            </span>
                          </span>
                          <span className="project-item-open">Open</span>
                        </button>
                        <button
                          type="button"
                          className="np-text-btn project-item-delete"
                          onClick={(e) => onDelete(project.id, e)}
                        >
                          Delete
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>

            {recentScans.length ? (
              <section className="np-block projects-recent">
                <ScanHistoryList
                  scans={recentScans}
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
