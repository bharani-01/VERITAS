import { useEffect, useState, type MouseEvent, type KeyboardEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import { findingsCountLabel, relativeTime, shortCommit } from "../lib/scanDisplay";
import type { Project, Scan } from "../lib/workspace";
import { ProjectSwitcher } from "./ProjectSwitcher";
import { ScanHistoryList } from "./ScanHistoryList";

export function UserProjectsPage() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
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

  const latestByProject = new Map<string, Scan>();
  for (const scan of recentScans) {
    if (!latestByProject.has(scan.project_id)) latestByProject.set(scan.project_id, scan);
  }

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Workspace</div>
          <h1>Projects</h1>
          <p>Open a project to run scans — commits and findings show up below as they finish.</p>
        </div>
        <div className="project-header-actions">
          {projects.length ? (
            <ProjectSwitcher
              projects={projects}
              showAllLink={false}
              onNewProject={() => navigate("/user/projects/new")}
              compact
              menuAlign="right"
            />
          ) : null}
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
        <div className="empty-state">
          <strong>No projects yet</strong>
          Create a project from a GitHub repository you own.
          <div style={{ marginTop: "0.85rem" }}>
            <Link className="btn" to="/user/projects/new">
              New project
            </Link>
          </div>
        </div>
      ) : (
        <>
          <div className="project-list" role="list">
            {projects.map((project) => {
              const latest = latestByProject.get(project.id);
              const sha = latest ? shortCommit(latest.commit_short, latest.commit_sha) : null;
              return (
                <button
                  type="button"
                  className="project-row"
                  key={project.id}
                  role="listitem"
                  onClick={() => navigate(`/user/projects/${project.id}`)}
                >
                  <span className="project-row-main">
                    <span className="project-row-title">{project.name}</span>
                    <span className="project-row-meta">
                      {project.github_repo_full_name ? (
                        <span className="project-repo">{project.github_repo_full_name}</span>
                      ) : (
                        <span>Manual</span>
                      )}
                      {project.auto_scan_on_push ? (
                        <>
                          <span>·</span>
                          <span>
                            Auto-scan · {project.auto_scan_branch || project.github_default_branch || "branch"}
                          </span>
                        </>
                      ) : null}
                      {latest ? (
                        <>
                          <span>·</span>
                          <span className="project-latest-commit">
                            {sha ? <code>{sha}</code> : null}
                            {sha ? " · " : null}
                            {findingsCountLabel(latest)} findings
                            {" · "}
                            {relativeTime(latest.finished_at || latest.created_at)}
                          </span>
                        </>
                      ) : (
                        <>
                          <span>·</span>
                          <span>No scans yet</span>
                        </>
                      )}
                    </span>
                  </span>
                  <span className="project-row-actions">
                    <span className="project-row-cta">Open scans</span>
                    <span
                      className="project-row-delete"
                      role="button"
                      tabIndex={0}
                      onClick={(e) => onDelete(project.id, e)}
                      onKeyDown={(e: KeyboardEvent) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          onDelete(project.id, e as unknown as MouseEvent);
                        }
                      }}
                    >
                      Delete
                    </span>
                  </span>
                </button>
              );
            })}
          </div>

          {recentScans.length ? (
            <div className="projects-recent-scans">
              <ScanHistoryList
                scans={recentScans}
                title="Recent scans"
                showProjectName
                emptyTitle="No recent scans"
              />
            </div>
          ) : null}
        </>
      )}
    </main>
  );
}
