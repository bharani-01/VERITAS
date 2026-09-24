import { useEffect, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { User } from "../lib/api";
import { formatStatus } from "../lib/avatars";
import { formatLocalDateTime } from "../lib/time";
import type { WorkspaceDashboard } from "../lib/workspace";

type ShellContext = { user: User };

/** User home — workspace summary from live APIs. */
export function UserDashboardPage() {
  const { user } = useOutletContext<ShellContext>();
  const [data, setData] = useState<WorkspaceDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<WorkspaceDashboard>("/workspace/dashboard")
      .then(setData)
      .catch((err: Error) => setError(err.message));
  }, []);

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
  const recentScans = data.recent_scans.slice(0, 6);
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
              <>
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
                <div className="dash-side-meta">
                  <p>
                    {data.github.connected
                      ? `GitHub connected as @${data.github.github_login}`
                      : data.github.configured
                        ? "GitHub is not connected yet"
                        : "GitHub OAuth is not configured"}
                  </p>
                  <div className="dash-side-links">
                    <Link to="/user/projects/new">New project</Link>
                    <Link to="/user/scans">All scans</Link>
                    {needsGithub ? <Link to="/user/projects/new">Connect GitHub</Link> : null}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </section>

      <section className="dash-footnote">
        <span>
          Signed in as {user.display_name}
          {user.username ? ` · @${user.username}` : ""} · {user.email} ·{" "}
          <Link to="/user/profile">Profile</Link>
          {" · "}
          <Link to="/user/settings">Settings</Link>
        </span>
      </section>
    </main>
  );
}
