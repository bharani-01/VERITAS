import { useEffect, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { User } from "../lib/api";
import { avatarUrl, formatStatus } from "../lib/avatars";
import { formatLocalDateTime } from "../lib/time";
import type { WorkspaceDashboard } from "../lib/workspace";

type ShellContext = { user: User };

/** User home — identity + Phase 2 workspace summary from live APIs. */
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

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Workspace</div>
          <h1>Welcome, {user.display_name.split(" ")[0]}</h1>
          <p>Projects, recent scans, and your GitHub connection.</p>
        </div>
        <div className="profile-actions">
          <Link className="btn" to="/user/projects/new">
            New project
          </Link>
          {!data.github.connected ? (
            <Link className="btn secondary" to="/user/projects/new">
              Connect GitHub
            </Link>
          ) : null}
        </div>
      </header>

      <section className="dash-metrics user-metrics" aria-label="Workspace summary">
        <div className="dash-metric">
          <span>Projects</span>
          <strong>{data.totals.projects}</strong>
        </div>
        <div className="dash-metric">
          <span>Scans this week</span>
          <strong>{data.totals.scans_this_week}</strong>
        </div>
        <div className="dash-metric">
          <span>GitHub</span>
          <strong className="metric-text">
            {data.github.connected ? `@${data.github.github_login}` : data.github.configured ? "Not connected" : "Not configured"}
          </strong>
        </div>
      </section>

      <section className="dash-panels">
        <div className="dash-panel">
          <div className="dash-panel-head">
            <h2>Recent scans</h2>
            <Link to="/user/projects">Projects</Link>
          </div>
          {!data.recent_scans.length ? (
            <div className="empty-state compact">
              <strong>No scans yet</strong>
              Create a project and open it to start a scan.
            </div>
          ) : (
            <ul className="dash-list activity">
              {data.recent_scans.map((scan) => (
                <li key={scan.id}>
                  <span>
                    <b>
                      <Link to={`/user/projects/${scan.project_id}/scans/${scan.id}`}>{scan.target}</Link>
                    </b>
                    <small>
                      <Link to={`/user/projects/${scan.project_id}`}>{scan.project_name || "Project"}</Link> ·{" "}
                      {formatLocalDateTime(scan.created_at)}
                    </small>
                  </span>
                  <span className={`badge ${scan.status}`}>{formatStatus(scan.status)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="dash-panel">
          <div className="dash-panel-head">
            <h2>Your identity</h2>
            <Link to="/user/profile">Manage</Link>
          </div>
          <div className="dash-identity">
            <span className="user-avatar large">
              <img className="avatar-art" src={avatarUrl(user.avatar)} alt="" width={64} height={64} />
            </span>
            <div>
              <h3>{user.display_name}</h3>
              <p>
                {user.username ? `@${user.username}` : "No username"} · {user.email}
              </p>
              <span className={`badge ${user.status}`}>{formatStatus(user.status)}</span>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
