import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { User } from "../lib/api";
import { avatarUrl, formatStatus } from "../lib/avatars";

type DashboardData = {
  totals: {
    users: number;
    active: number;
    pending_approval: number;
    pending_verification: number;
    deactivated: number;
    rejected: number;
    admins: number;
    projects?: number;
    scans?: number;
    github_connections?: number;
  };
  pending_approval: User[];
  recent_events: {
    id: string;
    action: string;
    actor_user_id: string | null;
    target_user_id: string | null;
    created_at: string;
  }[];
};

function formatAction(action: string) {
  return action.replace(/_/g, " ");
}

/** Admin identity dashboard — Phase 1 scope only. */
export function AdminDashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<DashboardData>("/admin/dashboard")
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
        <LoadingMark label="Loading overview…" />
      </main>
    );
  }

  const metrics = [
    { label: "Total accounts", value: data.totals.users },
    { label: "Active", value: data.totals.active },
    { label: "Awaiting approval", value: data.totals.pending_approval, emphasis: true },
    { label: "Pending verification", value: data.totals.pending_verification },
  ];

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Overview</div>
          <h1>Identity dashboard</h1>
          <p>Account access health for VERITAS Phase 1 — approvals, verification, and recent audit activity.</p>
        </div>
        <Link className="btn" to="/admin/directory">
          Manage users
        </Link>
      </header>

      <section className="dash-metrics" aria-label="Account metrics">
        {metrics.map((item) => (
          <div className={`dash-metric ${item.emphasis ? "emphasis" : ""}`} key={item.label}>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </section>

      <section className="dash-panels">
        <div className="dash-panel">
          <div className="dash-panel-head">
            <h2>Approval queue</h2>
            <Link to="/admin/directory?status=pending_approval">View all</Link>
          </div>
          {!data.pending_approval.length ? (
            <div className="empty-state compact">
              <strong>Queue clear</strong>
              No accounts are waiting for approval.
            </div>
          ) : (
            <ul className="dash-list">
              {data.pending_approval.map((user) => (
                <li key={user.id}>
                  <span className="user-avatar">
                    <img className="avatar-art" src={avatarUrl(user.avatar)} alt="" width={40} height={40} />
                  </span>
                  <span>
                    <b>{user.display_name}</b>
                    <small>
                      @{user.username || "—"} · {user.email}
                    </small>
                  </span>
                  <span className={`badge ${user.status}`}>{formatStatus(user.status)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="dash-panel">
          <div className="dash-panel-head">
            <h2>Recent activity</h2>
            <Link className="btn ghost small" to="/admin/audit">
              Full audit log
            </Link>
          </div>
          {!data.recent_events.length ? (
            <div className="empty-state compact">
              <strong>No events yet</strong>
              Audit activity will appear here.
            </div>
          ) : (
            <ul className="dash-list activity">
              {data.recent_events.map((event) => (
                <li key={event.id}>
                  <span>
                    <b>{formatAction(event.action)}</b>
                    <small>{new Date(event.created_at).toLocaleString()}</small>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section className="dash-footnote">
        <span>
          {data.totals.admins} administrator{data.totals.admins === 1 ? "" : "s"} · {data.totals.deactivated}{" "}
          deactivated · {data.totals.rejected} rejected · {data.totals.projects ?? 0} projects ·{" "}
          {data.totals.scans ?? 0} scans · {data.totals.github_connections ?? 0} GitHub links
        </span>
      </section>
    </main>
  );
}
