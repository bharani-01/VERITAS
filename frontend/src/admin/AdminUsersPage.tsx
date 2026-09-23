import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import type { User } from "../lib/api";
import { avatarUrl, formatStatus } from "../lib/avatars";
import { formatLocalDate, formatLocalDateTime } from "../lib/time";

type MenuPos = { top: number; left: number };

export function AdminUsersPage() {
  const [searchParams] = useSearchParams();
  const [users, setUsers] = useState<User[]>([]);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState(() => searchParams.get("status") || "");
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const [menuPos, setMenuPos] = useState<MenuPos | null>(null);

  useEffect(() => {
    const fromUrl = searchParams.get("status") || "";
    setStatus(fromUrl);
  }, [searchParams]);

  async function fetchUsers() {
    const data = await api<{ items: User[] }>(
      `/admin/users?q=${encodeURIComponent(q)}&account_status=${encodeURIComponent(status)}`,
    );
    setUsers(data.items);
  }

  useEffect(() => {
    fetchUsers().catch((error: Error) => alert(error.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, status]);

  useEffect(() => {
    const close = () => {
      setOpenMenu(null);
      setMenuPos(null);
    };
    document.addEventListener("click", close);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    return () => {
      document.removeEventListener("click", close);
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
    };
  }, []);

  async function runAction(action: string, id: string) {
    setOpenMenu(null);
    setMenuPos(null);
    try {
      if (action === "edit") {
        const current = users.find((x) => x.id === id);
        if (!current) return;
        const display_name = prompt("Display name", current.display_name);
        if (display_name === null) return;
        const email = prompt("Email address", current.email);
        if (email === null) return;
        const role = prompt("Role: admin or user", current.role);
        if (role === null) return;
        await api(`/admin/users/${id}`, {
          method: "PATCH",
          body: JSON.stringify({ display_name, email, role }),
        });
      } else if (action === "history") {
        const details = await api<{ audit_events: { created_at: string; action: string }[] }>(`/admin/users/${id}`);
        alert(
          details.audit_events.map((x) => `${formatLocalDateTime(x.created_at)} — ${x.action}`).join("\n") ||
            "No audit events yet.",
        );
      } else {
        await api(`/admin/users/${id}/${action}`, { method: "POST" });
      }
      await fetchUsers();
    } catch (error) {
      alert((error as Error).message);
    }
  }

  function menuItems(user: User) {
    const items: { action?: string; label?: string; danger?: boolean; sep?: boolean }[] = [
      { action: "edit", label: "Edit profile" },
      { action: "history", label: "View history" },
    ];
    if (user.status === "pending_approval") {
      items.push({ sep: true }, { action: "approve", label: "Approve" }, { action: "reject", label: "Reject", danger: true });
    }
    if (user.status === "active") items.push({ sep: true }, { action: "deactivate", label: "Deactivate", danger: true });
    if (user.status === "deactivated") items.push({ sep: true }, { action: "reactivate", label: "Reactivate" });
    return items;
  }

  function openRowMenu(userId: string, trigger: HTMLElement) {
    if (openMenu === userId) {
      setOpenMenu(null);
      setMenuPos(null);
      return;
    }
    const rect = trigger.getBoundingClientRect();
    const width = 188;
    const approxHeight = 220;
    let left = rect.right - width;
    let top = rect.bottom + 4;
    if (left < 8) left = 8;
    if (left + width > window.innerWidth - 8) left = Math.max(8, window.innerWidth - width - 8);
    if (top + approxHeight > window.innerHeight - 8) top = Math.max(8, rect.top - approxHeight - 4);
    setMenuPos({ top, left });
    setOpenMenu(userId);
  }

  const openUser = users.find((u) => u.id === openMenu) || null;

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Administration</div>
          <h1>Users</h1>
          <p>Approve, manage, and audit account access.</p>
        </div>
      </header>
      <div className="toolbar" aria-label="Filters">
        <div className="field-wrap">
          <input
            type="search"
            placeholder="Search name, username, or email"
            aria-label="Search users"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
          <option value="">All statuses</option>
          <option value="pending_verification">Pending verification</option>
          <option value="pending_approval">Pending approval</option>
          <option value="active">Active</option>
          <option value="rejected">Rejected</option>
          <option value="deactivated">Deactivated</option>
        </select>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>Status</th>
              <th>Activity</th>
              <th className="col-actions">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {!users.length ? (
              <tr>
                <td colSpan={5}>
                  <div className="empty-state">
                    <strong>No users match</strong>
                    Adjust search or status filters.
                  </div>
                </td>
              </tr>
            ) : (
              users.map((u) => {
                const activity = u.last_login_at || u.email_verified_at
                  ? formatLocalDate(u.last_login_at || u.email_verified_at)
                  : "—";
                return (
                  <tr key={u.id}>
                    <td>
                      <div className="user-cell">
                        <span className="user-avatar">
                          <img className="avatar-art" src={avatarUrl(u.avatar)} alt="" width={80} height={80} loading="lazy" />
                        </span>
                        <span>
                          <b>{u.display_name}</b>
                          <small>
                            @{u.username || "—"} · {u.email}
                          </small>
                        </span>
                      </div>
                    </td>
                    <td>{u.role}</td>
                    <td>
                      <span className={`badge ${u.status}`}>{formatStatus(u.status)}</span>
                    </td>
                    <td>{activity}</td>
                    <td className="col-actions">
                      <div className={`menu ${openMenu === u.id ? "open" : ""}`}>
                        <button
                          type="button"
                          className="menu-trigger"
                          aria-label={`Manage ${u.display_name}`}
                          aria-haspopup="menu"
                          aria-expanded={openMenu === u.id}
                          onClick={(e) => {
                            e.stopPropagation();
                            openRowMenu(u.id, e.currentTarget);
                          }}
                        >
                          <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
                            <circle cx="12" cy="5" r="1.4" fill="currentColor" stroke="none" />
                            <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
                            <circle cx="12" cy="19" r="1.4" fill="currentColor" stroke="none" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      {openUser &&
        menuPos &&
        createPortal(
          <div
            className="menu-panel menu-panel-fixed"
            role="menu"
            style={{ top: menuPos.top, left: menuPos.left }}
            onClick={(e) => e.stopPropagation()}
          >
            {menuItems(openUser).map((item, index) =>
              item.sep ? (
                <div className="menu-sep" role="separator" key={`sep-${index}`} />
              ) : (
                <button
                  key={item.action}
                  type="button"
                  className={item.danger ? "danger" : ""}
                  onClick={() => runAction(item.action!, openUser.id)}
                >
                  {item.label}
                </button>
              ),
            )}
          </div>,
          document.body,
        )}
    </main>
  );
}
