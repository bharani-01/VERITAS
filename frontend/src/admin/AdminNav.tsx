import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import type { User } from "../lib/api";
import { avatarUrl } from "../lib/avatars";
import { applyTheme } from "../lib/theme";

type Props = {
  user: User;
  collapsed: boolean;
  onToggle: () => void;
  onLogout: () => void;
};

function BrandMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <img src="/brand/veritas-mark.png" alt="" width={28} height={28} decoding="async" />
    </span>
  );
}

/** Admin-only navigation. Not used by the user area. */
export function AdminNav({ user, collapsed, onToggle, onLogout }: Props) {
  const { pathname } = useLocation();
  const dashActive = pathname === "/admin" || pathname === "/admin/";
  const usersActive = pathname.startsWith("/admin/directory");
  const auditActive = pathname.startsWith("/admin/audit");
  const [menuOpen, setMenuOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const closeTimer = useRef<number | null>(null);
  const handle = user.username ? `@${user.username}` : user.display_name;

  useEffect(() => {
    applyTheme("dark");
  }, []);

  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (!wrapRef.current?.contains(e.target as Node)) setMenuOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setMenuOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, []);

  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  return (
    <aside className="app-nav">
      <div className="nav-top">
        <div className="brand">
          <BrandMark />
          <span className="brand-text">VERITAS</span>
        </div>
        <button
          type="button"
          className="nav-toggle"
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          aria-expanded={!collapsed}
          onClick={onToggle}
        >
          <svg className="icon icon-collapse" viewBox="0 0 24 24">
            <rect x="3" y="4" width="18" height="16" rx="2" />
            <path d="M9 4v16" />
            <path d="M14 9l-3 3 3 3" />
          </svg>
          <svg className="icon icon-expand" viewBox="0 0 24 24">
            <rect x="3" y="4" width="18" height="16" rx="2" />
            <path d="M9 4v16" />
            <path d="M12 9l3 3-3 3" />
          </svg>
        </button>
      </div>
      <p className="nav-label">Admin</p>
      <Link
        className={`nav-link ${dashActive ? "active" : ""}`}
        to="/admin/"
        aria-label="Overview"
        aria-current={dashActive ? "page" : undefined}
      >
        <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
          <rect x="3" y="3" width="7" height="9" rx="1" />
          <rect x="14" y="3" width="7" height="5" rx="1" />
          <rect x="14" y="12" width="7" height="9" rx="1" />
          <rect x="3" y="16" width="7" height="5" rx="1" />
        </svg>
        <span className="nav-link-text">Overview</span>
      </Link>
      <Link
        className={`nav-link ${usersActive ? "active" : ""}`}
        to="/admin/directory"
        aria-label="Users"
        aria-current={usersActive ? "page" : undefined}
      >
        <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
          <circle cx="9" cy="7" r="4" />
          <path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
        </svg>
        <span className="nav-link-text">Users</span>
      </Link>
      <Link
        className={`nav-link ${auditActive ? "active" : ""}`}
        to="/admin/audit"
        aria-label="Audit"
        aria-current={auditActive ? "page" : undefined}
      >
        <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 3v18" />
          <path d="M5 8h14" />
          <path d="M5 14h10" />
          <path d="M5 20h7" />
        </svg>
        <span className="nav-link-text">Audit</span>
      </Link>

      <div className={`nav-account ${menuOpen ? "open" : ""}`} ref={wrapRef}>
        {menuOpen ? (
          <div className="account-menu" role="menu" aria-label="Account">
            <div className="account-menu-head" role="presentation">
              <span className="account-avatar">
                <img src={avatarUrl(user.avatar)} alt="" width={36} height={36} />
              </span>
              <span className="account-head-text">
                <b>{handle}</b>
                <small>Administrator</small>
              </span>
            </div>
            <div className="account-menu-sep" />
            <Link className="account-menu-item" to="/admin/profile" role="menuitem" onClick={() => setMenuOpen(false)}>
              <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                <circle cx="12" cy="7" r="4" />
              </svg>
              Profile
            </Link>
            <Link className="account-menu-item" to="/admin/settings" role="menuitem" onClick={() => setMenuOpen(false)}>
              <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="12" cy="12" r="3" />
                <path d="M12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4" />
              </svg>
              Settings
            </Link>
            <div className="account-menu-sep" />
            <button type="button" className="account-menu-item danger" role="menuitem" onClick={onLogout}>
              <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                <path d="M16 17l5-5-5-5" />
                <path d="M21 12H9" />
              </svg>
              Log out
            </button>
          </div>
        ) : null}

        <button
          type="button"
          className="nav-account-chip"
          aria-label={`Account menu for ${handle}`}
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          onClick={(e) => {
            e.stopPropagation();
            if (closeTimer.current) window.clearTimeout(closeTimer.current);
            setMenuOpen((v) => !v);
          }}
        >
          <span className="account-avatar small">
            <img src={avatarUrl(user.avatar)} alt="" width={28} height={28} />
          </span>
          <span className="nav-account-meta">
            <b>{handle}</b>
            <small>Admin</small>
          </span>
        </button>
      </div>
    </aside>
  );
}
