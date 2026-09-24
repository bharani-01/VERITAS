import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import type { User } from "../lib/api";
import { avatarUrl } from "../lib/avatars";
import { initialsFromName } from "../lib/preferences";
import { applyTheme } from "../lib/theme";

type Props = {
  user: User;
  collapsed: boolean;
  onToggle: () => void;
  onLogout: () => void;
};

function BrandMark() {
  return (
    <img className="brand-nav-logo" src="/brand/veritas-mark.png" alt="" height={28} width={28} decoding="async" />
  );
}

/** User-only navigation. Not used by the admin area. */
export function UserNav({ user, collapsed, onToggle, onLogout }: Props) {
  const { pathname } = useLocation();
  const homeActive = pathname === "/user" || pathname === "/user/";
  const projectsActive = pathname.startsWith("/user/projects") || pathname.startsWith("/user/scans");
  const [menuOpen, setMenuOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const closeTimer = useRef<number | null>(null);

  const handle = user.username ? `@${user.username}` : user.display_name;
  const roleLabel = user.role === "admin" ? "Admin" : "User";

  useEffect(() => {
    applyTheme("light");
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
      <p className="nav-label">Workspace</p>
      <Link
        className={`nav-link ${homeActive ? "active" : ""}`}
        to="/user/"
        aria-label="Home"
        aria-current={homeActive ? "page" : undefined}
      >
        <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M3 10.5 12 3l9 7.5" />
          <path d="M5 9.5V20h14V9.5" />
        </svg>
        <span className="nav-link-text">Home</span>
      </Link>
      <Link
        className={`nav-link ${projectsActive ? "active" : ""}`}
        to="/user/projects"
        aria-label="Projects"
        aria-current={projectsActive ? "page" : undefined}
      >
        <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M3 7h18v12H3z" />
          <path d="M3 7l2.5-3h13L21 7" />
        </svg>
        <span className="nav-link-text">Projects</span>
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
                <small>{roleLabel}</small>
              </span>
            </div>
            <div className="account-menu-sep" />
            <Link className="account-menu-item" to="/user/profile" role="menuitem" onClick={() => setMenuOpen(false)}>
              <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                <circle cx="12" cy="7" r="4" />
              </svg>
              Profile
            </Link>
            <Link className="account-menu-item" to="/user/settings" role="menuitem" onClick={() => setMenuOpen(false)}>
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
            {user.avatar ? (
              <img src={avatarUrl(user.avatar)} alt="" width={28} height={28} />
            ) : (
              <span className="account-initials">{initialsFromName(user.display_name)}</span>
            )}
          </span>
          <span className="nav-account-meta">
            <b>{handle}</b>
            <small>{roleLabel}</small>
          </span>
        </button>
      </div>
    </aside>
  );
}
