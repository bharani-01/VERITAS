import { useEffect, useState } from "react";
import { Outlet, useNavigate } from "react-router-dom";
import { UserNav } from "./UserNav";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { User } from "../lib/api";
import { readNavCollapsed, writeNavCollapsed } from "../lib/navPreference";

/** User workspace only — never mounts admin-area UI. */
export function UserShell() {
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null);
  const [collapsed, setCollapsed] = useState(() => readNavCollapsed("user"));
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const id = requestAnimationFrame(() => setReady(true));
    return () => cancelAnimationFrame(id);
  }, []);

  useEffect(() => {
    let active = true;
    async function checkAuth(retries = 1) {
      try {
        const { user: current } = await api<{ user: User }>("/auth/me");
        if (!active) return;
        if (current.role === "admin") {
          navigate("/admin/", { replace: true });
          return;
        }
        setUser(current);
      } catch (err) {
        if (!active) return;
        if (retries > 0) {
          setTimeout(() => void checkAuth(retries - 1), 600);
          return;
        }
        navigate("/");
      }
    }
    void checkAuth();
    return () => {
      active = false;
    };
  }, [navigate]);

  function onToggle() {
    const next = !collapsed;
    setCollapsed(next);
    writeNavCollapsed("user", next);
  }

  async function onLogout() {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch {
      /* ignore */
    }
    navigate("/");
  }

  if (!user) {
    return <LoadingMark fullPage label="Loading workspace…" size="lg" />;
  }

  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <div className={`app-frame ${ready ? "nav-ready" : ""} ${collapsed ? "nav-collapsed" : ""}`} id="appFrame">
        <UserNav user={user} collapsed={collapsed} onToggle={onToggle} onLogout={onLogout} />
        <div id="main-content" tabIndex={-1}>
          <Outlet context={{ user, setUser }} />
        </div>
      </div>
    </>
  );
}
