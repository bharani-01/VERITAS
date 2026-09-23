import { useEffect, useState } from "react";
import { Outlet, useNavigate } from "react-router-dom";
import { AdminNav } from "./AdminNav";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { User } from "../lib/api";
import { readNavCollapsed, writeNavCollapsed } from "../lib/navPreference";

/** Admin workspace only — never mounts user-area UI. */
export function AdminShell() {
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null);
  const [collapsed, setCollapsed] = useState(() => readNavCollapsed("admin"));
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const id = requestAnimationFrame(() => setReady(true));
    return () => cancelAnimationFrame(id);
  }, []);

  useEffect(() => {
    api<{ user: User }>("/auth/me")
      .then(({ user: current }) => {
        if (current.role !== "admin") {
          navigate("/user/");
          return;
        }
        setUser(current);
      })
      .catch(() => navigate("/"));
  }, [navigate]);

  function onToggle() {
    const next = !collapsed;
    setCollapsed(next);
    writeNavCollapsed("admin", next);
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
    return <LoadingMark fullPage label="Loading admin…" size="lg" />;
  }

  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <div className={`app-frame ${ready ? "nav-ready" : ""} ${collapsed ? "nav-collapsed" : ""}`} id="appFrame">
        <AdminNav user={user} collapsed={collapsed} onToggle={onToggle} onLogout={onLogout} />
        <div id="main-content" tabIndex={-1}>
          <Outlet context={{ user, setUser }} />
        </div>
      </div>
    </>
  );
}
