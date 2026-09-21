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
    api<{ user: User }>("/auth/me")
      .then(({ user: current }) => {
        if (current.role === "admin") {
          navigate("/admin/");
          return;
        }
        setUser(current);
      })
      .catch(() => navigate("/"));
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
    <div className={`app-frame ${ready ? "nav-ready" : ""} ${collapsed ? "nav-collapsed" : ""}`} id="appFrame">
      <UserNav user={user} collapsed={collapsed} onToggle={onToggle} onLogout={onLogout} />
      <Outlet context={{ user, setUser }} />
    </div>
  );
}
