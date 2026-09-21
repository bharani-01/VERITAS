import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { AuthLinks, AuthShell, Link } from "../components/AuthShell";
import { api } from "../lib/api";
import type { User } from "../lib/api";

/** Local demo fills — college/dev convenience only. */
const DEMO = {
  user: {
    email: "bharani.cyber@gmail.com",
    password: "<Bharani@321>",
  },
  admin: {
    email: "admin@bharani-01.xyz",
    password: "VeritasDemo!2026",
  },
} as const;

export function LoginPage() {
  const navigate = useNavigate();
  const [notice, setNotice] = useState<{ message: string; type: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  function fillDemo(kind: keyof typeof DEMO) {
    const next = DEMO[kind];
    setEmail(next.email);
    setPassword(next.password);
    setNotice({ message: `Filled ${kind} credentials — click Sign in.`, type: "success" });
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const data = await api<{ user: User }>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      navigate(data.user.role === "admin" ? "/admin/" : "/user/");
    } catch (error) {
      setNotice({ message: (error as Error).message, type: "error" });
      setBusy(false);
    }
  }

  return (
    <AuthShell eyebrow="Welcome back" title="Sign in" lede="Use your approved VERITAS account credentials.">
      <form onSubmit={onSubmit}>
        <div className={`notice ${notice?.type || ""}`} role="status">
          {notice?.message || ""}
        </div>
        <div className="demo-fills" aria-label="Quick fill demo accounts">
          <button type="button" className="demo-fill-btn" onClick={() => fillDemo("user")} disabled={busy}>
            <span className="demo-fill-kicker">Quick fill</span>
            <span className="demo-fill-title">User</span>
            <span className="demo-fill-meta">{DEMO.user.email}</span>
          </button>
          <button type="button" className="demo-fill-btn" onClick={() => fillDemo("admin")} disabled={busy}>
            <span className="demo-fill-kicker">Quick fill</span>
            <span className="demo-fill-title">Admin</span>
            <span className="demo-fill-meta">{DEMO.admin.email}</span>
          </button>
        </div>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            name="email"
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <AuthLinks>
          <Link to="/signup">Create account</Link>
          <Link to="/forgot">Forgot password?</Link>
        </AuthLinks>
      </form>
    </AuthShell>
  );
}
