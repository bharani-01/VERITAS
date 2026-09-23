import { useState } from "react";
import type { FormEvent } from "react";
import { AuthLinks, AuthShell, Link } from "../components/AuthShell";
import { api } from "../lib/api";

export function SignupPage() {
  const [notice, setNotice] = useState<{ message: string; type: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const form = event.currentTarget;
    const data = new FormData(form);
    try {
      const result = await api<{ message: string }>("/auth/signup", {
        method: "POST",
        body: JSON.stringify({
          display_name: data.get("display_name"),
          email: data.get("email"),
          password: data.get("password"),
        }),
      });
      setNotice({ message: result.message, type: "success" });
      form.reset();
    } catch (error) {
      setNotice({ message: (error as Error).message, type: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell eyebrow="Get started" title="Create account" lede="Register with a strong password. Email verification is required.">
      <form onSubmit={onSubmit}>
        <div className={`notice ${notice?.type || ""}`} role="status">
          {notice?.message || ""}
        </div>
        <div className="field">
          <label htmlFor="display_name">Display name</label>
          <input id="display_name" name="display_name" required maxLength={120} autoComplete="name" />
        </div>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" name="email" type="email" required autoComplete="email" />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            required
            minLength={12}
            autoComplete="new-password"
            aria-describedby="password-hint"
          />
          <p id="password-hint" className="muted small">
            At least 12 characters.
          </p>
        </div>
        <button type="submit" disabled={busy}>
          {busy ? "Creating account…" : "Create account"}
        </button>
        <AuthLinks>
          <Link to="/">Already have an account?</Link>
        </AuthLinks>
      </form>
    </AuthShell>
  );
}
