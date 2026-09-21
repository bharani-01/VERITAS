import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AuthLinks, AuthShell, Link } from "../components/AuthShell";
import { api } from "../lib/api";

export function ResetPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [notice, setNotice] = useState<{ message: string; type: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const result = await api<{ message: string }>("/auth/password-reset/confirm", {
        method: "POST",
        body: JSON.stringify({
          token: params.get("token"),
          password: form.get("password"),
        }),
      });
      setNotice({ message: result.message, type: "success" });
      setTimeout(() => navigate("/"), 900);
    } catch (error) {
      setNotice({ message: (error as Error).message, type: "error" });
      setBusy(false);
    }
  }

  return (
    <AuthShell eyebrow="Recovery" title="Choose a new password" lede="Use at least 12 characters for your replacement password.">
      <form onSubmit={onSubmit}>
        <div className={`notice ${notice?.type || ""}`} role="status">
          {notice?.message || ""}
        </div>
        <div className="field">
          <label htmlFor="password">New password</label>
          <input id="password" name="password" type="password" required minLength={12} autoComplete="new-password" />
        </div>
        <button type="submit" disabled={busy}>
          {busy ? "Updating password…" : "Update password"}
        </button>
        <AuthLinks>
          <Link to="/">Return to sign in</Link>
        </AuthLinks>
      </form>
    </AuthShell>
  );
}
