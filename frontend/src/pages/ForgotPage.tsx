import { useState } from "react";
import type { FormEvent } from "react";
import { AuthLinks, AuthShell, Link } from "../components/AuthShell";
import { api } from "../lib/api";

export function ForgotPage() {
  const [notice, setNotice] = useState<{ message: string; type: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const result = await api<{ message: string }>("/auth/password-reset/request", {
        method: "POST",
        body: JSON.stringify({ email: form.get("email") }),
      });
      setNotice({ message: result.message, type: "success" });
    } catch (error) {
      setNotice({ message: (error as Error).message, type: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell eyebrow="Recovery" title="Reset password" lede="We will email a reset link if an active account uses this address.">
      <form onSubmit={onSubmit}>
        <div className={`notice ${notice?.type || ""}`} role="status">
          {notice?.message || ""}
        </div>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" name="email" type="email" required autoComplete="email" />
        </div>
        <button type="submit" disabled={busy}>
          {busy ? "Sending link…" : "Send reset link"}
        </button>
        <AuthLinks>
          <Link to="/">Return to sign in</Link>
        </AuthLinks>
      </form>
    </AuthShell>
  );
}
