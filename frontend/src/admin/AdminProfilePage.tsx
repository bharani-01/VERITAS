import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { api } from "../lib/api";
import type { User } from "../lib/api";
import { AVATARS, avatarUrl, formatStatus } from "../lib/avatars";
import { formatLocalDateTime } from "../lib/time";

type ShellContext = {
  user: User;
  setUser: (user: User) => void;
};

/** Admin-only profile page at /admin/profile — not shared with /user/. */
export function AdminProfilePage() {
  const { user: shellUser, setUser: setShellUser } = useOutletContext<ShellContext>();
  const [user, setUser] = useState<User>(shellUser);
  const [selectedAvatar, setSelectedAvatar] = useState(shellUser.avatar || "slate");
  const [notice, setNotice] = useState<{ message: string; type: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setUser(shellUser);
    setSelectedAvatar(shellUser.avatar || "slate");
  }, [shellUser]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const data = await api<{ user: User; message: string }>("/auth/me", {
        method: "POST",
        body: JSON.stringify({
          display_name: String(form.get("display_name") || "").trim(),
          username: String(form.get("username") || "").trim(),
          avatar: selectedAvatar,
        }),
      });
      setUser(data.user);
      setShellUser(data.user);
      setSelectedAvatar(data.user.avatar || "slate");
      setNotice({ message: data.message || "Profile updated.", type: "success" });
    } catch (error) {
      setNotice({ message: (error as Error).message, type: "error" });
    } finally {
      setBusy(false);
    }
  }

  const handle = user.username ? `@${user.username}` : "No username yet";

  return (
    <main className="admin-main profile-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Administrator</div>
          <h1>My account</h1>
          <p>Update your administrator identity settings.</p>
        </div>
      </header>
      <form className="profile-shell" onSubmit={onSubmit}>
        <div className={`notice ${notice?.type || ""}`} role="status">
          {notice?.message || ""}
        </div>
        <section className="profile-banner">
          <div className="avatar-preview">
            <img className="avatar-art" src={avatarUrl(selectedAvatar)} alt="" width={80} height={80} />
          </div>
          <div className="profile-banner-copy">
            <h2>{user.display_name}</h2>
            <p>
              {handle} · {user.email}
            </p>
            <span className={`badge ${user.status}`}>{formatStatus(user.status)}</span>
          </div>
          <div className="profile-banner-meta">
            <div>
              <span>Role</span>
              <strong>{user.role}</strong>
            </div>
            <div>
              <span>Last login</span>
              <strong>{user.last_login_at ? formatLocalDateTime(user.last_login_at) : "—"}</strong>
            </div>
          </div>
        </section>
        <section className="profile-card rr-row">
          <div className="rr-meta profile-card-head">
            <h3>Profile photo</h3>
            <p>Choose an avatar for the directory and account views.</p>
          </div>
          <div className="rr-controls">
            <div className="avatar-grid">
              {AVATARS.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className={`avatar-option ${item.id === selectedAvatar ? "selected" : ""}`}
                  aria-label={item.label}
                  aria-pressed={item.id === selectedAvatar}
                  title={item.label}
                  onClick={() => setSelectedAvatar(item.id)}
                >
                  <img className="avatar-art" src={avatarUrl(item.id)} alt={item.label} width={80} height={80} />
                </button>
              ))}
            </div>
          </div>
        </section>
        <section className="profile-card rr-row">
          <div className="rr-meta profile-card-head">
            <h3>Public details</h3>
            <p>Name and username appear across VERITAS.</p>
          </div>
          <div className="rr-controls">
            <div className="profile-form-grid">
              <div className="field">
                <label htmlFor="admin_display_name">Display name</label>
                <input
                  id="admin_display_name"
                  name="display_name"
                  required
                  maxLength={120}
                  defaultValue={user.display_name}
                  key={`admin-name-${user.id}-${user.display_name}`}
                  autoComplete="name"
                />
              </div>
              <div className="field">
                <label htmlFor="admin_username">Username</label>
                <input
                  id="admin_username"
                  name="username"
                  required
                  minLength={3}
                  maxLength={32}
                  pattern="[a-z][a-z0-9_]{2,31}"
                  defaultValue={user.username || ""}
                  key={`admin-user-${user.id}-${user.username}`}
                  autoComplete="username"
                  placeholder="your_handle"
                />
                <p className="hint">Lowercase letters, numbers, underscores.</p>
              </div>
              <div className="field">
                <label htmlFor="admin_email">Email</label>
                <input id="admin_email" name="email" type="email" value={user.email} disabled />
                <p className="hint">Verified email is locked.</p>
              </div>
            </div>
            <div className="profile-actions">
              <button type="submit" disabled={busy}>
                {busy ? "Saving…" : "Save changes"}
              </button>
              <Link className="btn secondary" to="/forgot">
                Change password
              </Link>
            </div>
          </div>
        </section>
      </form>
    </main>
  );
}
