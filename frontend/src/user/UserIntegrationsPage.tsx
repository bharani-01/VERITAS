import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { GitHubStatus } from "../lib/workspace";

export function UserIntegrationsPage() {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState<GitHubStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    const data = await api<GitHubStatus>("/workspace/github/status");
    setStatus(data);
  }

  useEffect(() => {
    if (searchParams.get("connected") === "1") setMessage("GitHub connected.");
    const err = searchParams.get("error");
    if (err) setError(err.replace(/_/g, " "));
    load().catch((e: Error) => setError(e.message));
  }, [searchParams]);

  async function disconnect() {
    setBusy(true);
    setError(null);
    try {
      await api("/workspace/github/disconnect", { method: "POST" });
      setMessage("GitHub disconnected.");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function connect() {
    // Full navigation so the browser follows the OAuth redirect (not fetch).
    window.location.href = "/workspace/github/authorize";
  }

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Workspace</div>
          <h1>Integrations</h1>
          <p>
            Link your GitHub account. Only repositories you own can be attached to projects. Reconnect only if you see an
            authorization-expired banner — temporary GitHub rate limits do not require reconnecting.
          </p>
        </div>
      </header>

      {message ? (
        <div className="notice success" role="status">
          {message}
        </div>
      ) : null}
      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}

      {!status ? (
        <LoadingMark label="Loading…" />
      ) : (
        <section className="dash-panel">
          <div className="dash-panel-head">
            <h2>GitHub</h2>
          </div>
          {!status.configured ? (
            <div className="empty-state compact">
              <strong>Not configured</strong>
              {status.env_file_found === false ? (
                <p className="lede">
                  Server cannot find <code>backend/.env</code>.
                </p>
              ) : status.missing && status.missing.length > 0 ? (
                <>
                  <p className="lede">Missing in the running server process:</p>
                  <ul style={{ margin: "8px 0 0", paddingLeft: 18 }}>
                    {status.missing.map((name) => (
                      <li key={name}>
                        <code>{name}</code>
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <p className="lede">
                  Server returned an outdated GitHub status payload. Restart uvicorn without --reload and hard-refresh this
                  page.
                </p>
              )}
              <p className="lede" style={{ marginTop: 10 }}>
                Use <code>http://127.0.0.1:8000</code> only.
              </p>
            </div>
          ) : status.connected ? (
            <div className="dash-identity">
              {status.avatar_url ? (
                <span className="user-avatar large">
                  <img className="avatar-art" src={status.avatar_url} alt="" width={64} height={64} />
                </span>
              ) : null}
              <div>
                <h3>@{status.github_login}</h3>
                {status.needs_reauth ? (
                  <div className="notice warning" role="status" style={{ marginBottom: 12 }}>
                    Reconnect GitHub — authorization expired or missing repo scope.
                  </div>
                ) : (
                  <p>
                    Connected
                    {status.connected_at ? ` · ${new Date(status.connected_at).toLocaleString()}` : ""}
                  </p>
                )}
                <div className="profile-actions">
                  {status.needs_reauth ? (
                    <button type="button" className="btn" disabled={busy} onClick={connect}>
                      Reconnect GitHub
                    </button>
                  ) : null}
                  <button type="button" className="btn secondary" disabled={busy} onClick={disconnect}>
                    Disconnect
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="empty-state compact">
              <strong>Not connected</strong>
              Connect to list repositories owned by your GitHub account. Ownership is verified on the server when you
              link a repo.
              <div className="profile-actions" style={{ marginTop: 14 }}>
                <button type="button" className="btn" onClick={connect}>
                  Connect GitHub
                </button>
              </div>
            </div>
          )}
        </section>
      )}
    </main>
  );
}
