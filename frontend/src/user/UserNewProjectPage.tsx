import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { GitHubRepo, GitHubStatus, GitRef, Project } from "../lib/workspace";

/** Full-page create flow — flat Render layout, no card chrome. */
export function UserNewProjectPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [gh, setGh] = useState<GitHubStatus | null>(null);
  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [repoQuery, setRepoQuery] = useState("");
  const [githubRepoId, setGithubRepoId] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [autoScanOnPush, setAutoScanOnPush] = useState(false);
  const [autoScanBranch, setAutoScanBranch] = useState("");
  const [branchOptions, setBranchOptions] = useState<GitRef[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [disconnectBusy, setDisconnectBusy] = useState(false);

  async function loadGithub() {
    const status = await api<GitHubStatus>("/workspace/github/status");
    setGh(status);
    if (status.connected && !status.needs_reauth) {
      try {
        const data = await api<{ items: GitHubRepo[] }>("/workspace/github/repos");
        setRepos(data.items);
      } catch {
        setRepos([]);
      }
    } else {
      setRepos([]);
    }
  }

  useEffect(() => {
    if (searchParams.get("connected") === "1") setMessage("GitHub connected. Choose a repository below.");
    const err = searchParams.get("error");
    if (err) setError(err.replace(/_/g, " "));
    loadGithub()
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [searchParams]);

  const selectedRepo = useMemo(
    () => repos.find((r) => String(r.id) === githubRepoId) || null,
    [repos, githubRepoId],
  );

  const filteredRepos = useMemo(() => {
    const q = repoQuery.trim().toLowerCase();
    if (!q) return repos;
    return repos.filter(
      (r) => r.full_name.toLowerCase().includes(q) || r.name.toLowerCase().includes(q),
    );
  }, [repos, repoQuery]);

  useEffect(() => {
    if (!selectedRepo) {
      setBranchOptions([]);
      return;
    }
    const branch = selectedRepo.default_branch || "main";
    setAutoScanBranch(branch);
    setBranchOptions([{ name: branch, type: "branch" }]);
  }, [selectedRepo]);

  function connectGithub() {
    window.location.href = "/workspace/github/authorize";
  }

  async function disconnectGithub() {
    setDisconnectBusy(true);
    setError(null);
    try {
      await api("/workspace/github/disconnect", { method: "POST" });
      setMessage("GitHub disconnected.");
      setGithubRepoId("");
      setName("");
      await loadGithub();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setDisconnectBusy(false);
    }
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    if (!githubRepoId) {
      setError("Select a GitHub repository.");
      return;
    }
    if (!name.trim()) {
      setError("Enter a project name.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        name: name.trim(),
        description: description.trim(),
        github_repo_id: Number(githubRepoId),
        auto_scan_on_push: autoScanOnPush,
      };
      if (autoScanOnPush && autoScanBranch.trim()) {
        body.auto_scan_branch = autoScanBranch.trim();
      }
      const created = await api<{ project: Project }>("/workspace/projects", {
        method: "POST",
        body: JSON.stringify(body),
      });
      navigate(`/user/projects/${created.project.id}`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <main className="admin-main">
        <LoadingMark label="Loading…" />
      </main>
    );
  }

  const githubReady = !!gh?.configured && !!gh.connected && !gh.needs_reauth;

  return (
    <main className="admin-main new-project-page">
      <div className="new-project-wrap">
        <header className="new-project-header">
          <nav className="new-project-crumb" aria-label="Breadcrumb">
            <Link to="/user/projects">Projects</Link>
            <span aria-hidden="true">/</span>
            <span>New</span>
          </nav>
          <h1>New project</h1>
          <p>Connect GitHub, choose a repository you own, then name the project.</p>
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

        <form className="new-project-form" onSubmit={(e) => void onCreate(e)}>
          <section className="np-block">
            <h2 className="np-label">Account</h2>
            {!gh?.configured ? (
              <p className="np-empty">GitHub OAuth is not configured on this server.</p>
            ) : githubReady ? (
              <div className="np-account">
                {gh.avatar_url ? (
                  <img className="np-avatar" src={gh.avatar_url} alt="" width={36} height={36} />
                ) : (
                  <span className="np-avatar placeholder" aria-hidden="true">
                    {(gh.github_login || "?").slice(0, 1).toUpperCase()}
                  </span>
                )}
                <div className="np-account-text">
                  <strong>@{gh.github_login}</strong>
                  <span>GitHub · connected</span>
                </div>
                <button
                  type="button"
                  className="np-text-btn"
                  disabled={disconnectBusy}
                  onClick={() => void disconnectGithub()}
                >
                  {disconnectBusy ? "…" : "Disconnect"}
                </button>
              </div>
            ) : (
              <div className="np-connect">
                {gh.needs_reauth ? (
                  <p className="notice warning" role="status">
                    Reconnect GitHub — authorization expired or missing repo scope.
                  </p>
                ) : (
                  <p className="muted">No GitHub account linked yet.</p>
                )}
                <button type="button" className="btn" onClick={connectGithub}>
                  {gh.needs_reauth ? "Reconnect GitHub" : "Connect GitHub"}
                </button>
              </div>
            )}
          </section>

          <section className={`np-block ${githubReady ? "" : "is-disabled"}`}>
            <h2 className="np-label">Repository</h2>
            {githubReady ? (
              <>
                <input
                  className="np-input"
                  value={repoQuery}
                  onChange={(e) => setRepoQuery(e.target.value)}
                  placeholder="Filter repositories…"
                  autoComplete="off"
                  aria-label="Filter repositories"
                />
                {!filteredRepos.length ? (
                  <p className="np-empty">
                    {repoQuery ? "No repositories match that filter." : "No owned repositories found."}
                  </p>
                ) : (
                  <ul className="np-repos" role="listbox" aria-label="Repositories">
                    {filteredRepos.map((repo) => {
                      const selected = String(repo.id) === githubRepoId;
                      return (
                        <li key={repo.id}>
                          <button
                            type="button"
                            role="option"
                            aria-selected={selected}
                            className={`np-repo ${selected ? "is-selected" : ""}`}
                            onClick={() => {
                              setGithubRepoId(String(repo.id));
                              setName(repo.name);
                            }}
                          >
                            <span className="np-repo-mark" aria-hidden="true">
                              {selected ? (
                                <svg viewBox="0 0 24 24">
                                  <path
                                    d="M20 6 9 17l-5-5"
                                    fill="none"
                                    stroke="currentColor"
                                    strokeWidth="2.5"
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                  />
                                </svg>
                              ) : null}
                            </span>
                            <span className="np-repo-body">
                              <span className="np-repo-name">{repo.full_name}</span>
                              <span className="np-repo-meta">
                                {repo.private ? "Private" : "Public"}
                                {repo.default_branch ? ` · ${repo.default_branch}` : ""}
                              </span>
                            </span>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </>
            ) : (
              <p className="np-empty">Connect GitHub to choose a repository.</p>
            )}
          </section>

          <section className={`np-block ${githubRepoId ? "" : "is-disabled"}`}>
            <h2 className="np-label">Project name</h2>
            <label className="np-field">
              <span className="sr-only">Name</span>
              <input
                className="np-input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                maxLength={120}
                disabled={!githubRepoId}
                placeholder="my-app"
              />
            </label>
          </section>

          <section className="np-block np-advanced">
            <button
              type="button"
              className="np-advanced-toggle"
              aria-expanded={showAdvanced}
              onClick={() => setShowAdvanced((v) => !v)}
            >
              <span>
                <strong>Advanced</strong>
                <span className="muted"> Description · auto-scan · branch</span>
              </span>
              <svg className={`icon ${showAdvanced ? "is-open" : ""}`} viewBox="0 0 24 24" aria-hidden="true">
                <path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              </svg>
            </button>
            {showAdvanced ? (
              <div className="np-advanced-body">
                <label className="np-field">
                  <span>Description</span>
                  <input
                    className="np-input"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    maxLength={2000}
                    placeholder="Optional"
                  />
                </label>
                <label className="np-check">
                  <input
                    type="checkbox"
                    checked={autoScanOnPush}
                    disabled={!githubRepoId}
                    onChange={(e) => setAutoScanOnPush(e.target.checked)}
                  />
                  <span>Auto-scan on push</span>
                </label>
                <label className="np-field">
                  <span>Watched branch</span>
                  <select
                    className="np-input"
                    value={autoScanBranch}
                    disabled={!autoScanOnPush || !githubRepoId}
                    onChange={(e) => setAutoScanBranch(e.target.value)}
                  >
                    {(branchOptions.length
                      ? branchOptions
                      : [{ name: selectedRepo?.default_branch || "main", type: "branch" }]
                    ).map((b) => (
                      <option key={b.name} value={b.name}>
                        {b.name}
                        {b.name === selectedRepo?.default_branch ? " (default)" : ""}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            ) : null}
          </section>

          <div className="np-actions">
            <Link className="btn ghost" to="/user/projects">
              Cancel
            </Link>
            <button className="btn" type="submit" disabled={busy || !githubRepoId || !name.trim()}>
              {busy ? "Creating…" : "Create project"}
            </button>
          </div>
        </form>
      </div>
    </main>
  );
}
