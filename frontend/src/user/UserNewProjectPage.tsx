import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { GitHubRepo, GitHubStatus, GitRef, Project } from "../lib/workspace";

/**
 * Create-from-GitHub flow:
 * 1) Connect GitHub if needed
 * 2) Search + pick an owned repo (list collapses once selected)
 * 3) Name the project → Create (optional settings collapsed)
 */
export function UserNewProjectPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const nameInputRef = useRef<HTMLInputElement>(null);
  const [gh, setGh] = useState<GitHubStatus | null>(null);
  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [repoQuery, setRepoQuery] = useState("");
  const [githubRepoId, setGithubRepoId] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [autoScanOnPush, setAutoScanOnPush] = useState(false);
  const [autoScanBranch, setAutoScanBranch] = useState("");
  const [branchOptions, setBranchOptions] = useState<GitRef[]>([]);
  const [refsLoading, setRefsLoading] = useState(false);
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
    if (searchParams.get("connected") === "1") setMessage("GitHub connected. Pick a repository to continue.");
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
      setRefsLoading(false);
      return;
    }
    const fallback = selectedRepo.default_branch || "main";
    setAutoScanBranch(fallback);
    setBranchOptions([{ name: fallback, type: "branch" }]);
    let cancelled = false;
    setRefsLoading(true);
    api<{ branches: GitRef[]; tags: GitRef[]; default?: string | null }>(
      `/workspace/github/repos/${selectedRepo.id}/refs`,
    )
      .then((data) => {
        if (cancelled) return;
        const branches = data.branches?.length
          ? data.branches
          : [{ name: fallback, type: "branch" as const }];
        setBranchOptions(branches);
        const def = data.default || fallback;
        setAutoScanBranch((prev) => (branches.some((b) => b.name === prev) ? prev : def));
      })
      .catch(() => {
        if (!cancelled) setBranchOptions([{ name: fallback, type: "branch" }]);
      })
      .finally(() => {
        if (!cancelled) setRefsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedRepo]);

  useEffect(() => {
    if (!selectedRepo) return;
    const id = window.requestAnimationFrame(() => nameInputRef.current?.focus());
    return () => window.cancelAnimationFrame(id);
  }, [selectedRepo?.id]);

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
      setDescription("");
      setShowAdvanced(false);
      await loadGithub();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setDisconnectBusy(false);
    }
  }

  function pickRepo(repo: GitHubRepo) {
    setGithubRepoId(String(repo.id));
    setName(repo.name);
    if (repo.description) setDescription(repo.description.slice(0, 2000));
    setError(null);
    setRepoQuery("");
  }

  function clearRepo() {
    setGithubRepoId("");
    setName("");
    setDescription("");
    setShowAdvanced(false);
    setError(null);
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
  const defaultBranch = selectedRepo?.default_branch || "main";
  const canCreate = !!githubRepoId && !!name.trim() && !busy;
  const step = !githubReady ? 1 : selectedRepo ? 3 : 2;

  return (
    <main className="admin-main new-project-page">
      <div className="np-flow">
        <header className="np-flow-header">
          <nav className="new-project-crumb" aria-label="Breadcrumb">
            <Link to="/user/projects">Projects</Link>
            <span aria-hidden="true">/</span>
            <span>New</span>
          </nav>
          <h1>New project</h1>
          <p>Import a GitHub repo you own. VERITAS will scan it for secrets, dependencies, and code issues.</p>
        </header>

        <ol className="np-progress" aria-label="Create project steps">
          <li className={step >= 1 ? (step === 1 ? "is-current" : "is-done") : ""}>
            <span className="np-progress-num" aria-hidden="true">
              1
            </span>
            <span>Connect</span>
          </li>
          <li className={step >= 2 ? (step === 2 ? "is-current" : "is-done") : ""}>
            <span className="np-progress-num" aria-hidden="true">
              2
            </span>
            <span>Choose repo</span>
          </li>
          <li className={step >= 3 ? (step === 3 ? "is-current" : "is-done") : ""}>
            <span className="np-progress-num" aria-hidden="true">
              3
            </span>
            <span>Create</span>
          </li>
        </ol>

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

        {!gh?.configured ? (
          <section className="np-gate">
            <h2>GitHub is not configured</h2>
            <p>Ask an administrator to set GitHub OAuth on this server before creating projects.</p>
            <Link className="btn ghost" to="/user/projects">
              Back to projects
            </Link>
          </section>
        ) : !githubReady ? (
          <section className="np-gate">
            <div className="np-gate-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
                <path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.89 1.52 2.34 1.08 2.91.83.09-.65.35-1.08.63-1.33-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02A9.56 9.56 0 0 1 12 6.8c.85 0 1.71.11 2.51.33 1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 12 2z" />
              </svg>
            </div>
            <h2>{gh.needs_reauth ? "Reconnect GitHub" : "Connect GitHub to continue"}</h2>
            <p>
              {gh.needs_reauth
                ? "Your GitHub authorization expired or is missing repo access. Reconnect, then choose a repository."
                : "One-time connect. You’ll only see repositories you own."}
            </p>
            <button type="button" className="btn" onClick={connectGithub}>
              {gh.needs_reauth ? "Reconnect GitHub" : "Connect GitHub"}
            </button>
            <Link className="np-gate-back" to="/user/projects">
              Cancel
            </Link>
          </section>
        ) : (
          <form className="np-flow-form" onSubmit={(e) => void onCreate(e)}>
            <div className="np-provider">
              <div className="np-provider-left">
                {gh.avatar_url ? (
                  <img className="np-avatar" src={gh.avatar_url} alt="" width={32} height={32} />
                ) : (
                  <span className="np-avatar placeholder" aria-hidden="true">
                    {(gh.github_login || "?").slice(0, 1).toUpperCase()}
                  </span>
                )}
                <div>
                  <strong>GitHub</strong>
                  <span>
                    Connected as @{gh.github_login}
                    {repos.length ? ` · ${repos.length} owned repo${repos.length === 1 ? "" : "s"}` : ""}
                  </span>
                </div>
              </div>
              <button
                type="button"
                className="np-text-btn"
                disabled={disconnectBusy}
                aria-busy={disconnectBusy}
                onClick={() => void disconnectGithub()}
              >
                {disconnectBusy ? "Disconnecting…" : "Disconnect"}
              </button>
            </div>

            <section className="np-step" aria-labelledby="np-repo-heading">
              <div className="np-step-head">
                <h2 id="np-repo-heading">Choose a repository</h2>
                <p>Only repositories you own are listed.</p>
              </div>

              {selectedRepo ? (
                <div className="np-selected-repo">
                  <div className="np-selected-repo-body">
                    <span className="np-selected-check" aria-hidden="true">
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
                    </span>
                    <div>
                      <strong>{selectedRepo.full_name}</strong>
                      <span>
                        {selectedRepo.private ? "Private" : "Public"}
                        {selectedRepo.default_branch ? ` · ${selectedRepo.default_branch}` : ""}
                      </span>
                    </div>
                  </div>
                  <button type="button" className="np-text-btn" onClick={clearRepo}>
                    Change
                  </button>
                </div>
              ) : (
                <>
                  <input
                    className="np-input np-search"
                    type="search"
                    value={repoQuery}
                    onChange={(e) => setRepoQuery(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") e.preventDefault();
                    }}
                    placeholder="Search your repositories…"
                    autoComplete="off"
                    autoFocus
                    aria-label="Search repositories"
                  />
                  {!filteredRepos.length ? (
                    <div className="np-empty-block">
                      <p className="np-empty">
                        {repoQuery
                          ? "No repositories match that search."
                          : "No owned repositories found on this account."}
                      </p>
                      {!repoQuery ? (
                        <p className="np-empty-hint">
                          Create a repo on GitHub first, or reconnect if the wrong account is linked.
                        </p>
                      ) : null}
                    </div>
                  ) : (
                    <ul className="np-repos" aria-label="Repositories">
                      {filteredRepos.map((repo) => (
                        <li key={repo.id}>
                          <button type="button" className="np-repo" onClick={() => pickRepo(repo)}>
                            <span className="np-repo-mark" aria-hidden="true" />
                            <span className="np-repo-body">
                              <span className="np-repo-name">{repo.full_name}</span>
                              <span className="np-repo-meta">
                                {repo.private ? "Private" : "Public"}
                                {repo.default_branch ? ` · ${repo.default_branch}` : ""}
                              </span>
                            </span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              )}
            </section>

            {selectedRepo ? (
              <section className="np-step np-step-config" aria-labelledby="np-config-heading">
                <div className="np-step-head">
                  <h2 id="np-config-heading">Name your project</h2>
                  <p>You can change this later. Scans start from the project page.</p>
                </div>

                <label className="np-field">
                  <span>Project name</span>
                  <input
                    ref={nameInputRef}
                    className="np-input"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                    maxLength={120}
                    placeholder="my-app"
                  />
                </label>

                <button
                  type="button"
                  className="np-advanced-toggle"
                  aria-expanded={showAdvanced}
                  onClick={() => setShowAdvanced((v) => !v)}
                >
                  <span>
                    <strong>Optional settings</strong>
                    <span className="muted"> Description · auto-scan on push</span>
                  </span>
                  <svg className={`icon ${showAdvanced ? "is-open" : ""}`} viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                  </svg>
                </button>

                {showAdvanced ? (
                  <div className="np-advanced-body">
                    <label className="np-field">
                      <span>Description</span>
                      <textarea
                        className="np-input np-textarea"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        maxLength={2000}
                        rows={3}
                        placeholder="Optional notes for your team"
                      />
                    </label>
                    <label className="np-check">
                      <input
                        type="checkbox"
                        checked={autoScanOnPush}
                        onChange={(e) => setAutoScanOnPush(e.target.checked)}
                      />
                      <span>
                        <strong>Auto-scan on push</strong>
                        <span className="np-check-sub">
                          Start a scan when commits land on the watched branch
                        </span>
                      </span>
                    </label>
                    <label className={`np-field ${autoScanOnPush ? "" : "is-dimmed"}`}>
                      <span>Watched branch {refsLoading ? "(loading…)" : ""}</span>
                      <select
                        className="np-input"
                        value={autoScanBranch}
                        disabled={!autoScanOnPush || refsLoading}
                        onChange={(e) => setAutoScanBranch(e.target.value)}
                      >
                        {(branchOptions.length
                          ? branchOptions
                          : [{ name: defaultBranch, type: "branch" as const }]
                        ).map((b) => (
                          <option key={b.name} value={b.name}>
                            {b.name}
                            {b.name === defaultBranch ? " (default)" : ""}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                ) : null}
              </section>
            ) : (
              <p className="np-next-hint">Select a repository above to name your project and create it.</p>
            )}

            <div className="np-actions">
              <Link className="btn ghost" to="/user/projects">
                Cancel
              </Link>
              <button className="btn" type="submit" disabled={!canCreate}>
                {busy ? "Creating…" : "Create project"}
              </button>
            </div>
          </form>
        )}
      </div>
    </main>
  );
}
