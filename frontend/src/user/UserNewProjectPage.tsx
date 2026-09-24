import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import { relativeTime } from "../lib/scanDisplay";
import type { GitHubRepo, GitHubStatus, GitRef, Project } from "../lib/workspace";

function GitHubMark({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="currentColor"
        d="M12 2C6.48 2 2 6.58 2 12.26c0 4.52 2.87 8.35 6.84 9.7.5.1.68-.22.68-.49v-1.7c-2.78.62-3.37-1.37-3.37-1.37-.45-1.18-1.11-1.5-1.11-1.5-.91-.64.07-.63.07-.63 1 .07 1.53 1.06 1.53 1.06.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.07 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.27 2.75 1.05A9.3 9.3 0 0 1 12 7.5c.85 0 1.71.12 2.51.34 1.91-1.32 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.8-4.57 5.06.36.32.68.94.68 1.9v2.81c0 .27.18.59.69.49A10.03 10.03 0 0 0 22 12.26C22 6.58 17.52 2 12 2z"
      />
    </svg>
  );
}

function repoOwnerName(fullName: string): { owner: string; name: string } {
  const i = fullName.indexOf("/");
  if (i <= 0) return { owner: "", name: fullName };
  return { owner: fullName.slice(0, i), name: fullName.slice(i + 1) };
}

/**
 * Create-from-GitHub flow:
 * 1) Connect GitHub if needed
 * 2) Search + pick an owned repo (list collapses once selected)
 * 3) Name + settings → Create
 */
export function UserNewProjectPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const nameInputRef = useRef<HTMLInputElement>(null);
  const credsRef = useRef<HTMLDivElement>(null);
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
  const [credsOpen, setCredsOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [disconnectBusy, setDisconnectBusy] = useState(false);

  async function loadGithub() {
    const status = await api<GitHubStatus>("/workspace/github/status");
    setGh(status);
    if (status.connected) {
      // Always try listing repos — server clears a stale needs_reauth on success.
      try {
        const data = await api<{ items: GitHubRepo[] }>("/workspace/github/repos");
        setRepos(data.items);
        if (status.needs_reauth) {
          const refreshed = await api<GitHubStatus>("/workspace/github/status");
          setGh(refreshed);
        }
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

  useEffect(() => {
    if (!credsOpen) return;
    function onDoc(e: MouseEvent) {
      if (!credsRef.current?.contains(e.target as Node)) setCredsOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setCredsOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [credsOpen]);

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
    setCredsOpen(false);
    try {
      await api("/workspace/github/disconnect", { method: "POST" });
      setMessage("GitHub disconnected.");
      setGithubRepoId("");
      setName("");
      setDescription("");
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
    setCredsOpen(false);
  }

  function clearRepo() {
    setGithubRepoId("");
    setName("");
    setDescription("");
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
  const selectedParts = selectedRepo ? repoOwnerName(selectedRepo.full_name) : null;

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
          <section className="np-gate np-gate-card">
            <div className="np-gate-copy">
              <span className="np-gate-icon" aria-hidden="true">
                <GitHubMark />
              </span>
              <div>
                <h2>GitHub is not configured</h2>
                <p>Ask an administrator to set GitHub OAuth on this server before creating projects.</p>
              </div>
            </div>
            <Link className="btn secondary" to="/user/projects">
              Back to projects
            </Link>
          </section>
        ) : !githubReady ? (
          <section className="np-gate np-gate-card">
            <div className="np-gate-copy">
              <span className="np-gate-icon" aria-hidden="true">
                <GitHubMark />
              </span>
              <div>
                <h2>{gh.needs_reauth ? "Reconnect GitHub" : "Connect GitHub to continue"}</h2>
                <p>
                  {gh.needs_reauth
                    ? "Your GitHub authorization expired or is missing repo access. Reconnect, then choose a repository."
                    : "One-time connect. You’ll only see repositories you own."}
                </p>
              </div>
            </div>
            <button type="button" className="btn" onClick={connectGithub}>
              {gh.needs_reauth ? "Reconnect GitHub" : "Connect GitHub"}
            </button>
          </section>
        ) : (
          <form className="np-flow-form np-flow-form-render" onSubmit={(e) => void onCreate(e)}>
            {!selectedRepo ? (
              <section className="np-step" aria-labelledby="np-repo-heading">
                <div className="np-step-head">
                  <h2 id="np-repo-heading">Choose a repository</h2>
                  <p>Search owned repos, then select one to import.</p>
                </div>
                <div className="np-picker">
                  <div className="np-picker-toolbar">
                    <label className="np-picker-search">
                      <svg viewBox="0 0 24 24" aria-hidden="true">
                        <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="1.75" />
                        <path d="m20 20-3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
                      </svg>
                      <input
                        type="search"
                        value={repoQuery}
                        onChange={(e) => setRepoQuery(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") e.preventDefault();
                        }}
                        placeholder="Search"
                        autoComplete="off"
                        autoFocus
                        aria-label="Search repositories"
                      />
                    </label>

                    <div className={`np-picker-creds ${credsOpen ? "open" : ""}`} ref={credsRef}>
                      <button
                        type="button"
                        className="np-picker-creds-btn"
                        aria-haspopup="menu"
                        aria-expanded={credsOpen}
                        onClick={() => setCredsOpen((v) => !v)}
                      >
                        <span className="np-picker-creds-icons" aria-hidden="true">
                          <GitHubMark />
                        </span>
                        Credentials (1)
                        <svg className="np-picker-chevron" viewBox="0 0 24 24" aria-hidden="true">
                          <path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                        </svg>
                      </button>
                      {credsOpen ? (
                        <div className="np-picker-creds-menu" role="menu">
                          <div className="np-picker-creds-head" role="presentation">
                            <GitHubMark />
                            <div>
                              <strong>GitHub</strong>
                              <span>@{gh.github_login}</span>
                            </div>
                          </div>
                          <button
                            type="button"
                            className="np-picker-creds-item danger"
                            role="menuitem"
                            disabled={disconnectBusy}
                            onClick={() => void disconnectGithub()}
                          >
                            {disconnectBusy ? "Disconnecting…" : "Disconnect"}
                          </button>
                        </div>
                      ) : null}
                    </div>
                  </div>

                  {!filteredRepos.length ? (
                    <div className="np-picker-empty">
                      <p>
                        {repoQuery
                          ? "No repositories match that search."
                          : "No owned repositories found on this account."}
                      </p>
                    </div>
                  ) : (
                    <ul className="np-picker-list" aria-label="Repositories">
                      {filteredRepos.map((repo) => {
                        const { owner, name: repoName } = repoOwnerName(repo.full_name);
                        const when = relativeTime(repo.updated_at);
                        return (
                          <li key={repo.id}>
                            <button type="button" className="np-picker-row" onClick={() => pickRepo(repo)}>
                              <span className="np-picker-gh" aria-hidden="true">
                                <GitHubMark />
                              </span>
                              <span className="np-picker-label">
                                <span className="np-picker-owner">{owner}</span>
                                <span className="np-picker-slash"> / </span>
                                <span className="np-picker-repo">{repoName}</span>
                              </span>
                              {when ? <span className="np-picker-time">{when}</span> : null}
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
                <p className="np-next-hint">Select a repository above to configure and create your project.</p>
              </section>
            ) : (
              <>
                <div className="np-render-fields" aria-label="New project settings">
                  <div className="rr-row np-config-row">
                    <div className="rr-meta">
                      <span className="rr-title">Repository</span>
                      <p>GitHub repo to import</p>
                    </div>
                    <div className="rr-controls">
                      <div className="np-selected-repo">
                        <div className="np-selected-repo-body">
                          <span className="np-picker-gh" aria-hidden="true">
                            <GitHubMark />
                          </span>
                          <div>
                            <strong>
                              <span className="np-picker-owner">{selectedParts!.owner}</span>
                              <span className="np-picker-slash"> / </span>
                              <span className="np-picker-repo">{selectedParts!.name}</span>
                            </strong>
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
                    </div>
                  </div>

                  <div className="rr-row np-config-row">
                    <div className="rr-meta">
                      <label className="rr-title" htmlFor="np-project-name">
                        Project name
                      </label>
                      <p>Shown across your workspace</p>
                    </div>
                    <div className="rr-controls">
                      <input
                        id="np-project-name"
                        ref={nameInputRef}
                        className="np-input"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        required
                        maxLength={120}
                        placeholder="my-app"
                      />
                    </div>
                  </div>

                  <div className="rr-row np-config-row">
                    <div className="rr-meta">
                      <label className="rr-title" htmlFor="np-project-desc">
                        Description
                      </label>
                      <p>Optional notes for your team</p>
                    </div>
                    <div className="rr-controls">
                      <textarea
                        id="np-project-desc"
                        className="np-input np-textarea"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        maxLength={2000}
                        rows={3}
                        placeholder="Optional notes for your team"
                      />
                    </div>
                  </div>

                  <div className="rr-row np-config-row">
                    <div className="rr-meta">
                      <span className="rr-title">Auto-scan on push</span>
                      <p>Start a scan when commits land on the watched branch</p>
                    </div>
                    <div className="rr-controls">
                      <label className="np-check np-check-inline">
                        <input
                          type="checkbox"
                          checked={autoScanOnPush}
                          onChange={(e) => setAutoScanOnPush(e.target.checked)}
                        />
                        <span>
                          <strong>{autoScanOnPush ? "Enabled" : "Disabled"}</strong>
                        </span>
                      </label>
                    </div>
                  </div>

                  <div className={`rr-row np-config-row ${autoScanOnPush ? "" : "is-dimmed"}`}>
                    <div className="rr-meta">
                      <label className="rr-title" htmlFor="np-watched-branch">
                        Watched branch
                      </label>
                      <p>{refsLoading ? "Loading branches…" : "Branch that triggers auto-scan"}</p>
                    </div>
                    <div className="rr-controls">
                      <select
                        id="np-watched-branch"
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
                    </div>
                  </div>
                </div>

                <div className="np-actions">
                  <p className="np-actions-hint">
                    Create <strong>{name.trim() || selectedRepo.name}</strong> from{" "}
                    <code>{selectedRepo.full_name}</code>
                  </p>
                  <button className="btn" type="submit" disabled={!canCreate}>
                    {busy ? "Creating…" : "Create project"}
                  </button>
                </div>
              </>
            )}
          </form>
        )}
      </div>
    </main>
  );
}
