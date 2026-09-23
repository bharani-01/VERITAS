import { useEffect, useState, type FormEvent, type MouseEvent, type KeyboardEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { createPortal } from "react-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { GitHubRepo, GitHubStatus, Project, Scan } from "../lib/workspace";
import { ProjectSwitcher } from "./ProjectSwitcher";

export function UserProjectsPage() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [scanCounts, setScanCounts] = useState<Record<string, number>>({});
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [githubRepoId, setGithubRepoId] = useState("");
  const [autoScanOnPush, setAutoScanOnPush] = useState(false);
  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [gh, setGh] = useState<GitHubStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [loading, setLoading] = useState(true);

  async function load() {
    const [proj, status, scans] = await Promise.all([
      api<{ items: Project[] }>("/workspace/projects"),
      api<GitHubStatus>("/workspace/github/status"),
      api<{ items: Scan[] }>("/workspace/scans?limit=100"),
    ]);
    setProjects(proj.items);
    setGh(status);
    const counts: Record<string, number> = {};
    for (const scan of scans.items) {
      counts[scan.project_id] = (counts[scan.project_id] || 0) + 1;
    }
    setScanCounts(counts);
    if (status.connected) {
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
    load()
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!showCreate) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") setShowCreate(false);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", onKey);
    };
  }, [showCreate]);

  function closeCreate() {
    setShowCreate(false);
    setFormError(null);
    setAutoScanOnPush(false);
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      const body: {
        name: string;
        description: string;
        github_repo_id?: number;
        auto_scan_on_push?: boolean;
      } = {
        name: name.trim(),
        description: description.trim(),
        auto_scan_on_push: autoScanOnPush && !!githubRepoId,
      };
      if (githubRepoId) body.github_repo_id = Number(githubRepoId);
      const created = await api<{ project: Project }>("/workspace/projects", {
        method: "POST",
        body: JSON.stringify(body),
      });
      setName("");
      setDescription("");
      setGithubRepoId("");
      setAutoScanOnPush(false);
      closeCreate();
      navigate(`/user/projects/${created.project.id}`);
    } catch (err) {
      setFormError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string, e: MouseEvent) {
    e.stopPropagation();
    e.preventDefault();
    if (!confirm("Delete this project and its scans?")) return;
    try {
      await api(`/workspace/projects/${id}`, { method: "DELETE" });
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const modal =
    showCreate &&
    createPortal(
      <div className="modal-root" role="presentation">
        <button type="button" className="modal-backdrop" aria-label="Close dialog" onClick={closeCreate} />
        <div className="modal-panel modal-panel-dark" role="dialog" aria-modal="true" aria-labelledby="new-project-title">
          <div className="modal-head">
            <div>
              <p className="modal-kicker">Workspace</p>
              <h2 id="new-project-title">New project</h2>
            </div>
            <button type="button" className="modal-close" aria-label="Close" onClick={closeCreate}>
              <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M18 6 6 18M6 6l12 12" fill="none" stroke="currentColor" strokeWidth="2" />
              </svg>
            </button>
          </div>
          <form className="modal-form" onSubmit={onCreate}>
            {formError ? (
              <div className="notice error" role="alert">
                {formError}
              </div>
            ) : null}
            <label>
              Name
              <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={120} autoFocus />
            </label>
            <label>
              Description
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                maxLength={2000}
                placeholder="Optional"
              />
            </label>
            <label>
              GitHub repo
              <select value={githubRepoId} onChange={(e) => setGithubRepoId(e.target.value)} disabled={!gh?.connected}>
                <option value="">None</option>
                {repos.map((repo) => (
                  <option key={repo.id} value={String(repo.id)}>
                    {repo.full_name}
                    {repo.private ? " (private)" : ""}
                  </option>
                ))}
              </select>
            </label>
            <label className="check" style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                type="checkbox"
                checked={autoScanOnPush}
                disabled={!githubRepoId}
                onChange={(e) => setAutoScanOnPush(e.target.checked)}
              />
              Auto-scan on push (default branch)
            </label>
            {!gh?.connected ? (
              <p className="modal-hint">
                <Link to="/user/integrations" onClick={closeCreate}>
                  Connect GitHub
                </Link>{" "}
                to link a repo you own.
              </p>
            ) : (
              <p className="modal-hint">Only repositories owned by your connected GitHub account can be linked.</p>
            )}
            <div className="modal-actions">
              <button type="button" className="btn modal-btn-ghost" onClick={closeCreate}>
                Cancel
              </button>
              <button className="btn modal-btn-primary" type="submit" disabled={busy}>
                {busy ? "Creating…" : "Create & open"}
              </button>
            </div>
          </form>
        </div>
      </div>,
      document.body,
    );

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Workspace</div>
          <h1>Projects</h1>
          <p>Open a project to run and review its scans.</p>
        </div>
        <div className="project-header-actions">
          {projects.length ? (
            <ProjectSwitcher
              projects={projects}
              showAllLink={false}
              onNewProject={() => setShowCreate(true)}
              compact
              menuAlign="right"
            />
          ) : null}
          <button type="button" className="btn" onClick={() => setShowCreate(true)}>
            New project
          </button>
        </div>
      </header>

      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}

      {modal}

      {loading ? (
        <LoadingMark label="Loading projects…" />
      ) : !projects.length ? (
        <div className="empty-state">
          <strong>No projects yet</strong>
          Create a project, then open it to start scans.
        </div>
      ) : (
        <div className="project-list" role="list">
          {projects.map((project) => {
            const count = scanCounts[project.id] || 0;
            return (
              <button
                type="button"
                className="project-row"
                key={project.id}
                role="listitem"
                onClick={() => navigate(`/user/projects/${project.id}`)}
              >
                <span className="project-row-main">
                  <span className="project-row-title">{project.name}</span>
                  <span className="project-row-meta">
                    {project.github_repo_full_name ? (
                      <span className="project-repo">{project.github_repo_full_name}</span>
                    ) : (
                      <span>Manual</span>
                    )}
                    <span>·</span>
                    <span>
                      {count} scan{count === 1 ? "" : "s"}
                    </span>
                    {project.auto_scan_on_push ? (
                      <>
                        <span>·</span>
                        <span>Auto-scan</span>
                      </>
                    ) : null}
                    <span>·</span>
                    <span>Updated {new Date(project.updated_at).toLocaleDateString()}</span>
                  </span>
                </span>
                <span className="project-row-actions">
                  <span className="project-row-cta">Open scans</span>
                  <span
                    className="project-row-delete"
                    role="button"
                    tabIndex={0}
                    onClick={(e) => onDelete(project.id, e)}
                    onKeyDown={(e: KeyboardEvent) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onDelete(project.id, e as unknown as MouseEvent);
                      }
                    }}
                  >
                    Delete
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      )}
    </main>
  );
}
