import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { Link, useNavigate } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import { findingsCountLabel, relativeTime, shortCommit } from "../lib/scanDisplay";
import type { Project, Scan } from "../lib/workspace";
import { ScanHistoryList } from "./ScanHistoryList";

function SearchIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <path d="m20 20-3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
    </svg>
  );
}

function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="currentColor"
        d="M12 2C6.48 2 2 6.58 2 12.26c0 4.52 2.87 8.35 6.84 9.7.5.1.68-.22.68-.49v-1.7c-2.78.62-3.37-1.37-3.37-1.37-.45-1.18-1.11-1.5-1.11-1.5-.91-.64.07-.63.07-.63 1 .07 1.53 1.06 1.53 1.06.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.07 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.27 2.75 1.05A9.3 9.3 0 0 1 12 7.5c.85 0 1.71.12 2.51.34 1.91-1.32 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.8-4.57 5.06.36.32.68.94.68 1.9v2.81c0 .27.18.59.69.49A10.03 10.03 0 0 0 22 12.26C22 6.58 17.52 2 12 2z"
      />
    </svg>
  );
}

function GitCommitIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" width="12" height="12" fill="currentColor" aria-hidden="true">
      <path d="M10.5 8a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0ZM8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0Zm0 1.5a6.5 6.5 0 0 1 5.92 3.826 3.998 3.998 0 0 0-4.42 2.174h-3a3.998 3.998 0 0 0-4.42-2.174A6.5 6.5 0 0 1 8 1.5Z" />
    </svg>
  );
}

function RenameProjectModal({
  project,
  onClose,
  onRenamed,
}: {
  project: Project;
  onClose: () => void;
  onRenamed: (newName: string) => void;
}) {
  const [name, setName] = useState(project.name);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) {
      setError("Project name cannot be empty");
      return;
    }
    if (trimmed === project.name) {
      onClose();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api<{ project: Project }>(`/workspace/projects/${project.id}`, {
        method: "PATCH",
        body: JSON.stringify({ name: trimmed }),
      });
      onRenamed(trimmed);
      onClose();
    } catch (err: unknown) {
      setError((err as Error).message || "Failed to rename project");
      setBusy(false);
    }
  }

  return createPortal(
    <div className="modal-root" role="presentation">
      <button
        type="button"
        className="modal-backdrop"
        aria-label="Close dialog"
        onClick={onClose}
      />
      <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="rename-modal-title">
        <div className="modal-head">
          <div>
            <p className="modal-kicker">Manage</p>
            <h2 id="rename-modal-title">Rename project</h2>
          </div>
          <button
            type="button"
            className="modal-close"
            aria-label="Close"
            onClick={onClose}
          >
            <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={(e) => void handleSubmit(e)} className="modal-form">
          {error ? (
            <div className="notice error" role="alert" style={{ marginBottom: "1rem" }}>
              {error}
            </div>
          ) : null}
          <label htmlFor="rename-project-name">Project name</label>
          <input
            id="rename-project-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={busy}
            autoFocus
            maxLength={100}
            required
          />
          <div className="modal-actions" style={{ marginTop: "1.25rem" }}>
            <button
              type="button"
              className="btn ghost"
              onClick={onClose}
              disabled={busy}
            >
              Cancel
            </button>
            <button type="submit" className="btn" disabled={busy || !name.trim()}>
              {busy ? "Saving…" : "Save changes"}
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  );
}

function DeleteProjectModal({
  project,
  onClose,
  onDeleted,
}: {
  project: Project;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleDelete() {
    setBusy(true);
    setError(null);
    try {
      await api(`/workspace/projects/${project.id}`, {
        method: "DELETE",
      });
      onDeleted();
      onClose();
    } catch (err: unknown) {
      setError((err as Error).message || "Failed to delete project");
      setBusy(false);
    }
  }

  return createPortal(
    <div className="modal-root" role="presentation">
      <button
        type="button"
        className="modal-backdrop"
        aria-label="Close dialog"
        onClick={onClose}
      />
      <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="delete-modal-title">
        <div className="modal-head">
          <div>
            <p className="modal-kicker" style={{ color: "var(--danger)" }}>Danger Zone</p>
            <h2 id="delete-modal-title">Delete project</h2>
          </div>
          <button
            type="button"
            className="modal-close"
            aria-label="Close"
            onClick={onClose}
          >
            <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div style={{ padding: "0.5rem 0 1rem" }}>
          {error ? (
            <div className="notice error" role="alert" style={{ marginBottom: "1rem" }}>
              {error}
            </div>
          ) : null}
          <p className="modal-copy">
            Are you sure you want to delete <strong>{project.name}</strong>? This will permanently
            remove the project, its settings, and all associated scan history. This action cannot be undone.
          </p>
        </div>

        <div className="modal-actions">
          <button
            type="button"
            className="btn ghost"
            onClick={onClose}
            disabled={busy}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn danger"
            onClick={() => void handleDelete()}
            disabled={busy}
          >
            {busy ? "Deleting…" : "Delete project"}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}

function ProjectRowMenu({
  project,
  onRename,
  onDelete,
}: {
  project: Project;
  onRename: () => void;
  onDelete: () => void;
}) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [menuPos, setMenuPos] = useState<{ top: number; right: number } | null>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  function toggle(e: React.MouseEvent) {
    e.stopPropagation();
    e.preventDefault();
    if (!open) {
      if (triggerRef.current) {
        const rect = triggerRef.current.getBoundingClientRect();
        const spaceBelow = window.innerHeight - rect.bottom;
        const top = spaceBelow < 280 ? Math.max(10, rect.top - 270) : rect.bottom + 6;
        setMenuPos({
          top,
          right: Math.max(12, window.innerWidth - rect.right),
        });
      }
      setOpen(true);
    } else {
      setOpen(false);
    }
  }

  useEffect(() => {
    if (!open) return;
    function onDocClick(e: MouseEvent) {
      if (
        !triggerRef.current?.contains(e.target as Node) &&
        !panelRef.current?.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    function onScroll() {
      setOpen(false);
    }
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("scroll", onScroll);
    };
  }, [open]);

  function handleCopyId(e: React.MouseEvent) {
    e.stopPropagation();
    void navigator.clipboard?.writeText(project.id);
    setCopied(true);
    window.setTimeout(() => {
      setCopied(false);
      setOpen(false);
    }, 800);
  }

  return (
    <div className="project-menu-wrap">
      <button
        ref={triggerRef}
        type="button"
        className={`project-menu-trigger ${open ? "active" : ""}`}
        aria-label={`Options for ${project.name}`}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={toggle}
      >
        <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true">
          <circle cx="12" cy="5" r="1.6" />
          <circle cx="12" cy="12" r="1.6" />
          <circle cx="12" cy="19" r="1.6" />
        </svg>
      </button>

      {open && menuPos
        ? createPortal(
            <div
              ref={panelRef}
              className="project-menu-panel"
              style={{
                position: "fixed",
                top: `${menuPos.top}px`,
                right: `${menuPos.right}px`,
                zIndex: 9999,
              }}
              role="menu"
              aria-label={`Actions for ${project.name}`}
              onClick={(e) => e.stopPropagation()}
            >
              <button
                type="button"
                className="project-menu-item"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  navigate(`/user/projects/${project.id}`);
                }}
              >
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                  <polyline points="15 3 21 3 21 9" />
                  <line x1="10" y1="14" x2="21" y2="3" />
                </svg>
                <span>Open project</span>
              </button>

              <button
                type="button"
                className="project-menu-item"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  onRename();
                }}
              >
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M12 20h9" />
                  <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
                </svg>
                <span>Rename project</span>
              </button>

              <button
                type="button"
                className="project-menu-item"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  navigate(`/user/projects/${project.id}#advanced`);
                }}
              >
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="3" />
                  <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                </svg>
                <span>Project settings</span>
              </button>

              <button
                type="button"
                className="project-menu-item"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  navigate(`/user/projects/${project.id}`);
                }}
              >
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <polygon points="5 3 19 12 5 21 5 3" />
                </svg>
                <span>Start scan</span>
              </button>

              {project.github_repo_full_name ? (
                <button
                  type="button"
                  className="project-menu-item"
                  role="menuitem"
                  onClick={() => {
                    setOpen(false);
                    window.open(
                      `https://github.com/${project.github_repo_full_name}`,
                      "_blank",
                      "noopener,noreferrer",
                    );
                  }}
                >
                  <GitHubIcon className="project-menu-icon" />
                  <span>View on GitHub</span>
                </button>
              ) : null}

              <button
                type="button"
                className="project-menu-item"
                role="menuitem"
                onClick={handleCopyId}
              >
                {copied ? (
                  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--ok)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                )}
                <span>{copied ? "Copied ID!" : "Copy project ID"}</span>
              </button>

              <div className="project-menu-divider" />

              <button
                type="button"
                className="project-menu-item danger"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  onDelete();
                }}
              >
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <polyline points="3 6 5 6 21 6" />
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                </svg>
                <span>Delete project</span>
              </button>
            </div>,
            document.body,
          )
        : null}
    </div>
  );
}

/** Flat Render-style projects index — same language as New project. */
export function UserProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [renamingProject, setRenamingProject] = useState<Project | null>(null);
  const [deletingProject, setDeletingProject] = useState<Project | null>(null);

  async function load() {
    const [proj, scans] = await Promise.all([
      api<{ items: Project[] }>("/workspace/projects"),
      api<{ items: Scan[] }>("/workspace/scans?limit=40"),
    ]);
    setProjects(proj.items);
    setRecentScans(scans.items);
  }

  useEffect(() => {
    load()
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const active = recentScans.some((s) => s.status === "queued" || s.status === "running");
    if (!active) return;
    const id = window.setInterval(() => {
      load().catch(() => undefined);
    }, 4000);
    return () => window.clearInterval(id);
  }, [recentScans]);

  const latestByProject = useMemo(() => {
    const map = new Map<string, Scan>();
    for (const scan of recentScans) {
      if (!map.has(scan.project_id)) map.set(scan.project_id, scan);
    }
    return map;
  }, [recentScans]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return projects;
    return projects.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.github_repo_full_name || "").toLowerCase().includes(q) ||
        (p.description || "").toLowerCase().includes(q),
    );
  }, [projects, query]);

  return (
    <main className="admin-main projects-page">
      <div className="projects-wrap">
        <header className="new-project-header projects-header">
          <div className="projects-header-row">
            <div>
              <nav className="new-project-crumb" aria-label="Breadcrumb">
                <span>Workspace</span>
                <span aria-hidden="true">/</span>
                <span>Projects</span>
              </nav>
              <h1>Projects</h1>
              <p>Link a GitHub repo, run scans, and track findings as commits land.</p>
            </div>
            <Link className="btn" to="/user/projects/new">
              New project
            </Link>
          </div>
        </header>

        {error ? (
          <div className="notice error" role="alert">
            {error}
          </div>
        ) : null}

        {loading ? (
          <LoadingMark label="Loading projects…" />
        ) : !projects.length ? (
          <section className="np-block projects-empty">
            <h2 className="np-label">Get started</h2>
            <p className="np-empty">
              No projects yet. Connect GitHub and create one from a repository you own.
            </p>
            <Link className="btn" to="/user/projects/new">
              New project
            </Link>
          </section>
        ) : (
          <>
            <div className="projects-filter-bar">
              <div className="projects-section-title-wrap">
                <h2 className="projects-section-title">
                  Projects
                  <span className="projects-count-pill">{filtered.length}</span>
                </h2>
              </div>

              <div className="projects-search-wrap">
                <SearchIcon className="projects-search-icon" />
                <input
                  className="projects-search-input"
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search projects or repositories…"
                  autoComplete="off"
                  aria-label="Filter projects"
                />
                {query ? (
                  <button
                    type="button"
                    className="projects-search-clear"
                    onClick={() => setQuery("")}
                    aria-label="Clear search"
                  >
                    ×
                  </button>
                ) : null}
              </div>
            </div>

            <section className="projects-table-section" aria-label="Projects list">
              <div className="projects-grid projects-head">
                <span className="projects-h-main">Project</span>
                <span className="projects-h-col">Latest Commit</span>
                <span className="projects-h-col">Security Status</span>
                <span className="projects-h-col">Activity</span>
                <span className="projects-h-action">
                  <span className="sr-only">Actions</span>
                </span>
              </div>

              {!filtered.length ? (
                <div className="empty-state projects-empty-filter">
                  <strong>No projects found</strong>
                  <p>{query ? `No projects match "${query}".` : "No projects registered yet."}</p>
                </div>
              ) : (
                <ul className="projects-list">
                  {filtered.map((project) => {
                    const latest = latestByProject.get(project.id);
                    const sha = latest ? shortCommit(latest.commit_short, latest.commit_sha) : null;
                    const scanning =
                      latest && (latest.status === "queued" || latest.status === "running");
                    const findingsCount = latest?.summary?.findings_count;
                    const initial = (project.name || "P").trim().slice(0, 1).toUpperCase();
                    const href = `/user/projects/${project.id}`;
                    const when = latest ? relativeTime(latest.finished_at || latest.created_at) : null;

                    return (
                      <li key={project.id} className="projects-row-item">
                        <div className="projects-grid projects-row">
                          <Link
                            className="projects-row-stretch"
                            to={href}
                            aria-label={`Open project ${project.name}`}
                          />

                          <div className="projects-col-main">
                            <div
                              className={`project-avatar ${scanning ? "is-scanning" : ""}`}
                              aria-hidden="true"
                            >
                              <span className="project-avatar-initial">{initial}</span>
                              {scanning ? <span className="project-avatar-scan-dot" /> : null}
                            </div>

                            <div className="project-info">
                              <div className="project-info-top">
                                <span className="project-name">{project.name}</span>
                                {project.auto_scan_on_push ? (
                                  <span className="project-auto-chip" title="Auto-scan on push enabled">
                                    <span className="project-auto-dot" />
                                    Auto · {project.auto_scan_branch || project.github_default_branch || "main"}
                                  </span>
                                ) : null}
                              </div>

                              <div className="project-info-sub">
                                {project.github_repo_full_name ? (
                                  <span className="project-repo-tag">
                                    <GitHubIcon className="project-github-icon" />
                                    <span>{project.github_repo_full_name}</span>
                                  </span>
                                ) : (
                                  <span className="project-repo-tag muted">No repository linked</span>
                                )}
                              </div>
                            </div>
                          </div>

                          <div className="projects-col-commit">
                            {sha ? (
                              <code className="projects-sha-badge" title={`Commit ${sha}`}>
                                <GitCommitIcon />
                                <span>{sha}</span>
                              </code>
                            ) : (
                              <span className="projects-empty-cell">—</span>
                            )}
                          </div>

                          <div className="projects-col-status">
                            {latest ? (
                              <span
                                className={`badge ${
                                  scanning
                                    ? "pending"
                                    : findingsCount === 0
                                    ? "ok"
                                    : "medium"
                                }`}
                              >
                                {scanning ? (
                                  <>
                                    <span className="badge-spinner" aria-hidden="true" />
                                    Scanning…
                                  </>
                                ) : findingsCount === 0 ? (
                                  <>
                                    <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                      <polyline points="20 6 9 17 4 12" />
                                    </svg>
                                    Clean · 0 findings
                                  </>
                                ) : (
                                  `${findingsCountLabel(latest)} findings`
                                )}
                              </span>
                            ) : (
                              <span className="badge muted">No scans</span>
                            )}
                          </div>

                          <div className="projects-col-time">
                            {when ? (
                              <span className="projects-time-text">{when}</span>
                            ) : (
                              <span className="projects-empty-cell">—</span>
                            )}
                          </div>

                          <div className="projects-col-action">
                            <ProjectRowMenu
                              project={project}
                              onRename={() => setRenamingProject(project)}
                              onDelete={() => setDeletingProject(project)}
                            />
                          </div>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>

            {recentScans.length ? (
              <section className="projects-recent-section">
                <ScanHistoryList
                  scans={recentScans.slice(0, 12)}
                  title="Recent scans"
                  showProjectName
                  emptyTitle="No recent scans"
                />
              </section>
            ) : null}

            {renamingProject ? (
              <RenameProjectModal
                project={renamingProject}
                onClose={() => setRenamingProject(null)}
                onRenamed={(newName) => {
                  setProjects((prev) =>
                    prev.map((p) => (p.id === renamingProject.id ? { ...p, name: newName } : p)),
                  );
                }}
              />
            ) : null}

            {deletingProject ? (
              <DeleteProjectModal
                project={deletingProject}
                onClose={() => setDeletingProject(null)}
                onDeleted={() => {
                  setProjects((prev) => prev.filter((p) => p.id !== deletingProject.id));
                  setRecentScans((prev) => prev.filter((s) => s.project_id !== deletingProject.id));
                }}
              />
            ) : null}
          </>
        )}
      </div>
    </main>
  );
}
