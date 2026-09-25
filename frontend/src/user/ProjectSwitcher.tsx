import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import type { Project } from "../lib/workspace";

type Props = {
  /** Current project when on a detail page; omit on the all-projects list. */
  current?: Project | null;
  /** Optional preloaded list — avoids an extra fetch when the parent already has projects. */
  projects?: Project[];
  /** Show "All projects" row (useful on detail pages). */
  showAllLink?: boolean;
  /** Optional create action (e.g. open New project modal on the list page). */
  onNewProject?: () => void;
  /** Compact pill for header actions (name + chevron only). */
  compact?: boolean;
  /** Align dropdown to the right edge of the trigger. */
  menuAlign?: "left" | "right";
  className?: string;
};

/** Workspace project picker — search and jump between projects. */
export function ProjectSwitcher({
  current = null,
  projects: seeded,
  showAllLink = true,
  onNewProject,
  compact = false,
  menuAlign = "left",
  className,
}: Props) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<Project[]>(seeded || []);
  const [loading, setLoading] = useState(!seeded);
  const wrapRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (seeded) {
      setItems(seeded);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    api<{ items: Project[] }>("/workspace/projects")
      .then((data) => {
        if (!cancelled) setItems(data.items);
      })
      .catch(() => {
        if (!cancelled) setItems([]);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [seeded]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    window.addEventListener("keydown", onKey);
    const t = window.setTimeout(() => searchRef.current?.focus(), 0);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      window.removeEventListener("keydown", onKey);
      window.clearTimeout(t);
    };
  }, [open]);

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.github_repo_full_name || "").toLowerCase().includes(q) ||
        (p.description || "").toLowerCase().includes(q),
    );
  }, [items, query]);

  const label = current?.name || "All projects";

  function selectProject(id: string) {
    setOpen(false);
    navigate(`/user/projects/${id}`);
  }

  return (
    <div
      className={`project-switcher ${compact ? "compact" : ""} ${menuAlign === "right" ? "menu-right" : ""} ${className || ""} ${open ? "open" : ""}`}
      ref={wrapRef}
    >
      <button
        type="button"
        className="project-switcher-trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={`Switch project, current ${label}`}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="project-switcher-mark" aria-hidden="true">
          {(current?.name || "P").slice(0, 1).toUpperCase()}
        </span>
        <span className="project-switcher-copy">
          <span className="project-switcher-kicker">Project</span>
          <span className="project-switcher-label">{label}</span>
        </span>
        <svg className="project-switcher-chevron" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      </button>

      {open ? (
        <div className="project-switcher-menu" role="listbox" aria-label="Switch project">
          <label className="project-switcher-search">
            <svg className="project-switcher-search-icon" viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="11" cy="11" r="6.5" fill="none" stroke="currentColor" strokeWidth="1.75" />
              <path d="M16.5 16.5 20 20" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
            </svg>
            <input
              ref={searchRef}
              className="project-switcher-search-input"
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Find a project…"
              aria-label="Find a project"
            />
          </label>

          <div className="project-switcher-meta">
            <span>{loading ? "Loading" : `${filtered.length} project${filtered.length === 1 ? "" : "s"}`}</span>
          </div>

          <div className="project-switcher-list">
            {loading ? (
              <p className="project-switcher-empty">Loading projects…</p>
            ) : !filtered.length ? (
              <p className="project-switcher-empty">
                {query.trim() ? "No matches for that search." : "No projects yet."}
              </p>
            ) : (
              filtered.map((p) => {
                const active = current?.id === p.id;
                return (
                  <button
                    key={p.id}
                    type="button"
                    role="option"
                    aria-selected={active}
                    className={`project-switcher-item ${active ? "active" : ""}`}
                    onClick={() => selectProject(p.id)}
                  >
                    <span className="project-switcher-item-mark" aria-hidden="true">
                      {p.name.slice(0, 1).toUpperCase()}
                    </span>
                    <span className="project-switcher-item-text">
                      <b>{p.name}</b>
                      <small>{p.github_repo_full_name || "No GitHub repo linked"}</small>
                    </span>
                    {active ? (
                      <span className="project-switcher-badge" aria-hidden="true">
                        Current
                      </span>
                    ) : null}
                  </button>
                );
              })
            )}
          </div>

          <div className="project-switcher-foot">
            {showAllLink ? (
              <Link to="/user/projects" className="project-switcher-foot-link" onClick={() => setOpen(false)}>
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path
                    d="M4 6h16M4 12h16M4 18h10"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.75"
                    strokeLinecap="round"
                  />
                </svg>
                All projects
              </Link>
            ) : null}
            {onNewProject ? (
              <button
                type="button"
                className="project-switcher-foot-btn"
                onClick={() => {
                  setOpen(false);
                  onNewProject();
                }}
              >
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M12 5v14M5 12h14" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
                </svg>
                New project
              </button>
            ) : (
              <Link to="/user/projects" className="project-switcher-foot-link" onClick={() => setOpen(false)}>
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path
                    d="M5 7h14M5 12h14M5 17h8"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.75"
                    strokeLinecap="round"
                  />
                </svg>
                Manage projects
              </Link>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}
