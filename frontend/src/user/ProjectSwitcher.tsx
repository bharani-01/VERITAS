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

/** Supabase-style project picker: search + jump between workspace projects. */
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
        <span className="project-switcher-label">{label}</span>
        <svg className="project-switcher-chevron" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      </button>

      {open ? (
        <div className="project-switcher-menu" role="listbox" aria-label="Switch project">
          <div className="project-switcher-search">
            <input
              ref={searchRef}
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Find a project…"
              aria-label="Find a project"
            />
          </div>
          <div className="project-switcher-list">
            {loading ? (
              <p className="project-switcher-empty">Loading…</p>
            ) : !filtered.length ? (
              <p className="project-switcher-empty">No matching projects</p>
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
                      <small>{p.github_repo_full_name || "No GitHub repo"}</small>
                    </span>
                    {active ? (
                      <svg className="project-switcher-check" viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M5 12l5 5L20 7" fill="none" stroke="currentColor" strokeWidth="2" />
                      </svg>
                    ) : null}
                  </button>
                );
              })
            )}
          </div>
          <div className="project-switcher-foot">
            {showAllLink ? (
              <Link to="/user/projects" className="project-switcher-foot-link" onClick={() => setOpen(false)}>
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
                New project
              </button>
            ) : (
              <Link to="/user/projects" className="project-switcher-foot-link" onClick={() => setOpen(false)}>
                Manage projects
              </Link>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}
