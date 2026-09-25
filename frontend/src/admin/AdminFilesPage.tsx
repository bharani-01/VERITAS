import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import { formatLocalDateTime } from "../lib/time";

type Mount = {
  mountpoint: string;
  source: string;
  fstype: string;
  size?: string | null;
  used?: string | null;
  avail?: string | null;
  percent?: number | null;
  size_bytes?: number | null;
  used_bytes?: number | null;
  avail_bytes?: number | null;
};

type FsEntry = {
  name: string;
  type: "file" | "dir" | string;
  size: number | null;
  mtime: string | null;
  mode: string | null;
  is_symlink?: boolean;
  download_blocked?: boolean;
};

type ListResponse = {
  root: string;
  path: string;
  absolute: string;
  breadcrumbs: { name: string; path: string }[];
  entries: FsEntry[];
  total: number;
  limit: number;
  offset: number;
};

function formatBytes(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  let size = n;
  for (const unit of ["B", "KB", "MB", "GB", "TB"]) {
    if (size < 1024 || unit === "TB") {
      return unit === "B" ? `${size} ${unit}` : `${size.toFixed(1)} ${unit}`;
    }
    size /= 1024;
  }
  return `${n} B`;
}

function joinRel(base: string, name: string): string {
  const clean = (base || "").replace(/^\/+|\/+$/g, "");
  return clean ? `${clean}/${name}` : name;
}

/** Admin host disk browser — list mounts, browse folders, download files. */
export function AdminFilesPage() {
  const [mounts, setMounts] = useState<Mount[]>([]);
  const [root, setRoot] = useState<string>("");
  const [path, setPath] = useState("");
  const [listing, setListing] = useState<ListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadingMounts, setLoadingMounts] = useState(true);
  const [loadingList, setLoadingList] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);

  const loadMounts = useCallback(async () => {
    setLoadingMounts(true);
    setError(null);
    try {
      const data = await api<{ mounts: Mount[] }>("/admin/fs/mounts");
      const list = data.mounts || [];
      setMounts(list);
      setRoot((prev) => {
        if (prev && list.some((m) => m.mountpoint === prev)) return prev;
        const prefer = list.find((m) => m.mountpoint === "/data") || list[0];
        return prefer?.mountpoint || "";
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load mounts.");
    } finally {
      setLoadingMounts(false);
    }
  }, []);

  const loadList = useCallback(
    async (nextRoot: string, nextPath: string) => {
      if (!nextRoot) return;
      setLoadingList(true);
      setError(null);
      try {
        const params = new URLSearchParams({
          root: nextRoot,
          path: nextPath || "",
          limit: "500",
          offset: "0",
        });
        const data = await api<ListResponse>(`/admin/fs/list?${params.toString()}`);
        setListing(data);
        setPath(data.path || "");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unable to list directory.");
        setListing(null);
      } finally {
        setLoadingList(false);
      }
    },
    [],
  );

  useEffect(() => {
    void loadMounts();
  }, [loadMounts]);

  useEffect(() => {
    if (!root) return;
    setPath("");
    void loadList(root, "");
  }, [root, loadList]);

  async function downloadFile(relPath: string, name: string) {
    setDownloading(name);
    setError(null);
    try {
      const params = new URLSearchParams({ root, path: relPath });
      const response = await fetch(`/admin/fs/download?${params.toString()}`, {
        credentials: "same-origin",
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        const detail = (data as { detail?: string }).detail;
        throw new Error(detail || "Download failed.");
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed.");
    } finally {
      setDownloading(null);
    }
  }

  function selectMount(mp: string) {
    setRoot(mp);
  }

  function openDir(name: string) {
    const next = joinRel(path, name);
    void loadList(root, next);
  }

  function goCrumb(crumbPath: string) {
    void loadList(root, crumbPath);
  }

  function goUp() {
    if (!path) return;
    const parts = path.split("/").filter(Boolean);
    parts.pop();
    void loadList(root, parts.join("/"));
  }

  if (loadingMounts && !mounts.length) {
    return (
      <main className="admin-main">
        <LoadingMark label="Loading disks…" />
      </main>
    );
  }

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Host</div>
          <h1>Files</h1>
          <p>Browse mounted disks and download files. Secret paths (env keys, private keys, shadow) are blocked.</p>
        </div>
        <button type="button" className="btn ghost" onClick={() => void loadMounts()}>
          Refresh disks
        </button>
      </header>

      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}

      <section className="fs-mounts" aria-label="Mounted disks">
        {mounts.map((m) => {
          const active = m.mountpoint === root;
          const pct = m.percent ?? 0;
          return (
            <button
              type="button"
              key={m.mountpoint}
              className={`fs-mount ${active ? "is-active" : ""}`}
              onClick={() => selectMount(m.mountpoint)}
              aria-pressed={active}
            >
              <span className="fs-mount-path">{m.mountpoint}</span>
              <span className="fs-mount-meta">
                {m.fstype || "disk"} · {m.source || "—"}
              </span>
              <span className="fs-mount-usage">
                {m.used || "—"} used of {m.size || "—"} ({pct}%) · {m.avail || "—"} free
              </span>
              <span className="fs-mount-bar" aria-hidden="true">
                <span style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} />
              </span>
            </button>
          );
        })}
        {!mounts.length ? <p className="muted">No browsable mounts found on this host.</p> : null}
      </section>

      <section className="fs-browser dash-panel">
        <div className="dash-panel-head fs-browser-head">
          <div className="fs-crumbs" aria-label="Path">
            <button type="button" className="fs-crumb" onClick={() => void loadList(root, "")} disabled={!root}>
              {root || "—"}
            </button>
            {(listing?.breadcrumbs || []).map((c) => (
              <span key={c.path} className="fs-crumb-wrap">
                <span className="fs-crumb-sep">/</span>
                <button type="button" className="fs-crumb" onClick={() => goCrumb(c.path)}>
                  {c.name}
                </button>
              </span>
            ))}
          </div>
          <div className="fs-browser-actions">
            <button type="button" className="btn ghost" disabled={!path || loadingList} onClick={goUp}>
              Up
            </button>
            <button
              type="button"
              className="btn ghost"
              disabled={!root || loadingList}
              onClick={() => void loadList(root, path)}
            >
              Refresh
            </button>
          </div>
        </div>

        <div className="dash-panel-body">
          {loadingList ? (
            <LoadingMark label="Listing…" />
          ) : !listing ? (
            <p className="muted">Select a disk to browse.</p>
          ) : listing.entries.length === 0 ? (
            <p className="muted">This folder is empty.</p>
          ) : (
            <div className="table-wrap fs-table-wrap">
              <table className="audit-table fs-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Modified</th>
                    <th>Mode</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {listing.entries.map((entry) => {
                    const rel = joinRel(path, entry.name);
                    const when = entry.mtime ? formatLocalDateTime(entry.mtime) : "—";
                    return (
                      <tr key={`${entry.type}:${entry.name}`}>
                        <td>
                          {entry.type === "dir" ? (
                            <button type="button" className="fs-name-link" onClick={() => openDir(entry.name)}>
                              {entry.name}/
                            </button>
                          ) : (
                            <span className="fs-name">
                              {entry.name}
                              {entry.is_symlink ? <span className="muted"> (link)</span> : null}
                            </span>
                          )}
                        </td>
                        <td>{entry.type}</td>
                        <td>{entry.type === "file" ? formatBytes(entry.size) : "—"}</td>
                        <td>{when}</td>
                        <td>
                          <code className="fs-mode">{entry.mode || "—"}</code>
                        </td>
                        <td className="fs-actions">
                          {entry.type === "file" ? (
                            entry.download_blocked ? (
                              <span className="muted">Blocked</span>
                            ) : (
                              <button
                                type="button"
                                className="btn ghost"
                                disabled={downloading === entry.name}
                                onClick={() => void downloadFile(rel, entry.name)}
                              >
                                {downloading === entry.name ? "…" : "Download"}
                              </button>
                            )
                          ) : (
                            <button type="button" className="btn ghost" onClick={() => openDir(entry.name)}>
                              Open
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <p className="fs-footer muted">
                Showing {listing.entries.length} of {listing.total}
                {listing.absolute ? ` · ${listing.absolute}` : ""}
              </p>
            </div>
          )}
        </div>
      </section>

      <p className="muted">
        <Link to="/admin/audit">Audit log</Link> records every list and download.
      </p>
    </main>
  );
}
