import { useEffect, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { Project, Scan } from "../lib/workspace";
import { formatStatus } from "../lib/avatars";

/** Project-scoped scans — opened from the projects list. */
export function UserProjectDetailPage() {
  const { projectId } = useParams();
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [target, setTarget] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    if (!projectId) return;
    const [proj, scanData] = await Promise.all([
      api<{ project: Project }>(`/workspace/projects/${projectId}`),
      api<{ items: Scan[] }>(`/workspace/projects/${projectId}/scans`),
    ]);
    setProject(proj.project);
    setScans(scanData.items);
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [projectId]);

  async function onScan(e: FormEvent) {
    e.preventDefault();
    if (!projectId) return;
    setBusy(true);
    setError(null);
    try {
      const body = target.trim() ? { target: target.trim() } : {};
      await api(`/workspace/projects/${projectId}/scans`, { method: "POST", body: JSON.stringify(body) });
      setTarget("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (error && !project) {
    return (
      <main className="admin-main">
        <div className="notice error" role="alert">
          {error}
        </div>
        <Link to="/user/projects">Back to projects</Link>
      </main>
    );
  }

  if (!project) {
    return (
      <main className="admin-main">
        <LoadingMark label="Loading scans…" />
      </main>
    );
  }

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">
            <Link to="/user/projects">Projects</Link>
            <span aria-hidden="true"> / </span>
            Scans
          </div>
          <h1>{project.name}</h1>
          <p>
            {project.description || "Scans for this application."}
            {project.github_repo_full_name ? (
              <>
                {" "}
                ·{" "}
                {project.github_html_url ? (
                  <a href={project.github_html_url} target="_blank" rel="noreferrer">
                    {project.github_repo_full_name}
                  </a>
                ) : (
                  project.github_repo_full_name
                )}
              </>
            ) : null}
          </p>
        </div>
        <form className="scan-inline-form" onSubmit={onScan}>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={project.github_repo_full_name || "Target (optional)"}
            maxLength={512}
            aria-label="Scan target"
          />
          <button className="btn" type="submit" disabled={busy}>
            {busy ? "Starting…" : "Start scan"}
          </button>
        </form>
      </header>

      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}

      {!scans.length ? (
        <div className="empty-state">
          <strong>No scans yet</strong>
          Start a stub scan for this project. Findings engines arrive in a later phase.
        </div>
      ) : (
        <div className="scan-table-wrap">
          <table className="scan-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Source</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td>
                    <b>{scan.target}</b>
                  </td>
                  <td className="muted">{scan.source.replace(/_/g, " ")}</td>
                  <td>
                    <span className={`badge ${scan.status}`}>{formatStatus(scan.status)}</span>
                  </td>
                  <td>{scan.summary?.findings_count ?? "—"}</td>
                  <td className="muted">{new Date(scan.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
