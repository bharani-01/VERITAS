import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { githubCommitUrl } from "../lib/githubLinks";
import { exportScanReport, sortFindingsByRisk, type ExportFormat } from "../lib/reportExport";
import type { Finding, Scan } from "../lib/workspace";

type SharedPayload = {
  scan: Scan;
  project: { name: string; github_repo_full_name?: string | null; github_html_url?: string | null };
  items: Finding[];
  total: number;
};

/** Public shared scan report — no login required. */
export function SharedReportPage() {
  const { token } = useParams();
  const [data, setData] = useState<SharedPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exportFormat, setExportFormat] = useState<ExportFormat>("md");

  useEffect(() => {
    if (!token) return;
    fetch(`/public/reports/${token}`, { credentials: "omit" })
      .then(async (res) => {
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error((body as { detail?: string }).detail || "Report not found.");
        return body as SharedPayload;
      })
      .then(setData)
      .catch((err: Error) => setError(err.message));
  }, [token]);

  const sorted = useMemo(() => sortFindingsByRisk(data?.items || []), [data]);
  const repo = data?.project.github_repo_full_name;
  const headHref = data?.scan.commit_short
    ? githubCommitUrl(repo, data.scan.commit_sha || data.scan.commit_short)
    : null;

  if (error) {
    return (
      <main className="auth-shell shared-report-shell">
        <div className="auth-panel" style={{ maxWidth: 480, margin: "4rem auto" }}>
          <h1>Report unavailable</h1>
          <p className="muted">{error}</p>
          <Link className="btn" to="/">
            Go to VERITAS
          </Link>
        </div>
      </main>
    );
  }

  if (!data) {
    return (
      <main className="auth-shell shared-report-shell">
        <div className="auth-panel" style={{ maxWidth: 480, margin: "4rem auto" }}>
          <LoadingMark label="Loading shared report…" />
        </div>
      </main>
    );
  }

  const { scan, project } = data;

  return (
    <main className="shared-report-page">
      <header className="shared-report-header">
        <div>
          <div className="eyebrow">Shared VERITAS report</div>
          <h1>{project.name}</h1>
          <p className="muted">
            {scan.target}
            {scan.commit_short ? (
              <>
                {" "}
                · Git{" "}
                {headHref ? (
                  <a className="scan-git-link" href={headHref} target="_blank" rel="noreferrer">
                    <code>{scan.commit_short}</code>
                  </a>
                ) : (
                  <code>{scan.commit_short}</code>
                )}
                {scan.commit_message ? ` — ${scan.commit_message}` : ""}
              </>
            ) : null}
          </p>
        </div>
        <div className="scan-actions">
          <label className="report-export">
            Export
            <select value={exportFormat} onChange={(e) => setExportFormat(e.target.value as ExportFormat)}>
              <option value="md">Markdown (.md)</option>
              <option value="json">JSON (.json)</option>
              <option value="csv">CSV (.csv)</option>
              <option value="html">HTML (.html)</option>
            </select>
          </label>
          <button
            type="button"
            className="btn"
            onClick={() => exportScanReport(exportFormat, scan, sorted, project.name)}
          >
            Download
          </button>
        </div>
      </header>

      <section className="scan-report-panel">
        <h2>Findings (highest risk first)</h2>
        {!sorted.length ? (
          <div className="empty-state">No findings in this report.</div>
        ) : (
          <ul className="finding-list">
            {sorted.map((f) => (
              <li key={f.id}>
                <div className="finding-head">
                  <span className={`badge ${f.severity}`}>{f.severity}</span>
                  <span className="badge muted">risk {f.risk_score.toFixed(1)}</span>
                  <b>{f.title}</b>
                </div>
                <div className="muted small">
                  {f.engine}
                  {f.file_path ? ` · ${f.file_path}${f.line_start ? `:${f.line_start}` : ""}` : ""}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}
