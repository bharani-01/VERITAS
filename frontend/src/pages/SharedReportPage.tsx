import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Link, useParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { githubBlobUrl, githubCommitUrl } from "../lib/githubLinks";
import { exportScanReport, sortFindingsByRisk, type ExportFormat } from "../lib/reportExport";
import { shortCommit } from "../lib/scanDisplay";
import type { Finding, Scan } from "../lib/workspace";

type SharedPayload = {
  scan: Scan;
  project: { name: string; github_repo_full_name?: string | null; github_html_url?: string | null };
  items: Finding[];
  total: number;
};

const EXPORT_OPTIONS: { value: ExportFormat; label: string }[] = [
  { value: "md", label: "Markdown (.md)" },
  { value: "json", label: "JSON (.json)" },
  { value: "csv", label: "CSV (.csv)" },
  { value: "html", label: "HTML (.html)" },
  { value: "sarif", label: "SARIF (.sarif)" },
];

/** Public shared scan report — no login required. */
export function SharedReportPage() {
  const { token } = useParams();
  const [data, setData] = useState<SharedPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exportOpen, setExportOpen] = useState(false);
  const [selected, setSelected] = useState<Finding | null>(null);
  const exportWrapRef = useRef<HTMLDivElement>(null);

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

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setSelected(null);
        setExportOpen(false);
      }
    }
    function onDoc(e: MouseEvent) {
      if (!exportWrapRef.current?.contains(e.target as Node)) setExportOpen(false);
    }
    window.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDoc);
    return () => {
      window.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDoc);
    };
  }, []);

  const sorted = useMemo(() => sortFindingsByRisk(data?.items || []), [data]);
  const repo = data?.project.github_repo_full_name;
  const headShort = shortCommit(data?.scan.commit_short, data?.scan.commit_sha);
  const headHref = headShort
    ? githubCommitUrl(repo, data?.scan.commit_sha || headShort)
    : null;
  const blobHref = selected
    ? githubBlobUrl(repo, data?.scan.commit_sha || data?.scan.commit_short, selected.file_path, selected.line_start)
    : null;

  if (error) {
    return (
      <main className="shared-report-shell">
        <div className="auth-panel">
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
      <main className="shared-report-shell">
        <div className="auth-panel">
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
            {headShort ? (
              <>
                {" "}
                · Git{" "}
                {headHref ? (
                  <a className="scan-git-link" href={headHref} target="_blank" rel="noreferrer">
                    <code>{headShort}</code>
                  </a>
                ) : (
                  <code>{headShort}</code>
                )}
                {scan.commit_message ? ` — ${scan.commit_message}` : ""}
              </>
            ) : null}
          </p>
        </div>
        <div className="report-top-actions">
          <div className="report-export-menu" ref={exportWrapRef}>
            <button
              type="button"
              className="btn ghost report-action-btn"
              aria-haspopup="menu"
              aria-expanded={exportOpen}
              onClick={() => setExportOpen((o) => !o)}
            >
              Export
              <span className="report-action-caret" aria-hidden>
                ▾
              </span>
            </button>
            {exportOpen ? (
              <div className="report-export-dropdown" role="menu">
                <p className="report-export-label">Export as</p>
                {EXPORT_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    role="menuitem"
                    className="report-export-item"
                    onClick={() => {
                      setExportOpen(false);
                      exportScanReport(opt.value, scan, sorted, project.name);
                    }}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            ) : null}
          </div>
        </div>
      </header>

      <section className="scan-report-panel">
        {scan.summary?.ai_report ? (
          <div className="report-ai">
            <h2>AI final report</h2>
            <pre className="ai-report-body">{scan.summary.ai_report}</pre>
          </div>
        ) : null}
        <h2>Findings (highest risk first)</h2>
        {!sorted.length ? (
          <div className="empty-state">No findings in this report.</div>
        ) : (
          <div className="finding-table">
            <div className="finding-table-head" aria-hidden="true">
              <span>Severity</span>
              <span>Finding</span>
              <span>Status</span>
              <span>Risk</span>
              <span />
            </div>
            <ul className="finding-list">
              {sorted.map((f) => (
                <li key={f.id}>
                  <button type="button" className="finding-row-btn" onClick={() => setSelected(f)}>
                    <span className={`badge ${f.severity}`}>{f.severity}</span>
                    <span className="finding-row-main">
                      <b>{f.title}</b>
                      <span className="muted small">
                        {f.engine}
                        {f.file_path ? ` · ${f.file_path}${f.line_start ? `:${f.line_start}` : ""}` : ""}
                      </span>
                    </span>
                    <span className="finding-row-status">{f.status.replace(/_/g, " ")}</span>
                    <span className="finding-row-risk">{f.risk_score.toFixed(1)}</span>
                    <span className="finding-row-chevron" aria-hidden="true">
                      <svg viewBox="0 0 24 24">
                        <path
                          d="M9 6l6 6-6 6"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="1.75"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                      </svg>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      {selected
        ? createPortal(
            <div className="modal-root finding-drawer-root" role="presentation">
              <button type="button" className="modal-backdrop" aria-label="Close finding" onClick={() => setSelected(null)} />
              <aside className="finding-drawer" role="dialog" aria-modal="true" aria-labelledby="shared-finding-title">
                <div className="finding-drawer-top">
                  <button type="button" className="finding-back-btn" aria-label="Back to findings" onClick={() => setSelected(null)}>
                    <svg className="finding-back-icon" viewBox="0 0 24 24" aria-hidden="true">
                      <path
                        d="M15 6l-6 6 6 6"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.75"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                    <span>Back</span>
                  </button>
                </div>
                <div className="finding-drawer-head">
                  <p className="modal-kicker">Finding</p>
                  <h2 id="shared-finding-title">{selected.title}</h2>
                </div>
                <div className="finding-drawer-body">
                  <div className="finding-head">
                    <span className={`badge ${selected.severity}`}>{selected.severity}</span>
                    <span className="badge muted">{selected.status.replace(/_/g, " ")}</span>
                    <span className="badge muted">risk {selected.risk_score.toFixed(1)}</span>
                  </div>
                  <p className="muted small">
                    {selected.engine}
                    {selected.rule_id ? ` · ${selected.rule_id}` : ""}
                  </p>
                  {selected.file_path ? (
                    <p>
                      {blobHref ? (
                        <a href={blobHref} target="_blank" rel="noreferrer" className="scan-git-link">
                          {selected.file_path}
                          {selected.line_start ? `:${selected.line_start}` : ""}
                        </a>
                      ) : (
                        <code>
                          {selected.file_path}
                          {selected.line_start ? `:${selected.line_start}` : ""}
                        </code>
                      )}
                    </p>
                  ) : null}
                  {selected.message ? <p>{selected.message}</p> : null}
                  {selected.snippet ? <pre className="finding-snippet">{selected.snippet}</pre> : null}
                  {selected.ai_verdict ? (
                    <p>
                      <b>AI:</b> {selected.ai_verdict}
                      {selected.ai_rationale ? ` — ${selected.ai_rationale}` : ""}
                    </p>
                  ) : null}
                  <p className="muted small">Read-only shared view — sign in to change status or suppress.</p>
                </div>
              </aside>
            </div>,
            document.body,
          )
        : null}
    </main>
  );
}
