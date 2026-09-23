import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { LoadingMark } from "./LoadingMark";
import { api } from "../lib/api";
import { githubBlobUrl, githubCommitUrl } from "../lib/githubLinks";
import { exportScanReport, sortFindingsByRisk, type ExportFormat } from "../lib/reportExport";
import type { Finding, FindingStatus, Scan } from "../lib/workspace";

type Props = {
  scan: Scan;
  findings: Finding[];
  findingsLoading?: boolean;
  projectName?: string;
  githubRepoFullName?: string | null;
  onClose: () => void;
  onShared?: (scan: Scan) => void;
  onFindingsChange?: (items: Finding[]) => void;
};

const STATUSES: FindingStatus[] = ["open", "triage", "fixed", "false_positive"];

function shareCaption(scan: Scan, projectName?: string) {
  const name = projectName || scan.project_name || scan.target;
  const version = scan.commit_short ? ` · ${scan.commit_short}` : "";
  return `${name}${version}`;
}

function CommitLink({
  short,
  sha,
  repo,
}: {
  short: string;
  sha?: string | null;
  repo?: string | null;
}) {
  const href = githubCommitUrl(repo, sha || short);
  if (!href) return <code title={sha || undefined}>{short}</code>;
  return (
    <a className="scan-git-link" href={href} target="_blank" rel="noreferrer" title={`Open ${short} on GitHub`}>
      <code>{short}</code>
    </a>
  );
}

export function ScanReportModal({
  scan,
  findings,
  findingsLoading = false,
  projectName,
  githubRepoFullName,
  onClose,
  onShared,
  onFindingsChange,
}: Props) {
  const [exportFormat, setExportFormat] = useState<ExportFormat>("md");
  const [shareUrl, setShareUrl] = useState<string | null>(
    scan.share_token ? `${window.location.origin}/report/${scan.share_token}` : null,
  );
  const [shareOpen, setShareOpen] = useState(false);
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [statusBusy, setStatusBusy] = useState(false);

  const sorted = useMemo(() => sortFindingsByRisk(findings), [findings]);
  const filtered = useMemo(
    () => (statusFilter === "all" ? sorted : sorted.filter((f) => f.status === statusFilter)),
    [sorted, statusFilter],
  );
  const caption = shareCaption(scan, projectName);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      if (selected) {
        setSelected(null);
        return;
      }
      if (shareOpen) {
        setShareOpen(false);
        return;
      }
      onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [shareOpen, onClose, selected]);

  async function openShare() {
    setShareOpen(true);
    setShareError(null);
    setCopied(false);
    if (shareUrl) return;
    setShareBusy(true);
    try {
      const res = await api<{ share_url: string; scan: Scan }>(`/workspace/scans/${scan.id}/share`, {
        method: "POST",
      });
      setShareUrl(res.share_url);
      onShared?.(res.scan);
    } catch (err) {
      setShareError((err as Error).message);
    } finally {
      setShareBusy(false);
    }
  }

  async function copyShare() {
    if (!shareUrl) return;
    const text = `${caption}\n${shareUrl}`;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      setShareError("Could not copy link.");
    }
  }

  async function setFindingStatus(finding: Finding, status: FindingStatus) {
    setStatusBusy(true);
    try {
      const res = await api<{ finding: Finding }>(`/workspace/findings/${finding.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
      const next = findings.map((f) => (f.id === finding.id ? res.finding : f));
      onFindingsChange?.(next);
      setSelected(res.finding);
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setStatusBusy(false);
    }
  }

  async function suppressFinding(finding: Finding) {
    setStatusBusy(true);
    try {
      const res = await api<{ finding: Finding }>(`/workspace/findings/${finding.id}/suppress`, {
        method: "POST",
        body: JSON.stringify({ reason: "Suppressed from report" }),
      });
      const next = findings.map((f) => (f.id === finding.id ? res.finding : f));
      onFindingsChange?.(next);
      setSelected(res.finding);
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setStatusBusy(false);
    }
  }

  const blobHref = selected
    ? githubBlobUrl(githubRepoFullName, scan.commit_sha || scan.commit_short, selected.file_path, selected.line_start)
    : null;

  return createPortal(
    <div className="modal-root" role="presentation">
      <button type="button" className="modal-backdrop" aria-label="Close dialog" onClick={onClose} />
      <div className="modal-panel report-modal" role="dialog" aria-modal="true" aria-labelledby="scan-report-title">
        <div className="modal-head">
          <div>
            <p className="modal-kicker">Report</p>
            <h2 id="scan-report-title">{projectName || scan.project_name || "Scan report"}</h2>
          </div>
          <span className="muted small">Esc to close</span>
        </div>

        <div className="report-meta modal-body-pad">
          <div>
            <span className="muted">Target</span>
            <div>
              <b>{scan.target}</b>
            </div>
          </div>
          <div>
            <span className="muted">Git version</span>
            <div>
              {scan.commit_short ? (
                <>
                  <CommitLink short={scan.commit_short} sha={scan.commit_sha} repo={githubRepoFullName} />
                  {scan.commit_message ? <span className="muted"> — {scan.commit_message}</span> : null}
                </>
              ) : (
                <span className="muted">Not available</span>
              )}
            </div>
            {scan.commit_author ? <div className="muted small">{scan.commit_author}</div> : null}
          </div>
          <div>
            <span className="muted">Risk</span>
            <div>
              <b>{scan.risk_summary?.max_risk ?? scan.summary?.max_risk ?? "—"}</b>
              <span className="muted">
                {" "}
                ·{" "}
                {findingsLoading
                  ? `${scan.summary?.findings_count ?? "…"} findings`
                  : `${sorted.length} findings`}
              </span>
            </div>
          </div>
        </div>

        <div className="report-toolbar modal-body-pad">
          <label className="report-export">
            Status
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} disabled={findingsLoading}>
              <option value="all">All</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </label>
          <label className="report-export">
            Export
            <select
              value={exportFormat}
              onChange={(e) => setExportFormat(e.target.value as ExportFormat)}
              disabled={findingsLoading}
            >
              <option value="md">Markdown (.md)</option>
              <option value="json">JSON (.json)</option>
              <option value="csv">CSV (.csv)</option>
              <option value="html">HTML (.html)</option>
            </select>
          </label>
          <button
            type="button"
            className="btn secondary report-tool-btn"
            disabled={findingsLoading}
            onClick={() => exportScanReport(exportFormat, scan, sorted, projectName)}
          >
            Download
          </button>
          <button type="button" className="btn ghost report-tool-btn" onClick={() => void openShare()}>
            Share report
          </button>
        </div>

        <div className="report-findings modal-body-pad">
          <h3>Findings (highest risk first)</h3>
          {findingsLoading ? (
            <div className="report-findings-loading">
              <LoadingMark
                size="sm"
                label={
                  scan.summary?.findings_count
                    ? `Loading ${scan.summary.findings_count} findings…`
                    : "Loading findings…"
                }
              />
            </div>
          ) : !filtered.length ? (
            <div className="empty-state compact">No findings for this filter.</div>
          ) : (
            <ul className="finding-list">
              {filtered.map((f) => (
                <li key={f.id}>
                  <button type="button" className="finding-row-btn" onClick={() => setSelected(f)}>
                    <div className="finding-head">
                      <span className={`badge ${f.severity}`}>{f.severity}</span>
                      <span className="badge muted">{f.status.replace(/_/g, " ")}</span>
                      <span className="badge muted">risk {f.risk_score.toFixed(1)}</span>
                      <b>{f.title}</b>
                    </div>
                    <div className="muted small">
                      {f.engine}
                      {f.file_path ? ` · ${f.file_path}${f.line_start ? `:${f.line_start}` : ""}` : ""}
                      {f.ai_verdict ? ` · AI ${f.ai_verdict}` : ""}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {selected
        ? createPortal(
            <div className="modal-root finding-drawer-root" role="presentation">
              <button type="button" className="modal-backdrop" aria-label="Close finding" onClick={() => setSelected(null)} />
              <aside className="finding-drawer" role="dialog" aria-modal="true" aria-labelledby="finding-drawer-title">
                <div className="modal-head">
                  <div>
                    <p className="modal-kicker">Finding</p>
                    <h2 id="finding-drawer-title">{selected.title}</h2>
                  </div>
                  <button type="button" className="modal-close" aria-label="Close" onClick={() => setSelected(null)}>
                    ×
                  </button>
                </div>
                <div className="finding-drawer-body">
                  <div className="finding-head">
                    <span className={`badge ${selected.severity}`}>{selected.severity}</span>
                    <span className="badge muted">{selected.vuln_family}</span>
                    <span className="badge muted">risk {selected.risk_score.toFixed(1)}</span>
                  </div>
                  <p className="muted small">
                    {selected.engine}
                    {selected.rule_id ? ` · ${selected.rule_id}` : ""}
                    {selected.cwe ? ` · ${selected.cwe}` : ""}
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
                  <label>
                    Status
                    <select
                      value={selected.status}
                      disabled={statusBusy}
                      onChange={(e) => void setFindingStatus(selected, e.target.value as FindingStatus)}
                    >
                      {STATUSES.map((s) => (
                        <option key={s} value={s}>
                          {s.replace(/_/g, " ")}
                        </option>
                      ))}
                    </select>
                  </label>
                  <button
                    type="button"
                    className="btn ghost"
                    disabled={statusBusy}
                    onClick={() => void suppressFinding(selected)}
                  >
                    Suppress in future scans
                  </button>
                </div>
              </aside>
            </div>,
            document.body,
          )
        : null}

      {shareOpen
        ? createPortal(
            <div className="modal-root share-sheet-root" role="presentation">
              <button type="button" className="modal-backdrop" aria-label="Close share" onClick={() => setShareOpen(false)} />
              <div className="modal-panel share-sheet" role="dialog" aria-modal="true" aria-labelledby="share-report-title">
                <div className="modal-head">
                  <div>
                    <p className="modal-kicker">Share</p>
                    <h2 id="share-report-title">Copy link</h2>
                  </div>
                </div>
                <div className="modal-body-pad">
                  {shareBusy ? <LoadingMark size="sm" label="Creating link…" /> : null}
                  {shareError ? <p className="notice error">{shareError}</p> : null}
                  {shareUrl ? (
                    <>
                      <p className="muted">{caption}</p>
                      <code className="share-url">{shareUrl}</code>
                      <button type="button" className="btn" onClick={() => void copyShare()}>
                        {copied ? "Copied" : "Copy caption + URL"}
                      </button>
                    </>
                  ) : null}
                </div>
              </div>
            </div>,
            document.body,
          )
        : null}
    </div>,
    document.body,
  );
}
