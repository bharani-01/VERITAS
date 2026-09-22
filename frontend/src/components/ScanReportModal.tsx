import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { LoadingMark } from "./LoadingMark";
import { api } from "../lib/api";
import { githubCommitUrl } from "../lib/githubLinks";
import { exportScanReport, sortFindingsByRisk, type ExportFormat } from "../lib/reportExport";
import type { Finding, Scan } from "../lib/workspace";

type Props = {
  scan: Scan;
  findings: Finding[];
  findingsLoading?: boolean;
  projectName?: string;
  githubRepoFullName?: string | null;
  onClose: () => void;
  onShared?: (scan: Scan) => void;
};

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
}: Props) {
  const [exportFormat, setExportFormat] = useState<ExportFormat>("md");
  const [shareUrl, setShareUrl] = useState<string | null>(
    scan.share_token ? `${window.location.origin}/report/${scan.share_token}` : null,
  );
  const [shareOpen, setShareOpen] = useState(false);
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const sorted = useMemo(() => sortFindingsByRisk(findings), [findings]);
  const caption = shareCaption(scan, projectName);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      if (shareOpen) {
        setShareOpen(false);
        return;
      }
      onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [shareOpen, onClose]);

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
          ) : !sorted.length ? (
            <div className="empty-state compact">No findings for this scan.</div>
          ) : (
            <ul className="finding-list">
              {sorted.map((f) => (
                <li key={f.id}>
                  <div className="finding-head">
                    <span className={`badge ${f.severity}`}>{f.severity}</span>
                    <span className="badge muted">risk {f.risk_score.toFixed(1)}</span>
                    <span className="badge muted">{f.vuln_family}</span>
                    <b>{f.title}</b>
                  </div>
                  <div className="muted small">
                    {f.engine}
                    {f.file_path ? ` · ${f.file_path}${f.line_start ? `:${f.line_start}` : ""}` : ""}
                    {f.cwe ? ` · ${f.cwe}` : ""}
                  </div>
                  {f.countermeasures?.[0]?.steps?.length ? (
                    <ul className="finding-fixes">
                      {f.countermeasures[0].steps.map((step) => (
                        <li key={step}>{step}</li>
                      ))}
                    </ul>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

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
                <p className="modal-copy">Anyone with the link can view this report without signing in.</p>
                <div className="share-preview">
                  <b>{caption}</b>
                  <span className="muted small">{shareBusy ? "Creating link…" : shareUrl || "Link unavailable"}</span>
                </div>
                {shareError ? (
                  <div className="notice error compact" role="alert">
                    {shareError}
                  </div>
                ) : null}
                <div className="modal-actions">
                  <button type="button" className="btn ghost" onClick={() => setShareOpen(false)}>
                    Cancel
                  </button>
                  <button type="button" className="btn" onClick={() => void copyShare()} disabled={!shareUrl || shareBusy}>
                    {copied ? "Copied" : "Copy link"}
                  </button>
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
