import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { LoadingMark } from "./LoadingMark";
import { api } from "../lib/api";
import { githubBlobUrl, githubCommitUrl } from "../lib/githubLinks";
import { exportScanReport, sortFindingsByRisk, type ExportFormat } from "../lib/reportExport";
import { formatScanDuration, shortCommit } from "../lib/scanDisplay";
import { scanProgressLabel } from "../lib/scanProgress";
import type { Finding, Scan } from "../lib/workspace";

type Props = {
  scan: Scan;
  findings: Finding[];
  findingsLoading?: boolean;
  projectName?: string;
  githubRepoFullName?: string | null;
  onClose: () => void;
  onShared?: (scan: Scan) => void;
  onFindingsChange?: (items: Finding[]) => void;
  variant?: "modal" | "page";
  onCancelScan?: () => void;
  cancelBusy?: boolean;
};

const EXPORT_OPTIONS: { value: ExportFormat; label: string }[] = [
  { value: "md", label: "Markdown (.md)" },
  { value: "json", label: "JSON (.json)" },
  { value: "csv", label: "CSV (.csv)" },
  { value: "html", label: "HTML (.html)" },
  { value: "sarif", label: "SARIF (.sarif)" },
];

function IconExport() {
  return (
    <svg className="report-action-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M12 3v10m0 0l3.5-3.5M12 13L8.5 9.5M5 15v3a2 2 0 002 2h10a2 2 0 002-2v-3"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function IconBack() {
  return (
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
  );
}

function IconShare() {
  return (
    <svg className="report-action-icon" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="18" cy="5" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <circle cx="6" cy="12" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <circle cx="18" cy="19" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <path d="M8.4 10.8l7.2-4.6M8.4 13.2l7.2 4.6" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
    </svg>
  );
}

function shareCaption(scan: Scan, projectName?: string) {
  const name = projectName || scan.project_name || scan.target;
  const version = shortCommit(scan.commit_short, scan.commit_sha);
  return version ? `${name} · ${version}` : name;
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
  const display = shortCommit(short, sha) || short.slice(0, 7);
  const href = githubCommitUrl(repo, sha || short);
  if (!href) return <code title={sha || undefined}>{display}</code>;
  return (
    <a className="scan-git-link" href={href} target="_blank" rel="noreferrer" title={`Open ${display} on GitHub`}>
      <code>{display}</code>
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
  onFindingsChange: _onFindingsChange,
  variant = "modal",
  onCancelScan,
  cancelBusy = false,
}: Props) {
  const [shareUrl, setShareUrl] = useState<string | null>(
    scan.share_token ? `${window.location.origin}/report/${scan.share_token}` : null,
  );
  const [shareOpen, setShareOpen] = useState(false);
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [exportPos, setExportPos] = useState<{ top: number; left: number } | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const exportWrapRef = useRef<HTMLDivElement>(null);
  const exportBtnRef = useRef<HTMLButtonElement>(null);
  const exportMenuRef = useRef<HTMLDivElement>(null);
  const liveLogRef = useRef<HTMLDivElement>(null);

  const sorted = useMemo(() => sortFindingsByRisk(findings), [findings]);
  const caption = shareCaption(scan, projectName);
  const scanning = scan.status === "queued" || scan.status === "running";
  const progressPct = Math.max(0, Math.min(100, Number(scan.progress?.percent ?? (scanning ? 2 : 100))));
  const progressLabel = scanProgressLabel(scan.progress, scan.status);
  const liveLogs = scan.progress?.logs || [];
  const findingsSoFar = scan.progress?.findings_so_far ?? 0;

  const aiReport = scan.summary?.ai_report?.trim() || null;

  useEffect(() => {
    const el = liveLogRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [liveLogs.length, scanning]);

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
      if (exportOpen) {
        setExportOpen(false);
        return;
      }
      if (variant === "page") return;
      onClose();
    }
    function onDoc(e: MouseEvent) {
      const t = e.target as Node;
      if (exportWrapRef.current?.contains(t) || exportMenuRef.current?.contains(t)) return;
      setExportOpen(false);
    }
    function placeMenu() {
      const btn = exportBtnRef.current;
      if (!btn || !exportOpen) return;
      const r = btn.getBoundingClientRect();
      const width = 208;
      const left = Math.min(Math.max(8, r.right - width), window.innerWidth - width - 8);
      setExportPos({ top: r.bottom + 6, left });
    }
    window.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDoc);
    window.addEventListener("resize", placeMenu);
    window.addEventListener("scroll", placeMenu, true);
    placeMenu();
    return () => {
      window.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDoc);
      window.removeEventListener("resize", placeMenu);
      window.removeEventListener("scroll", placeMenu, true);
    };
  }, [shareOpen, exportOpen, onClose, selected, variant]);

  function toggleExport() {
    setExportOpen((open) => {
      if (open) return false;
      const btn = exportBtnRef.current;
      if (btn) {
        const r = btn.getBoundingClientRect();
        const width = 208;
        const left = Math.min(Math.max(8, r.right - width), window.innerWidth - width - 8);
        setExportPos({ top: r.bottom + 6, left });
      }
      return true;
    });
  }

  function runExport(format: ExportFormat) {
    setExportOpen(false);
    exportScanReport(format, scan, sorted, projectName);
  }

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

  const blobHref = selected
    ? githubBlobUrl(githubRepoFullName, scan.commit_sha || scan.commit_short, selected.file_path, selected.line_start)
    : null;

  const commitDisplay = shortCommit(scan.commit_short, scan.commit_sha);

  const reportBody = (
    <>
      <div className="report-chrome modal-body-pad">
        <div className="report-topbar">
          {variant === "page" ? (
            <button type="button" className="report-back-link" onClick={onClose}>
              Back to scans
            </button>
          ) : (
            <button type="button" className="report-back-link" onClick={onClose}>
              Close
            </button>
          )}
          <div className="report-top-actions">
            <div className="report-export-menu" ref={exportWrapRef}>
              <button
                type="button"
                ref={exportBtnRef}
                className="btn ghost report-action-btn"
                aria-haspopup="menu"
                aria-expanded={exportOpen}
                disabled={findingsLoading}
                onClick={toggleExport}
              >
                <IconExport />
                Export
                <span className="report-action-caret" aria-hidden>
                  ▾
                </span>
              </button>
            </div>
            <button type="button" className="btn ghost report-action-btn" onClick={() => void openShare()}>
              <IconShare />
              Share
            </button>
          </div>
        </div>

        <header className="report-title-block">
          <p className="modal-kicker">Report</p>
          <h2 id="scan-report-title">{projectName || scan.project_name || "Scan report"}</h2>
        </header>

        <div className="report-meta">
          <div>
            <span className="muted">Target</span>
            <div>
              <b>{scan.target}</b>
            </div>
          </div>
          <div>
            <span className="muted">Git version</span>
            <div>
              {commitDisplay ? (
                <>
                  <CommitLink short={commitDisplay} sha={scan.commit_sha} repo={githubRepoFullName} />
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
            {scan.summary?.policy_failed ? (
              <div className="muted small">Policy failed (≥ {scan.summary.fail_severity})</div>
            ) : null}
          </div>
        </div>
      </div>

      {scanning ? (
        <section className="scan-live modal-body-pad" aria-live="polite" aria-busy="true">
          <div className="scan-live-head">
            <div>
              <p className="modal-kicker">Scanning</p>
              <h3 className="scan-live-title">{progressLabel || "Working…"}</h3>
              <p className="muted small">
                {formatScanDuration(scan)}
                {findingsSoFar > 0 ? ` · ${findingsSoFar} finding${findingsSoFar === 1 ? "" : "s"} so far` : ""}
              </p>
            </div>
            {onCancelScan ? (
              <button
                type="button"
                className="btn ghost report-tool-btn"
                disabled={cancelBusy || !!scan.cancel_requested}
                onClick={onCancelScan}
              >
                {scan.cancel_requested || cancelBusy ? "Cancelling…" : "Cancel scan"}
              </button>
            ) : null}
          </div>
          <div className="scan-live-bar" role="progressbar" aria-valuenow={progressPct} aria-valuemin={0} aria-valuemax={100}>
            <div className="scan-live-bar-fill" style={{ width: `${progressPct}%` }} />
          </div>
          <div className="scan-live-pct muted small">{progressPct}%</div>
          <div className="scan-live-log" ref={liveLogRef}>
            {!liveLogs.length ? (
              <p className="muted small">Waiting for scanner output…</p>
            ) : (
              <ul>
                {liveLogs.map((row, i) => (
                  <li key={`${row.t || "log"}-${i}`}>
                    <span className="scan-live-log-msg">{row.msg}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      ) : null}

      {aiReport && !scanning ? (
        <div className="report-ai modal-body-pad">
          <h3 className="report-section-title">AI final report</h3>
          <pre className="ai-report-body">{aiReport}</pre>
        </div>
      ) : null}

      <div className="report-findings modal-body-pad">
        {scanning ? null : findingsLoading ? (
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
          <div className="empty-state compact">No findings.</div>
        ) : (
          <ul className="finding-list">
            {sorted.map((f) => (
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
    </>
  );

  const drawers = (
    <>
      {exportOpen && exportPos
        ? createPortal(
            <div
              ref={exportMenuRef}
              className="report-export-dropdown portal"
              role="menu"
              style={{ top: exportPos.top, left: exportPos.left, width: 208 }}
            >
              <p className="report-export-label">Export as</p>
              {EXPORT_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  role="menuitem"
                  className="report-export-item"
                  onClick={() => runExport(opt.value)}
                >
                  {opt.label}
                </button>
              ))}
            </div>,
            document.body,
          )
        : null}

      {selected
        ? createPortal(
            <div className="modal-root finding-drawer-root" role="presentation">
              <button type="button" className="modal-backdrop" aria-label="Close finding" onClick={() => setSelected(null)} />
              <aside className="finding-drawer" role="dialog" aria-modal="true" aria-labelledby="finding-drawer-title">
                <div className="finding-drawer-top">
                  <button type="button" className="finding-back-btn" aria-label="Back to findings" onClick={() => setSelected(null)}>
                    <IconBack />
                    <span>Back</span>
                  </button>
                </div>
                <div className="finding-drawer-head">
                  <p className="modal-kicker">Finding</p>
                  <h2 id="finding-drawer-title">{selected.title}</h2>
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
    </>
  );

  if (variant === "page") {
    return (
      <main className="admin-main scan-report-page">
        <div className="report-page-panel">{reportBody}</div>
        {drawers}
      </main>
    );
  }

  return createPortal(
    <div className="modal-root" role="presentation">
      <button type="button" className="modal-backdrop" aria-label="Close dialog" onClick={onClose} />
      <div className="modal-panel report-modal" role="dialog" aria-modal="true" aria-labelledby="scan-report-title">
        {reportBody}
      </div>
      {drawers}
    </div>,
    document.body,
  );
}
