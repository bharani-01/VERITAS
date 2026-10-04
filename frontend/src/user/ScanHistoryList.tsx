import { Link, useNavigate } from "react-router-dom";
import { formatStatus } from "../lib/avatars";
import {
  findingsCountLabel,
  formatScanDuration,
  relativeTime,
  scanHeadline,
  scanTriggerLabel,
  shortCommit,
} from "../lib/scanDisplay";
import { scanProgressLabel } from "../lib/scanProgress";
import type { Scan } from "../lib/workspace";

type Props = {
  scans: Scan[];
  /** When set, rows navigate to /user/projects/:id/scans/:scanId */
  projectId?: string;
  title?: string;
  emptyTitle?: string;
  emptyBody?: string;
  showProjectName?: boolean;
  /** Scan ids that just appeared — play enter animation */
  enteringIds?: string[];
  onCancel?: (scanId: string) => void;
};

function StatusIcon({ status }: { status: string }) {
  if (status === "completed") {
    return (
      <span className="scan-hist-icon ok" aria-label="Completed" title="Completed">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M20 6 9 17l-5-5" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className="scan-hist-icon fail" aria-label="Failed" title="Failed">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M18 6 6 18M6 6l12 12" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
        </svg>
      </span>
    );
  }
  if (status === "cancelled") {
    return (
      <span className="scan-hist-icon muted" aria-label="Cancelled" title="Cancelled">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M8 12h8" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
        </svg>
      </span>
    );
  }
  return (
    <span className="scan-hist-icon pending" aria-label={formatStatus(status)} title={formatStatus(status)}>
      <svg className="scan-hist-spinner" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2.75" strokeOpacity="0.25" />
        <path
          d="M12 3a9 9 0 0 1 9 9"
          stroke="currentColor"
          strokeWidth="2.75"
          strokeLinecap="round"
        />
      </svg>
    </span>
  );
}

export function ScanHistoryList({
  scans,
  projectId,
  title = "Scans",
  emptyTitle = "No scans yet",
  emptyBody = "Start a scan or enable auto-scan on push to see history here.",
  showProjectName = false,
  enteringIds = [],
  onCancel,
}: Props) {
  const navigate = useNavigate();
  const entering = new Set(enteringIds);

  return (
    <section className="scan-hist" aria-label={title}>
      <div className="scan-hist-grid scan-hist-head">
        <span className="scan-hist-h-main">
          {title}
          <span className="scan-hist-count">{scans.length}</span>
        </span>
        <span className="scan-hist-h-col">Trigger</span>
        <span className="scan-hist-h-col">Findings</span>
        <span className="scan-hist-h-col">Duration</span>
        <span className="scan-hist-h-action">
          <span className="sr-only">Actions</span>
        </span>
      </div>
      {!scans.length ? (
        <div className="empty-state scan-hist-empty">
          <strong>{emptyTitle}</strong>
          {emptyBody}
        </div>
      ) : (
        <ul className="scan-hist-list">
          {scans.map((scan) => {
            const sha = shortCommit(scan.commit_short, scan.commit_sha);
            const scanning = scan.status === "queued" || scan.status === "running";
            const pid = projectId || scan.project_id;
            const href = `/user/projects/${pid}/scans/${scan.id}`;
            const when = relativeTime(scan.finished_at || scan.created_at);
            const findings = findingsCountLabel(scan);
            const headline = scanHeadline(scan);
            const percent = Math.max(2, Math.min(100, Number(scan.progress?.percent ?? (scan.status === "running" ? 15 : 4))));
            const progressLabel = scanProgressLabel(scan.progress, scan.status) || "Scanning…";

            return (
              <li key={scan.id} className={entering.has(scan.id) ? "scan-hist-enter" : undefined}>
                <div className={`scan-hist-grid scan-hist-row ${scanning ? "is-scanning" : ""}`}>
                  <Link className="scan-hist-stretch" to={href} aria-label={`Open scan: ${headline}`} />
                  <span className="scan-hist-main">
                    <StatusIcon status={scan.status} />
                    <span className="scan-hist-copy">
                      <div className="scan-hist-headline-row">
                        <span className="scan-hist-msg">{headline}</span>
                        {scanning ? (
                          <span className="scan-live-phase-chip" title={progressLabel}>
                            <span className="scan-live-dot" />
                            <span className="scan-live-phase-text">{progressLabel}</span>
                          </span>
                        ) : null}
                      </div>

                      <span className="scan-hist-meta">
                        {showProjectName && scan.project_name ? (
                          <>
                            <span className="scan-hist-project">{scan.project_name}</span>
                            <span className="scan-hist-dot" aria-hidden="true">
                              ·
                            </span>
                          </>
                        ) : null}
                        {sha ? <code className="scan-hist-sha">{sha}</code> : <span>—</span>}
                        {when ? (
                          <>
                            <span className="scan-hist-dot" aria-hidden="true">
                              ·
                            </span>
                            <span>
                              {scanning ? "Running" : scan.status === "completed" ? "Scanned" : formatStatus(scan.status)} {when}
                            </span>
                          </>
                        ) : null}
                        {scanning && percent > 0 ? (
                          <>
                            <span className="scan-hist-dot" aria-hidden="true">
                              ·
                            </span>
                            <span className="scan-live-percent">{percent}%</span>
                          </>
                        ) : null}
                        <span className="scan-hist-mobile-extra">
                          {" · "}
                          {scanTriggerLabel(scan)}
                          {" · "}
                          {findings === "—" || findings === "…" ? findings : `${findings} findings`}
                          {" · "}
                          {formatScanDuration(scan)}
                        </span>
                      </span>
                    </span>
                  </span>

                  <span className="scan-hist-col">{scanTriggerLabel(scan)}</span>

                  <span className="scan-hist-col scan-hist-findings">
                    {scanning ? (
                      <span className="scan-analyzing-pill">
                        <span className="badge-spinner" aria-hidden="true" />
                        <span>Analyzing…</span>
                      </span>
                    ) : findings === "—" || findings === "…" ? (
                      findings
                    ) : (
                      <>
                        <b>{findings}</b>
                        <span className="scan-hist-findings-label"> findings</span>
                      </>
                    )}
                  </span>

                  <span className="scan-hist-col">
                    {scanning ? (
                      <span className="scan-duration-live" title="Estimated time remaining">
                        <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                          <circle cx="12" cy="12" r="10" />
                          <polyline points="12 6 12 12 16 14" />
                        </svg>
                        <span>{formatScanDuration(scan)}</span>
                      </span>
                    ) : (
                      formatScanDuration(scan)
                    )}
                  </span>

                  <span className="scan-hist-action">
                    {scanning && onCancel ? (
                      <button
                        type="button"
                        className="scan-hist-cancel-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          e.preventDefault();
                          onCancel(scan.id);
                        }}
                        disabled={!!scan.cancel_requested}
                        aria-label="Cancel scan"
                      >
                        <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round">
                          <line x1="18" y1="6" x2="6" y2="18" />
                          <line x1="6" y1="6" x2="18" y2="18" />
                        </svg>
                        <span>{scan.cancel_requested ? "Cancelling…" : "Cancel"}</span>
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="scan-hist-chevron"
                        onClick={() => navigate(href)}
                        tabIndex={-1}
                        aria-hidden="true"
                      >
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
                      </button>
                    )}
                  </span>

                  {scanning ? (
                    <div className="scan-hist-bottom-track" aria-hidden="true">
                      <div
                        className="scan-hist-bottom-fill"
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  ) : null}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
