import { Link, useNavigate } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
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
      <LoadingMark variant="scan" size="xs" label="" />
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
  onCancel,
}: Props) {
  const navigate = useNavigate();

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
            return (
              <li key={scan.id}>
                <div className="scan-hist-grid scan-hist-row">
                  <Link className="scan-hist-stretch" to={href} aria-label={`Open scan: ${headline}`} />
                  <span className="scan-hist-main">
                    <StatusIcon status={scan.status} />
                    <span className="scan-hist-copy">
                      <span className="scan-hist-msg">{headline}</span>
                      {scanning ? (
                        <span className="scan-hist-live">
                          <span className="scan-hist-live-bar" aria-hidden>
                            <span
                              className="scan-hist-live-fill"
                              style={{ width: `${Math.max(2, Math.min(100, Number(scan.progress?.percent ?? 2)))}%` }}
                            />
                          </span>
                          <span className="scan-hist-live-label">
                            {scanProgressLabel(scan.progress, scan.status) || "Scanning…"}
                          </span>
                        </span>
                      ) : null}
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
                              {scan.status === "completed" ? "Scanned" : formatStatus(scan.status)} {when}
                            </span>
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
                    {findings === "—" || findings === "…" ? (
                      findings
                    ) : (
                      <>
                        <b>{findings}</b>
                        <span className="scan-hist-findings-label"> findings</span>
                      </>
                    )}
                  </span>
                  <span className="scan-hist-col">{formatScanDuration(scan)}</span>
                  <span className="scan-hist-action">
                    {scanning && onCancel ? (
                      <button
                        type="button"
                        className="scan-hist-cancel"
                        onClick={() => onCancel(scan.id)}
                      >
                        {scan.cancel_requested ? "Cancelling…" : "Cancel"}
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
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
