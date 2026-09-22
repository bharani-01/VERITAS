import { useEffect, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { Link, useParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { ScanReportModal } from "../components/ScanReportModal";
import { api } from "../lib/api";
import type { Finding, Project, Scan } from "../lib/workspace";
import { formatStatus } from "../lib/avatars";
import { scanProgressLabel } from "../lib/scanProgress";
import { githubCommitUrl } from "../lib/githubLinks";

/** Project-scoped scans with Mode A/B, ETA, and findings report. */
export function UserProjectDetailPage() {
  const { projectId } = useParams();
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [target, setTarget] = useState("");
  const [scanMode, setScanMode] = useState<"rules_only" | "rules_plus_ai">("rules_only");
  const [notifyEmail, setNotifyEmail] = useState(true);
  const [notifyInApp, setNotifyInApp] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [advancedConfirmOpen, setAdvancedConfirmOpen] = useState(false);
  const [draftMode, setDraftMode] = useState<"rules_only" | "rules_plus_ai">("rules_only");
  const [draftTarget, setDraftTarget] = useState("");
  const [draftNotifyEmail, setDraftNotifyEmail] = useState(true);
  const [draftNotifyInApp, setDraftNotifyInApp] = useState(true);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [reportOpen, setReportOpen] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
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
    if (proj.project.notify_email_default != null) setNotifyEmail(!!proj.project.notify_email_default);
    if (proj.project.notify_in_app_default != null) setNotifyInApp(!!proj.project.notify_in_app_default);
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [projectId]);

  useEffect(() => {
    const active = scans.some((s) => s.status === "queued" || s.status === "running");
    if (!active) return;
    const id = window.setInterval(() => {
      load().catch(() => undefined);
    }, 2500);
    return () => window.clearInterval(id);
  }, [scans, projectId]);

  useEffect(() => {
    if (!selectedScanId || !projectId) {
      setFindings([]);
      setFindingsLoading(false);
      return;
    }
    const selected = scans.find((s) => s.id === selectedScanId);
    const status = selected?.status;
    if (status && status !== "completed" && status !== "failed") {
      setFindings([]);
      setFindingsLoading(false);
      return;
    }
    let cancelled = false;
    setFindingsLoading(true);
    setFindings([]);
    api<{ items: Finding[] }>(`/workspace/projects/${projectId}/scans/${selectedScanId}/findings`)
      .then((data) => {
        if (!cancelled) setFindings(data.items);
      })
      .catch(() => {
        if (!cancelled) setFindings([]);
      })
      .finally(() => {
        if (!cancelled) setFindingsLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // Re-fetch only when the selected scan identity/status changes — not on scan list poll ticks.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- intentional: avoid findings flicker on ETA polls
  }, [selectedScanId, projectId, scans.find((s) => s.id === selectedScanId)?.status]);

  async function startScan() {
    if (!projectId) return;
    setConfirmOpen(false);
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        scan_mode: scanMode,
        notify_email: notifyEmail,
        notify_in_app: notifyInApp,
      };
      if (target.trim()) body.target = target.trim();
      const res = await api<{ scan: Scan }>(`/workspace/projects/${projectId}/scans`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      setTarget("");
      setSelectedScanId(res.scan.id);
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function onAskScan(e: FormEvent) {
    e.preventDefault();
    if (!projectId || busy) return;
    setConfirmOpen(true);
  }

  function openAdvanced() {
    setDraftMode(scanMode);
    setDraftTarget(target);
    setDraftNotifyEmail(notifyEmail);
    setDraftNotifyInApp(notifyInApp);
    setShowAdvanced(true);
  }

  function askSaveAdvanced() {
    setAdvancedConfirmOpen(true);
  }

  function saveAdvanced() {
    setScanMode(draftMode);
    setTarget(draftTarget);
    setNotifyEmail(draftNotifyEmail);
    setNotifyInApp(draftNotifyInApp);
    setAdvancedConfirmOpen(false);
    setShowAdvanced(false);
  }

  function closeAdvanced() {
    setAdvancedConfirmOpen(false);
    setShowAdvanced(false);
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

  const selected = scans.find((s) => s.id === selectedScanId) || null;

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
            {project.description || "Security scans for this application."}
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
      </header>

      <section className="scan-start-panel">
        <div className="scan-start-main">
          <h2>Start scan</h2>
          <p className="muted scan-start-summary">
            {scanMode === "rules_plus_ai" ? "Rules + AI" : "Rules only"}
            {" · "}
            {target.trim() || project.github_repo_full_name || "No target set"}
          </p>
        </div>
        <form className="scan-actions" onSubmit={onAskScan}>
          <button className="btn" type="submit" disabled={busy}>
            {busy ? "Starting…" : "Scan now"}
          </button>
          <button
            type="button"
            className="icon-btn scan-advanced-btn"
            aria-label="Advanced options"
            title="Advanced options"
            onClick={openAdvanced}
          >
            <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
          </button>
        </form>
      </section>

      {showAdvanced
        ? createPortal(
            <div className="modal-root" role="presentation">
              <button type="button" className="modal-backdrop" aria-label="Close dialog" onClick={closeAdvanced} />
              <div className="modal-panel scan-advanced-modal" role="dialog" aria-modal="true" aria-labelledby="scan-advanced-title">
                <div className="modal-head">
                  <div>
                    <p className="modal-kicker">Scan</p>
                    <h2 id="scan-advanced-title">Advanced options</h2>
                  </div>
                  <button type="button" className="modal-close" aria-label="Close" onClick={closeAdvanced}>
                    <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M18 6 6 18M6 6l12 12" />
                    </svg>
                  </button>
                </div>
                <div className="scan-advanced modal-body-pad">
                  <label>
                    Mode
                    <select value={draftMode} onChange={(e) => setDraftMode(e.target.value as "rules_only" | "rules_plus_ai")}>
                      <option value="rules_only">Rules only (Semgrep / Gitleaks / OSV)</option>
                      <option value="rules_plus_ai">Rules + AI review (Groq)</option>
                    </select>
                  </label>
                  <label>
                    Target override
                    <input
                      value={draftTarget}
                      onChange={(e) => setDraftTarget(e.target.value)}
                      placeholder={project.github_repo_full_name || "Target (optional)"}
                      maxLength={512}
                    />
                  </label>
                  <div className="scan-notify">
                    <p className="scan-notify-label">Notify when finished</p>
                    <div className="scan-notify-options">
                      <label className="check">
                        <input
                          type="checkbox"
                          checked={draftNotifyInApp}
                          onChange={(e) => setDraftNotifyInApp(e.target.checked)}
                        />
                        In-app
                      </label>
                      <label className="check">
                        <input
                          type="checkbox"
                          checked={draftNotifyEmail}
                          onChange={(e) => setDraftNotifyEmail(e.target.checked)}
                        />
                        Email
                      </label>
                    </div>
                  </div>
                </div>
                <div className="modal-actions">
                  <button type="button" className="btn ghost" onClick={closeAdvanced}>
                    Cancel
                  </button>
                  <button type="button" className="btn" onClick={askSaveAdvanced}>
                    Save
                  </button>
                </div>
              </div>
            </div>,
            document.body,
          )
        : null}

      {advancedConfirmOpen
        ? createPortal(
            <div className="modal-root" role="presentation" style={{ zIndex: 90 }}>
              <button
                type="button"
                className="modal-backdrop"
                aria-label="Close dialog"
                onClick={() => setAdvancedConfirmOpen(false)}
              />
              <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="scan-advanced-confirm-title">
                <div className="modal-head">
                  <div>
                    <p className="modal-kicker">Scan</p>
                    <h2 id="scan-advanced-confirm-title">Save advanced options?</h2>
                  </div>
                  <button
                    type="button"
                    className="modal-close"
                    aria-label="Close"
                    onClick={() => setAdvancedConfirmOpen(false)}
                  >
                    <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M18 6 6 18M6 6l12 12" />
                    </svg>
                  </button>
                </div>
                <p className="modal-copy">
                  Apply {draftMode === "rules_plus_ai" ? "rules + AI" : "rules-only"}
                  {" · "}
                  <strong>{draftTarget.trim() || project.github_repo_full_name || "default target"}</strong>
                  {" · notify "}
                  {[draftNotifyInApp ? "in-app" : null, draftNotifyEmail ? "email" : null].filter(Boolean).join(" + ") || "none"}
                  .
                </p>
                <div className="modal-actions">
                  <button type="button" className="btn ghost" onClick={() => setAdvancedConfirmOpen(false)}>
                    Cancel
                  </button>
                  <button type="button" className="btn" onClick={saveAdvanced}>
                    Confirm save
                  </button>
                </div>
              </div>
            </div>,
            document.body,
          )
        : null}

      {confirmOpen
        ? createPortal(
            <div className="modal-root" role="presentation">
              <button type="button" className="modal-backdrop" aria-label="Close dialog" onClick={() => setConfirmOpen(false)} />
              <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="scan-confirm-title">
                <div className="modal-head">
                  <div>
                    <p className="modal-kicker">Scan</p>
                    <h2 id="scan-confirm-title">Start this scan?</h2>
                  </div>
                  <button type="button" className="modal-close" aria-label="Close" onClick={() => setConfirmOpen(false)}>
                    <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M18 6 6 18M6 6l12 12" />
                    </svg>
                  </button>
                </div>
                <p className="modal-copy">
                  Run {scanMode === "rules_plus_ai" ? "rules + AI" : "rules-only"} analysis on{" "}
                  <strong>{target.trim() || project.github_repo_full_name || "the project target"}</strong>.
                </p>
                <div className="modal-actions">
                  <button type="button" className="btn ghost" onClick={() => setConfirmOpen(false)} disabled={busy}>
                    Cancel
                  </button>
                  <button type="button" className="btn" onClick={() => void startScan()} disabled={busy}>
                    {busy ? "Starting…" : "Confirm scan"}
                  </button>
                </div>
              </div>
            </div>,
            document.body,
          )
        : null}

      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}

      {!scans.length ? (
        <div className="empty-state">
          <strong>No scans yet</strong>
          Start a scan to run Semgrep / secrets / dependency checks on the linked repo.
        </div>
      ) : (
        <div className="scan-table-wrap">
          <table className="scan-table">
            <colgroup>
              <col className="col-target" />
              <col className="col-git" />
              <col className="col-mode" />
              <col className="col-status" />
              <col className="col-eta" />
              <col className="col-findings" />
              <col className="col-started" />
              <col className="col-actions" />
            </colgroup>
            <thead>
              <tr>
                <th>Target</th>
                <th>Git</th>
                <th>Mode</th>
                <th>Status</th>
                <th>ETA</th>
                <th>Findings</th>
                <th>Started</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const eta = scan.progress?.eta_remaining_seconds ?? scan.eta_seconds;
                const pct = scan.progress?.percent;
                const progressLabel = scanProgressLabel(scan.progress, scan.status);
                const scanning = scan.status === "queued" || scan.status === "running";
                const commitHref = githubCommitUrl(
                  project.github_repo_full_name,
                  scan.commit_sha || scan.commit_short,
                );
                return (
                  <tr key={scan.id} className={selectedScanId === scan.id ? "selected" : undefined}>
                    <td className="scan-target">
                      <b title={scan.target}>{scan.target}</b>
                    </td>
                    <td className="muted scan-git" title={scan.commit_sha || undefined}>
                      {scanning && !scan.commit_short ? (
                        <LoadingMark variant="scan" size="xs" label="" />
                      ) : scan.commit_short && commitHref ? (
                        <a
                          className="scan-git-link"
                          href={commitHref}
                          target="_blank"
                          rel="noreferrer"
                          title={`Open ${scan.commit_short} on GitHub`}
                        >
                          {scan.commit_short}
                        </a>
                      ) : (
                        scan.commit_short || "—"
                      )}
                    </td>
                    <td className="muted scan-mode">{(scan.scan_mode || "rules_only").replace(/_/g, " ")}</td>
                    <td className="scan-status">
                      <div className="scan-status-stack">
                        <span className={`badge ${scan.status}`}>{formatStatus(scan.status)}</span>
                        {progressLabel && scanning ? (
                          <span className="muted small scan-progress-line">
                            {progressLabel}
                            {pct != null && scan.status === "running" ? ` · ${pct}%` : ""}
                          </span>
                        ) : null}
                        {scan.error_message ? (
                          <span className="scan-error-line" title={scan.error_message}>
                            {scan.error_message}
                          </span>
                        ) : null}
                      </div>
                    </td>
                    <td className="muted scan-eta">
                      {scanning
                        ? eta != null
                          ? `~${Math.max(1, Math.round(eta / 60))} min`
                          : "…"
                        : "—"}
                    </td>
                    <td className="scan-findings">
                      {scanning ? (
                        <LoadingMark variant="scan" size="xs" label="" />
                      ) : (
                        (scan.summary?.findings_count ?? "—")
                      )}
                    </td>
                    <td className="muted scan-started">{new Date(scan.created_at).toLocaleString()}</td>
                    <td className="scan-row-actions">
                      <button
                        type="button"
                        className="btn ghost small"
                        onClick={() => {
                          setSelectedScanId(scan.id);
                          setReportOpen(true);
                        }}
                      >
                        Report
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {reportOpen && selected ? (
        <ScanReportModal
          scan={selected}
          findings={findings}
          findingsLoading={findingsLoading}
          projectName={project.name}
          githubRepoFullName={project.github_repo_full_name}
          onClose={() => setReportOpen(false)}
          onShared={(updated) => {
            setScans((prev) => prev.map((s) => (s.id === updated.id ? { ...s, ...updated } : s)));
          }}
        />
      ) : null}
    </main>
  );
}
