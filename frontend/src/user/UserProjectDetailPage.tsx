import { useEffect, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { Link, useNavigate, useParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import type { GitRef, Project, Scan } from "../lib/workspace";
import { ProjectSwitcher } from "./ProjectSwitcher";
import { ScanHistoryList } from "./ScanHistoryList";
import { useDocumentTitle } from "../lib/documentTitle";

/** Project-scoped scans with Mode A/B, ETA, and Render-style history. */
export function UserProjectDetailPage() {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [target, setTarget] = useState("");
  const [scanMode, setScanMode] = useState<"rules_only" | "rules_plus_ai">("rules_only");
  const [scanScope, setScanScope] = useState<"full" | "changed">("full");
  const [scanRef, setScanRef] = useState("");
  const [gitRefs, setGitRefs] = useState<GitRef[]>([]);
  const [notifyEmail, setNotifyEmail] = useState(true);
  const [notifyInApp, setNotifyInApp] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [advancedConfirmOpen, setAdvancedConfirmOpen] = useState(false);
  const [draftMode, setDraftMode] = useState<"rules_only" | "rules_plus_ai">("rules_only");
  const [draftScope, setDraftScope] = useState<"full" | "changed">("full");
  const [draftRef, setDraftRef] = useState("");
  const [draftTarget, setDraftTarget] = useState("");
  const [draftNotifyEmail, setDraftNotifyEmail] = useState(true);
  const [draftNotifyInApp, setDraftNotifyInApp] = useState(true);
  const [draftAutoScan, setDraftAutoScan] = useState(false);
  const [draftAutoBranch, setDraftAutoBranch] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ghNeedsReauth, setGhNeedsReauth] = useState(false);
  const [advancedBusy, setAdvancedBusy] = useState(false);

  useDocumentTitle(project ? `${project.name} · Scans` : "Scans");

  async function load() {
    if (!projectId) return;
    const [proj, scanData, gh] = await Promise.all([
      api<{ project: Project }>(`/workspace/projects/${projectId}`),
      api<{ items: Scan[] }>(`/workspace/projects/${projectId}/scans`),
      api<{ needs_reauth?: boolean; connected?: boolean }>("/workspace/github/status").catch(() => ({
        needs_reauth: false,
        connected: false,
      })),
    ]);
    setProject(proj.project);
    setScans(scanData.items);
    setGhNeedsReauth(!!gh.needs_reauth);
    if (proj.project.notify_email_default != null) setNotifyEmail(!!proj.project.notify_email_default);
    if (proj.project.notify_in_app_default != null) setNotifyInApp(!!proj.project.notify_in_app_default);
    if (proj.project.github_default_branch && !scanRef) {
      setScanRef(proj.project.github_default_branch);
    }
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

  async function startScan() {
    if (!projectId) return;
    setConfirmOpen(false);
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        scan_mode: scanMode,
        scan_scope: scanScope,
        notify_email: notifyEmail,
        notify_in_app: notifyInApp,
      };
      if (target.trim()) body.target = target.trim();
      if (scanRef.trim()) body.ref = scanRef.trim();
      const res = await api<{ scan: Scan }>(`/workspace/projects/${projectId}/scans`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      setTarget("");
      await load();
      navigate(`/user/projects/${projectId}/scans/${res.scan.id}`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function cancelScan(scanId: string) {
    try {
      await api(`/workspace/scans/${scanId}/cancel`, { method: "POST" });
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  function onAskScan(e: FormEvent) {
    e.preventDefault();
    if (!projectId || busy) return;
    setConfirmOpen(true);
  }

  function openAdvanced() {
    setDraftMode(scanMode);
    setDraftScope(scanScope);
    setDraftRef(scanRef || project?.github_default_branch || "");
    setDraftTarget(target);
    setDraftNotifyEmail(notifyEmail);
    setDraftNotifyInApp(notifyInApp);
    setDraftAutoScan(!!project?.auto_scan_on_push);
    setDraftAutoBranch(
      project?.auto_scan_branch || project?.github_default_branch || "",
    );
    setShowAdvanced(true);
    if (projectId && project?.github_repo_full_name) {
      api<{ branches: GitRef[]; tags: GitRef[] }>(`/workspace/projects/${projectId}/git-refs`)
        .then((data) => setGitRefs([...(data.branches || []), ...(data.tags || [])]))
        .catch(() => setGitRefs([]));
    }
  }

  function closeAdvanced() {
    setAdvancedConfirmOpen(false);
    setShowAdvanced(false);
  }

  function askSaveAdvanced() {
    setAdvancedConfirmOpen(true);
  }

  async function saveAdvanced() {
    if (!projectId || !project) return;
    setAdvancedBusy(true);
    setError(null);
    try {
      const autoChanged =
        draftAutoScan !== !!project.auto_scan_on_push ||
        (draftAutoBranch || "") !== (project.auto_scan_branch || project.github_default_branch || "");
      if (autoChanged && project.github_repo_full_name) {
        const res = await api<{ project: Project }>(`/workspace/projects/${projectId}`, {
          method: "PATCH",
          body: JSON.stringify({
            auto_scan_on_push: draftAutoScan,
            auto_scan_branch: draftAutoBranch.trim() || project.github_default_branch || null,
          }),
        });
        setProject(res.project);
      }
      setScanMode(draftMode);
      setScanScope(draftScope);
      setScanRef(draftRef);
      setTarget(draftTarget);
      setNotifyEmail(draftNotifyEmail);
      setNotifyInApp(draftNotifyInApp);
      setAdvancedConfirmOpen(false);
      setShowAdvanced(false);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setAdvancedBusy(false);
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

  const autoBranchLabel =
    project.auto_scan_branch || project.github_default_branch || "default branch";
  const branchOptions = gitRefs.filter((r) => r.type === "branch" || !r.type);

  return (
    <main className="admin-main">
      <header className="admin-header project-detail-header">
        <div>
          <div className="eyebrow">
            <Link to="/user/projects">Projects</Link>
            <span aria-hidden="true"> / </span>
            Scans
          </div>
          <h1>Scans</h1>
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
            {project.auto_scan_on_push ? (
              <>
                {" "}
                · Auto-scan on <code>{autoBranchLabel}</code>
              </>
            ) : null}
          </p>
        </div>
        <ProjectSwitcher current={project} compact menuAlign="right" />
      </header>

      {ghNeedsReauth ? (
        <div className="notice warning" role="status">
          Reconnect GitHub — authorization expired or missing repo scope.{" "}
          <Link to="/user/projects/new">Reconnect on New project</Link>
        </div>
      ) : null}

      <section className="scan-start-panel">
        <div className="scan-start-main">
          <h2>Start scan</h2>
          <p className="muted scan-start-summary">
            {scanMode === "rules_plus_ai" ? "Rules + AI" : "Rules only"}
            {" · "}
            {scanScope === "changed" ? "Changed files" : "Full tree"}
            {" · "}
            {scanRef.trim() || project.github_default_branch || "default branch"}
            {" · "}
            {target.trim() || project.github_repo_full_name || "No target set"}
          </p>
        </div>
        <form className="scan-actions" onSubmit={onAskScan}>
          <button className="btn" type="submit" disabled={busy || ghNeedsReauth}>
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
                    Branch or tag (this scan)
                    <select value={draftRef} onChange={(e) => setDraftRef(e.target.value)}>
                      <option value={project.github_default_branch || ""}>
                        {project.github_default_branch || "default"} (default)
                      </option>
                      {gitRefs
                        .filter((r) => r.name !== project.github_default_branch)
                        .map((r) => (
                          <option key={`${r.type}:${r.name}`} value={r.name}>
                            {r.name} ({r.type})
                          </option>
                        ))}
                    </select>
                  </label>
                  <label>
                    Scope
                    <select value={draftScope} onChange={(e) => setDraftScope(e.target.value as "full" | "changed")}>
                      <option value="full">Full repository</option>
                      <option value="changed">Changed files only</option>
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

                  {project.github_repo_full_name ? (
                    <div className="scan-advanced-autoscan">
                      <p className="scan-notify-label">Auto-scan on push</p>
                      <label className="check">
                        <input
                          type="checkbox"
                          checked={draftAutoScan}
                          disabled={ghNeedsReauth}
                          onChange={(e) => setDraftAutoScan(e.target.checked)}
                        />
                        Run a scan when commits land on the watched branch
                      </label>
                      <label>
                        Watched branch
                        <select
                          value={draftAutoBranch}
                          disabled={!draftAutoScan || ghNeedsReauth}
                          onChange={(e) => setDraftAutoBranch(e.target.value)}
                        >
                          <option value={project.github_default_branch || ""}>
                            {project.github_default_branch || "default"} (default)
                          </option>
                          {branchOptions
                            .filter((r) => r.name !== project.github_default_branch)
                            .map((r) => (
                              <option key={`auto:${r.name}`} value={r.name}>
                                {r.name}
                              </option>
                            ))}
                        </select>
                      </label>
                    </div>
                  ) : null}
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
                  {draftScope === "changed" ? "changed files" : "full tree"}
                  {" · "}
                  <strong>{draftRef.trim() || project.github_default_branch || "default branch"}</strong>
                  {" · "}
                  <strong>{draftTarget.trim() || project.github_repo_full_name || "default target"}</strong>
                  {" · notify "}
                  {[draftNotifyInApp ? "in-app" : null, draftNotifyEmail ? "email" : null].filter(Boolean).join(" + ") || "none"}
                  {project.github_repo_full_name ? (
                    <>
                      {" · auto-scan "}
                      <strong>
                        {draftAutoScan ? `on ${draftAutoBranch || project.github_default_branch || "branch"}` : "off"}
                      </strong>
                    </>
                  ) : null}
                  .
                </p>
                <div className="modal-actions">
                  <button type="button" className="btn ghost" onClick={() => setAdvancedConfirmOpen(false)} disabled={advancedBusy}>
                    Cancel
                  </button>
                  <button type="button" className="btn" onClick={() => void saveAdvanced()} disabled={advancedBusy}>
                    {advancedBusy ? "Saving…" : "Confirm save"}
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
                  Run {scanMode === "rules_plus_ai" ? "rules + AI" : "rules-only"}{" "}
                  ({scanScope === "changed" ? "changed files" : "full tree"}) on{" "}
                  <strong>{target.trim() || project.github_repo_full_name || "the project target"}</strong>
                  {scanRef.trim() ? (
                    <>
                      {" "}
                      at <strong>{scanRef.trim()}</strong>
                    </>
                  ) : null}
                  .
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

      <ScanHistoryList
        scans={scans}
        projectId={projectId}
        onCancel={(id) => void cancelScan(id)}
      />
    </main>
  );
}
