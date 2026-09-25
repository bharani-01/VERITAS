import { useEffect, useRef, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { Link, useNavigate, useParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { api } from "../lib/api";
import { useDocumentTitle } from "../lib/documentTitle";
import type { GitRef, Project, Scan } from "../lib/workspace";
import { ProjectSwitcher } from "./ProjectSwitcher";
import { ScanHistoryList } from "./ScanHistoryList";

/** Project-scoped scans — flat layout, inline Advanced (no gear modal). */
export function UserProjectDetailPage() {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [enteringScanIds, setEnteringScanIds] = useState<string[]>([]);
  const [target, setTarget] = useState("");
  const [scanMode, setScanMode] = useState<"rules_only" | "rules_plus_ai">("rules_only");
  const [scanScope, setScanScope] = useState<"full" | "changed">("full");
  const [securityLevel, setSecurityLevel] = useState<"basic" | "standard" | "strict">("standard");
  const [engines, setEngines] = useState({ gitleaks: true, osv: true, semgrep: true });
  const [pathExcludes, setPathExcludes] = useState("node_modules/**\nvendor/**\ndist/**");
  const [failSeverity, setFailSeverity] = useState<"off" | "critical" | "high" | "medium">("off");
  const [scanRef, setScanRef] = useState("");
  const [gitRefs, setGitRefs] = useState<GitRef[]>([]);
  const [notifyEmail, setNotifyEmail] = useState(true);
  const [notifyInApp, setNotifyInApp] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [autoScan, setAutoScan] = useState(false);
  const [autoBranch, setAutoBranch] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ghNeedsReauth, setGhNeedsReauth] = useState(false);
  const [advancedBusy, setAdvancedBusy] = useState(false);
  const [advancedSaved, setAdvancedSaved] = useState(false);
  const [refsLoading, setRefsLoading] = useState(false);
  const knownScanIdsRef = useRef<Set<string>>(new Set());
  const initialScansLoadedRef = useRef(false);
  const enterTimersRef = useRef<number[]>([]);

  useDocumentTitle(project ? `${project.name} · Scans` : "Scans");

  async function load(opts?: { hydrateForm?: boolean }) {
    if (!projectId) return;
    const hydrateForm = !!opts?.hydrateForm;
    const [proj, scanData, gh] = await Promise.all([
      api<{ project: Project }>(`/workspace/projects/${projectId}`),
      api<{ items: Scan[] }>(`/workspace/projects/${projectId}/scans`),
      api<{ needs_reauth?: boolean; connected?: boolean }>("/workspace/github/status").catch(() => ({
        needs_reauth: false,
        connected: false,
      })),
    ]);
    setProject(proj.project);
    const items = scanData.items;
    if (!initialScansLoadedRef.current) {
      knownScanIdsRef.current = new Set(items.map((s) => s.id));
      initialScansLoadedRef.current = true;
      setScans(items);
    } else {
      const fresh = items.filter((s) => !knownScanIdsRef.current.has(s.id)).map((s) => s.id);
      knownScanIdsRef.current = new Set(items.map((s) => s.id));
      setScans(items);
      if (fresh.length) {
        setEnteringScanIds((prev) => [...new Set([...fresh, ...prev])]);
        const timer = window.setTimeout(() => {
          setEnteringScanIds((prev) => prev.filter((id) => !fresh.includes(id)));
        }, 700);
        enterTimersRef.current.push(timer);
      }
    }
    setGhNeedsReauth(!!gh.needs_reauth);
    // Only hydrate editable Advanced / notify fields on first load (or after save).
    // Polling must not wipe in-progress form edits.
    if (hydrateForm) {
      if (proj.project.notify_email_default != null) setNotifyEmail(!!proj.project.notify_email_default);
      if (proj.project.notify_in_app_default != null) setNotifyInApp(!!proj.project.notify_in_app_default);
      setAutoScan(!!proj.project.auto_scan_on_push);
      setAutoBranch(proj.project.auto_scan_branch || proj.project.github_default_branch || "");
      if (proj.project.security_level === "basic" || proj.project.security_level === "strict") {
        setSecurityLevel(proj.project.security_level);
      } else {
        setSecurityLevel("standard");
      }
      if (proj.project.github_default_branch && !scanRef) {
        setScanRef(proj.project.github_default_branch);
      }
    }
  }

  useEffect(() => {
    initialScansLoadedRef.current = false;
    knownScanIdsRef.current = new Set();
    setEnteringScanIds([]);
    setScans([]);
    setProject(null);
    load({ hydrateForm: true }).catch((err: Error) => setError(err.message));
    return () => {
      enterTimersRef.current.forEach((t) => window.clearTimeout(t));
      enterTimersRef.current = [];
    };
  }, [projectId]);

  useEffect(() => {
    if (!projectId) return;
    const active = scans.some((s) => s.status === "queued" || s.status === "running");
    const ms = active ? 1200 : 3000;
    const id = window.setInterval(() => {
      if (document.visibilityState === "hidden") return;
      load({ hydrateForm: false }).catch(() => undefined);
    }, ms);
    return () => window.clearInterval(id);
  }, [scans, projectId]);

  useEffect(() => {
    if (!showAdvanced || !projectId || !project?.github_repo_full_name) return;
    let cancelled = false;
    setRefsLoading(true);
    api<{ branches: GitRef[]; tags: GitRef[] }>(`/workspace/projects/${projectId}/git-refs`)
      .then((data) => {
        if (!cancelled) setGitRefs([...(data.branches || []), ...(data.tags || [])]);
      })
      .catch(() => {
        if (!cancelled) setGitRefs([]);
      })
      .finally(() => {
        if (!cancelled) setRefsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [showAdvanced, projectId, project?.github_repo_full_name]);

  async function startScan() {
    if (!projectId) return;
    setConfirmOpen(false);
    setBusy(true);
    setError(null);
    try {
      const selectedEngines = (["gitleaks", "osv", "semgrep"] as const).filter((e) => engines[e]);
      if (!selectedEngines.length) {
        setError("Select at least one engine.");
        setBusy(false);
        return;
      }
      const body: Record<string, unknown> = {
        scan_mode: scanMode,
        scan_scope: scanScope,
        security_level: securityLevel,
        notify_email: notifyEmail,
        notify_in_app: notifyInApp,
        engines: selectedEngines,
        path_excludes: pathExcludes
          .split(/[\n,]+/)
          .map((s) => s.trim())
          .filter(Boolean)
          .slice(0, 40),
        fail_severity: failSeverity,
        code_review: scanMode === "rules_plus_ai",
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

  async function saveAdvanced() {
    if (!projectId || !project) return;
    setAdvancedBusy(true);
    setError(null);
    setAdvancedSaved(false);
    try {
      const patch: Record<string, unknown> = {};
      if (securityLevel !== (project.security_level || "standard")) {
        patch.security_level = securityLevel;
      }
      const autoChanged =
        autoScan !== !!project.auto_scan_on_push ||
        (autoBranch || "") !== (project.auto_scan_branch || project.github_default_branch || "");
      if (autoChanged && project.github_repo_full_name) {
        patch.auto_scan_on_push = autoScan;
        patch.auto_scan_branch = autoBranch.trim() || project.github_default_branch || null;
      }
      if (Object.keys(patch).length) {
        const res = await api<{ project: Project }>(`/workspace/projects/${projectId}`, {
          method: "PATCH",
          body: JSON.stringify(patch),
        });
        setProject(res.project);
        setAutoScan(!!res.project.auto_scan_on_push);
        setAutoBranch(res.project.auto_scan_branch || res.project.github_default_branch || "");
        if (res.project.security_level === "basic" || res.project.security_level === "strict") {
          setSecurityLevel(res.project.security_level);
        } else if (patch.security_level) {
          setSecurityLevel("standard");
        }
      }
      setAdvancedSaved(true);
      window.setTimeout(() => setAdvancedSaved(false), 2500);
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

  const autoBranchLabel = project.auto_scan_branch || project.github_default_branch || "default branch";
  const branchOptions = gitRefs.filter((r) => r.type === "branch" || !r.type);
  const defaultBranch = project.github_default_branch || "main";

  return (
    <main className="admin-main project-detail-page">
      <div className="projects-wrap">
        <header className="new-project-header project-detail-header">
          <div className="projects-header-row">
            <div>
              <nav className="new-project-crumb" aria-label="Breadcrumb">
                <Link to="/user/projects">Projects</Link>
                <span aria-hidden="true">/</span>
                <span>{project.name}</span>
              </nav>
              <h1>{project.name}</h1>
              <p>
                {project.description || "Run security scans and review findings for this repository."}
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
          </div>
        </header>

        {ghNeedsReauth ? (
          <div className="notice warning" role="status">
            Reconnect GitHub — authorization expired or missing repo scope.{" "}
            <Link to="/user/projects/new">Reconnect on New project</Link>
          </div>
        ) : null}

        {error ? (
          <div className="notice error" role="alert">
            {error}
          </div>
        ) : null}

        <section className="np-block rr-row scan-start-block">
          <div className="rr-meta">
            <h2 className="rr-title">Start scan</h2>
            <p className="scan-start-summary">
              {securityLevel}
              {" · "}
              {scanMode === "rules_plus_ai" ? "Rules + AI" : "Rules only"}
              {" · "}
              {scanScope === "changed" ? "Changed files" : "Full tree"}
              {" · "}
              <code>{scanRef.trim() || defaultBranch}</code>
              {failSeverity !== "off" ? ` · Fail ≥ ${failSeverity}` : ""}
              {target.trim() ? (
                <>
                  {" · "}
                  {target.trim()}
                </>
              ) : null}
            </p>
          </div>
          <div className="rr-controls">
            <form className="scan-actions" onSubmit={onAskScan}>
              <button className="btn" type="submit" disabled={busy || ghNeedsReauth}>
                {busy ? "Starting…" : "Scan now"}
              </button>
              <button
                type="button"
                className="btn ghost"
                aria-expanded={showAdvanced}
                onClick={() => setShowAdvanced((v) => !v)}
              >
                {showAdvanced ? "Hide advanced" : "Advanced"}
              </button>
            </form>
          </div>
        </section>

        {showAdvanced ? (
          <>
            <section className="np-block rr-row">
              <div className="rr-meta">
                <h2 className="rr-title">Scan depth</h2>
                <p>Controls Semgrep rule packs (Basic faster, Strict deepest).</p>
              </div>
              <div className="rr-controls">
                <div className="np-choice-row" role="radiogroup" aria-label="Scan depth">
                  {(["basic", "standard", "strict"] as const).map((level) => (
                    <label key={level} className={`np-choice ${securityLevel === level ? "is-selected" : ""}`}>
                      <input
                        type="radio"
                        name="security-level"
                        checked={securityLevel === level}
                        onChange={() => setSecurityLevel(level)}
                      />
                      <span>
                        <strong>{level[0].toUpperCase() + level.slice(1)}</strong>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            </section>

            <section className="np-block rr-row">
              <div className="rr-meta">
                <h2 className="rr-title">Engines</h2>
                <p>Pick Secrets, Dependencies (SCA), and/or Code (SAST). At least one required.</p>
              </div>
              <div className="rr-controls">
                <div className="np-check-row">
                  <label className="np-check">
                    <input
                      type="checkbox"
                      checked={engines.gitleaks}
                      onChange={(e) => setEngines((v) => ({ ...v, gitleaks: e.target.checked }))}
                    />
                    <span>Secrets</span>
                  </label>
                  <label className="np-check">
                    <input
                      type="checkbox"
                      checked={engines.osv}
                      onChange={(e) => setEngines((v) => ({ ...v, osv: e.target.checked }))}
                    />
                    <span>Dependencies</span>
                  </label>
                  <label className="np-check">
                    <input
                      type="checkbox"
                      checked={engines.semgrep}
                      onChange={(e) => setEngines((v) => ({ ...v, semgrep: e.target.checked }))}
                    />
                    <span>Code</span>
                  </label>
                </div>
              </div>
            </section>

            <section className="np-block rr-row">
              <div className="rr-meta">
                <h2 className="rr-title">Scan mode</h2>
                <p>Rules only runs selected engines. Rules + AI adds OpenRouter code review and a Groq final report.</p>
              </div>
              <div className="rr-controls">
                <div className="np-choice-row" role="radiogroup" aria-label="Scan mode">
                  <label className={`np-choice ${scanMode === "rules_only" ? "is-selected" : ""}`}>
                    <input
                      type="radio"
                      name="scan-mode"
                      checked={scanMode === "rules_only"}
                      onChange={() => setScanMode("rules_only")}
                    />
                    <span>
                      <strong>Rules only</strong>
                      <span className="np-check-sub">Engines only</span>
                    </span>
                  </label>
                  <label className={`np-choice ${scanMode === "rules_plus_ai" ? "is-selected" : ""}`}>
                    <input
                      type="radio"
                      name="scan-mode"
                      checked={scanMode === "rules_plus_ai"}
                      onChange={() => setScanMode("rules_plus_ai")}
                    />
                    <span>
                      <strong>Rules + AI</strong>
                      <span className="np-check-sub">OpenRouter review + Groq report</span>
                    </span>
                  </label>
                </div>
              </div>
            </section>

            <section className="np-block rr-row">
              <div className="rr-meta">
                <h2 className="rr-title">Path excludes</h2>
                <p>One pattern per line (e.g. node_modules/**). Applied to SAST / AI review.</p>
              </div>
              <div className="rr-controls">
                <label className="np-field">
                  <span className="sr-only">Path excludes</span>
                  <textarea
                    className="np-input np-textarea"
                    rows={3}
                    value={pathExcludes}
                    onChange={(e) => setPathExcludes(e.target.value)}
                    placeholder={"node_modules/**\nvendor/**"}
                  />
                </label>
              </div>
            </section>

            <section className="np-block rr-row">
              <div className="rr-meta">
                <h2 className="rr-title">Severity policy</h2>
                <p>Mark the scan failed if any open finding meets or exceeds this severity.</p>
              </div>
              <div className="rr-controls">
                <label className="np-field">
                  <span className="sr-only">Fail severity</span>
                  <select
                    className="np-input"
                    value={failSeverity}
                    onChange={(e) => setFailSeverity(e.target.value as typeof failSeverity)}
                  >
                    <option value="off">Off</option>
                    <option value="critical">Fail if ≥ critical</option>
                    <option value="high">Fail if ≥ high</option>
                    <option value="medium">Fail if ≥ medium</option>
                  </select>
                </label>
              </div>
            </section>

            <section className="np-block rr-row">
              <div className="rr-meta">
                <h2 className="rr-title">Branch or tag</h2>
                <p>Applies to the next Scan now — not a project default.</p>
              </div>
              <div className="rr-controls">
                <label className="np-field">
                  <span className="sr-only">Branch or tag</span>
                  <select
                    className="np-input"
                    value={scanRef || defaultBranch}
                    disabled={refsLoading}
                    onChange={(e) => setScanRef(e.target.value)}
                  >
                    <option value={defaultBranch}>{defaultBranch} (default)</option>
                    {gitRefs
                      .filter((r) => r.name !== defaultBranch)
                      .map((r) => (
                        <option key={`${r.type}:${r.name}`} value={r.name}>
                          {r.name} ({r.type})
                        </option>
                      ))}
                  </select>
                </label>
              </div>
            </section>

            <section className="np-block rr-row">
              <div className="rr-meta">
                <h2 className="rr-title">Scope</h2>
                <p>Full tree or only files changed vs the default branch.</p>
              </div>
              <div className="rr-controls">
                <div className="np-choice-row" role="radiogroup" aria-label="Scan scope">
                  <label className={`np-choice ${scanScope === "full" ? "is-selected" : ""}`}>
                    <input
                      type="radio"
                      name="scan-scope"
                      checked={scanScope === "full"}
                      onChange={() => setScanScope("full")}
                    />
                    <span>
                      <strong>Full repository</strong>
                      <span className="np-check-sub">Entire tree at the selected ref</span>
                    </span>
                  </label>
                  <label className={`np-choice ${scanScope === "changed" ? "is-selected" : ""}`}>
                    <input
                      type="radio"
                      name="scan-scope"
                      checked={scanScope === "changed"}
                      onChange={() => setScanScope("changed")}
                    />
                    <span>
                      <strong>Changed files only</strong>
                      <span className="np-check-sub">Faster diff-scoped pass</span>
                    </span>
                  </label>
                </div>
              </div>
            </section>

            <section className="np-block rr-row">
              <div className="rr-meta">
                <h2 className="rr-title">Target override</h2>
                <p>Leave blank to scan the linked repository.</p>
              </div>
              <div className="rr-controls">
                <label className="np-field">
                  <span className="sr-only">Target</span>
                  <input
                    className="np-input"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder={project.github_repo_full_name || "Optional path or URL"}
                    maxLength={512}
                  />
                </label>
              </div>
            </section>

            <section className="np-block rr-row">
              <div className="rr-meta">
                <h2 className="rr-title">Notify when finished</h2>
                <p>Choose how you hear about scan completion.</p>
              </div>
              <div className="rr-controls">
                <div className="np-check-row">
                  <label className="np-check">
                    <input
                      type="checkbox"
                      checked={notifyInApp}
                      onChange={(e) => setNotifyInApp(e.target.checked)}
                    />
                    <span>In-app</span>
                  </label>
                  <label className="np-check">
                    <input
                      type="checkbox"
                      checked={notifyEmail}
                      onChange={(e) => setNotifyEmail(e.target.checked)}
                    />
                    <span>Email</span>
                  </label>
                </div>
              </div>
            </section>

            {project.github_repo_full_name ? (
              <section className="np-block rr-row">
                <div className="rr-meta">
                  <h2 className="rr-title">Auto-scan on push</h2>
                  <p>Webhook scans when commits land on the watched branch.</p>
                </div>
                <div className="rr-controls">
                  <label className="np-check">
                    <input
                      type="checkbox"
                      checked={autoScan}
                      disabled={ghNeedsReauth}
                      onChange={(e) => setAutoScan(e.target.checked)}
                    />
                    <span>
                      <strong>Enable auto-scan</strong>
                      <span className="np-check-sub">Saved to this project when you apply below</span>
                    </span>
                  </label>
                  <label className={`np-field ${autoScan ? "" : "is-dimmed"}`}>
                    <span>Watched branch</span>
                    <select
                      className="np-input"
                      value={autoBranch || defaultBranch}
                      disabled={!autoScan || ghNeedsReauth || refsLoading}
                      onChange={(e) => setAutoBranch(e.target.value)}
                    >
                      <option value={defaultBranch}>{defaultBranch} (default)</option>
                      {branchOptions
                        .filter((r) => r.name !== defaultBranch)
                        .map((r) => (
                          <option key={`auto:${r.name}`} value={r.name}>
                            {r.name}
                          </option>
                        ))}
                    </select>
                  </label>
                  <div className="np-advanced-foot">
                    <button
                      type="button"
                      className="btn ghost"
                      disabled={advancedBusy || ghNeedsReauth}
                      onClick={() => void saveAdvanced()}
                    >
                      {advancedBusy ? "Saving…" : advancedSaved ? "Saved" : "Save auto-scan settings"}
                    </button>
                  </div>
                </div>
              </section>
            ) : null}
          </>
        ) : null}

        {confirmOpen
          ? createPortal(
              <div className="modal-root" role="presentation">
                <button
                  type="button"
                  className="modal-backdrop"
                  aria-label="Close dialog"
                  onClick={() => setConfirmOpen(false)}
                />
                <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="scan-confirm-title">
                  <div className="modal-head">
                    <div>
                      <p className="modal-kicker">Scan</p>
                      <h2 id="scan-confirm-title">Start this scan?</h2>
                    </div>
                    <button
                      type="button"
                      className="modal-close"
                      aria-label="Close"
                      onClick={() => setConfirmOpen(false)}
                    >
                      <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M18 6 6 18M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  <p className="modal-copy">
                    Run {scanMode === "rules_plus_ai" ? "rules + AI" : "rules-only"} (
                    {scanScope === "changed" ? "changed files" : "full tree"}) on{" "}
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
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() => setConfirmOpen(false)}
                      disabled={busy}
                    >
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

        <ScanHistoryList
          scans={scans}
          projectId={projectId}
          enteringIds={enteringScanIds}
          onCancel={(id) => void cancelScan(id)}
        />
      </div>
    </main>
  );
}
