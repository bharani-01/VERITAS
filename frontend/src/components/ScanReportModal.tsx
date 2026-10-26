import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { LoadingMark } from "./LoadingMark";
import { MarkdownReport } from "./MarkdownReport";
import { OrbitLoader } from "./OrbitLoader";
import {
  DeduplicationCalloutBanner,
  FindingQuickFilterBar,
  Phase6AFindingBadges,
} from "./scan/Phase6AFindingBadges";
import { RiskMatrixCard, computeFindingRiskCell, type RiskCellCoord } from "./scan/RiskMatrixCard";
import { ScanSbomTab } from "./scan/ScanSbomTab";
import type { FindingQuickFilter, ScanFindingPhase6A } from "../types/phase6a";
import { api } from "../lib/api";
import { githubBlobUrl, githubCommitUrl } from "../lib/githubLinks";
import { exportScanReport, sortFindingsByRisk, type ExportFormat } from "../lib/reportExport";
import { formatScanDuration, scanTriggerLabel, shortCommit } from "../lib/scanDisplay";
import { scanProgressLabel } from "../lib/scanProgress";
import type { Finding, Scan, ScanComplianceResponse } from "../lib/workspace";


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

function toPhase6AFinding(f: Finding, scanProjectId: string): ScanFindingPhase6A {
  const extra = f as unknown as Partial<ScanFindingPhase6A> & {
    category?: string;
    description?: string;
    line_number?: number;
    owasp?: string;
    code_snippet?: string;
    countermeasure?: string;
    is_suppressed?: boolean;
  };
  return {
    id: f.id,
    scan_id: f.scan_id,
    project_id: scanProjectId,
    engine: f.engine,
    category: extra.category || f.vuln_family || "sast",
    severity: (f.severity as any) || "medium",
    title: f.title,
    description: extra.description || f.message || "",
    file_path: f.file_path || "",
    line_number: extra.line_number ?? f.line_start ?? 0,
    cwe: f.cwe,
    owasp: extra.owasp || f.owasp_category,
    code_snippet: extra.code_snippet || f.snippet,
    countermeasure: extra.countermeasure || "",
    fingerprint: f.fingerprint || String(f.id),
    status: (f.status as any) || "open",
    is_suppressed: Boolean(extra.is_suppressed),
    cve_id: f.cve_id,
    matched_engines: f.matched_engines || [f.engine],
    engine_count: f.engine_count ?? (f.matched_engines ? f.matched_engines.length : 1),
    confidence_level: f.confidence_level ?? "medium",
    epss_score: f.epss_score,
    epss_percentile: f.epss_percentile,
    is_kev: Boolean(f.is_kev),
    kev_due_date: f.kev_due_date,
    effective_priority_score: f.effective_priority_score ?? f.risk_score ?? 0,
    sla_due_at: f.sla_due_at,
    sla_breached: f.sla_breached,
  };
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
  const [activeTab, setActiveTab] = useState<"findings" | "sbom" | "compliance">("findings");
  const [quickFilter, setQuickFilter] = useState<FindingQuickFilter>("all");
  const [compliance, setCompliance] = useState<ScanComplianceResponse | null>(null);
  const [complianceLoading, setComplianceLoading] = useState(false);
  const [complianceError, setComplianceError] = useState<string | null>(null);
  const [matrixCell, setMatrixCell] = useState<RiskCellCoord | null>(null);
  const [fixPlan, setFixPlan] = useState<{
    branch_name: string;
    commit_message: string;
    pr_title: string;
    pr_body: string;
    unified_diff: string;
  } | null>(null);
  const [fixPlanBusy, setFixPlanBusy] = useState(false);

  useEffect(() => {
    if (activeTab !== "compliance" || (scan.status !== "completed" && scan.status !== "succeeded" && scan.status !== "failed") || !scan.project_id || !scan.id) return;
    let cancelled = false;
    setComplianceLoading(true);
    setComplianceError(null);
    api<ScanComplianceResponse>(`/workspace/projects/${scan.project_id}/scans/${scan.id}/compliance`)
      .then((res) => {
        if (!cancelled) setCompliance(res);
      })
      .catch((err: Error) => {
        if (!cancelled) setComplianceError(err.message);
      })
      .finally(() => {
        if (!cancelled) setComplianceLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeTab, scan.status, scan.project_id, scan.id]);

  const exportWrapRef = useRef<HTMLDivElement>(null);
  const exportBtnRef = useRef<HTMLButtonElement>(null);
  const exportMenuRef = useRef<HTMLDivElement>(null);
  const liveLogRef = useRef<HTMLDivElement>(null);

  const sorted = useMemo(() => sortFindingsByRisk(findings), [findings]);
  const phase6aFindings = useMemo(
    () => findings.map((f) => toPhase6AFinding(f, scan.project_id)),
    [findings, scan.project_id],
  );

  const filteredFindings = useMemo(() => {
    let list = sorted;
    if (matrixCell) {
      list = list.filter((f) => {
        const cell = computeFindingRiskCell(f);
        return cell.likelihood === matrixCell.likelihood && cell.impact === matrixCell.impact;
      });
    }
    if (quickFilter === "kev") {
      list = list.filter((f) => f.is_kev);
    } else if (quickFilter === "high_epss") {
      list = list.filter((f) => (f.epss_score ?? 0) >= 0.1);
    } else if (quickFilter === "multi_engine") {
      list = list.filter((f) => (f.engine_count ?? 1) >= 2);
    } else if (quickFilter === "license") {
      list = list.filter(
        (f) =>
          f.vuln_family === "license" ||
          f.engine === "trivy_license" ||
          (f as any).category === "license",
      );
    }
    return list;
  }, [sorted, quickFilter, matrixCell]);
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
    try {
      await navigator.clipboard.writeText(shareUrl);
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
          <button type="button" className="report-back-btn" onClick={onClose}>
            <IconBack />
            <span>{variant === "page" ? "Back to scans" : "Close"}</span>
          </button>
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
            {scan.source ? <div className="muted small">{scanTriggerLabel(scan)}</div> : null}
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
            {scanning ? (
              <div className="report-meta-scanning-risk" title="Assessing risk and counting findings…">
                <OrbitLoader size="sm" />
                <span className="report-meta-scanning-label">
                  {findingsSoFar > 0 ? `${findingsSoFar} finding${findingsSoFar === 1 ? "" : "s"} so far` : "Assessing…"}
                </span>
              </div>
            ) : (
              <>
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
              </>
            )}
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
          <MarkdownReport source={aiReport} className="ai-report-body" />
        </div>
      ) : null}

      <div className="report-findings modal-body-pad">
        {/* Tab switcher: Findings vs SBOM */}
        <div
          style={{
            display: "flex",
            gap: "8px",
            borderBottom: "1px solid var(--line, #e2e8f0)",
            marginBottom: "16px",
          }}
        >
          <button
            type="button"
            className={`btn ghost ${activeTab === "findings" ? "active" : ""}`}
            onClick={() => setActiveTab("findings")}
            style={{
              borderBottom:
                activeTab === "findings"
                  ? "2.5px solid var(--accent, #2563eb)"
                  : "2.5px solid transparent",
              borderRadius: 0,
              padding: "8px 16px",
              fontWeight: activeTab === "findings" ? 700 : 500,
              color: activeTab === "findings" ? "var(--ink, #0f172a)" : "var(--muted, #64748b)",
              background: "transparent",
            }}
          >
            Findings ({findings.length})
          </button>
          <button
            type="button"
            className={`btn ghost ${activeTab === "sbom" ? "active" : ""}`}
            onClick={() => setActiveTab("sbom")}
            style={{
              borderBottom:
                activeTab === "sbom"
                  ? "2.5px solid var(--accent, #2563eb)"
                  : "2.5px solid transparent",
              borderRadius: 0,
              padding: "8px 16px",
              fontWeight: activeTab === "sbom" ? 700 : 500,
              color: activeTab === "sbom" ? "var(--ink, #0f172a)" : "var(--muted, #64748b)",
              background: "transparent",
            }}
          >
            SBOM &amp; Licenses
          </button>
          <button
            type="button"
            className={`btn ghost ${activeTab === "compliance" ? "active" : ""}`}
            onClick={() => setActiveTab("compliance")}
            style={{
              borderBottom:
                activeTab === "compliance"
                  ? "2.5px solid var(--accent, #2563eb)"
                  : "2.5px solid transparent",
              borderRadius: 0,
              padding: "8px 16px",
              fontWeight: activeTab === "compliance" ? 700 : 500,
              color: activeTab === "compliance" ? "var(--ink, #0f172a)" : "var(--muted, #64748b)",
              background: "transparent",
            }}
          >
            Compliance &amp; SLA
          </button>
        </div>

        {activeTab === "compliance" ? (
          <section className="scan-report-section">
            {complianceLoading ? (
              <div className="report-findings-loading">
                <LoadingMark label="Evaluating OWASP Top 10, SOC 2 Type II & ISO 27001 controls…" />
              </div>
            ) : complianceError || !compliance ? (
              <p className="muted small">{complianceError || "Compliance posture unavailable."}</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
                  <div>
                    <h4 style={{ margin: 0 }}>
                      Overall Readiness: {compliance.overall_readiness_score}% · {compliance.overall_verdict}
                    </h4>
                    <span className="muted small">
                      Overdue SLA: {compliance.total_overdue_sla} · Pending Suppressions: {compliance.pending_suppressions_count} · SBOM Verified:{" "}
                      {compliance.sbom_verified ? "Yes" : "No"}
                    </span>
                  </div>
                  <a
                    className="btn primary btn-sm"
                    href={`/workspace/projects/${scan.project_id}/scans/${scan.id}/compliance/export`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Download Audit Certificate (.html / Print PDF)
                  </a>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
                  {(
                    [
                      compliance.frameworks.owasp_top_10,
                      compliance.frameworks.soc2,
                      compliance.frameworks.iso27001,
                    ] as const
                  ).map((fw) => (
                    <div key={fw.name} className="card" style={{ padding: 14, borderTop: "3px solid var(--accent-primary, #3b82f6)" }}>
                      <div className="muted small">{fw.name}</div>
                      <div style={{ fontSize: "1.6rem", fontWeight: 700, margin: "6px 0" }}>{fw.readiness_score}%</div>
                      <div className="muted small">
                        Pass: {fw.pass_count} · Warn: {fw.warn_count} · Fail: {fw.fail_count}
                      </div>
                    </div>
                  ))}
                </div>

                {(
                  [
                    compliance.frameworks.owasp_top_10,
                    compliance.frameworks.soc2,
                    compliance.frameworks.iso27001,
                  ] as const
                ).map((fw) => (
                  <div key={fw.name} style={{ border: "1px solid var(--line, #e2e8f0)", borderRadius: 10, overflow: "hidden", background: "var(--surface, #ffffff)" }}>
                    <div style={{ padding: "10px 14px", background: "var(--bg, #f8fafc)", color: "var(--ink, #0f172a)", borderBottom: "1px solid var(--line, #e2e8f0)", fontWeight: 700 }}>
                      {fw.name} ({fw.verdict})
                    </div>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
                      <thead>
                        <tr style={{ textAlign: "left", borderBottom: "1px solid var(--line, #e2e8f0)", color: "var(--ink-soft, #334155)", background: "var(--bg, #f8fafc)" }}>
                          <th style={{ padding: "8px 12px" }}>Control</th>
                          <th style={{ padding: "8px 12px" }}>Objective</th>
                          <th style={{ padding: "8px 12px" }}>Status</th>
                          <th style={{ padding: "8px 12px" }}>Open Findings</th>
                        </tr>
                      </thead>
                      <tbody>
                        {fw.controls.map((ctrl) => (
                          <tr key={ctrl.control_id} style={{ borderBottom: "1px solid var(--line, #e2e8f0)" }}>
                            <td style={{ padding: "8px 12px" }}>
                              <code>{ctrl.control_id}</code>
                            </td>
                            <td style={{ padding: "8px 12px" }}>
                              <strong>{ctrl.title}</strong>
                              <div className="muted small">{ctrl.description}</div>
                            </td>
                            <td style={{ padding: "8px 12px" }}>
                              <span
                                className={`badge ${
                                  ctrl.status === "pass"
                                    ? "info"
                                    : ctrl.status === "warn"
                                      ? "medium"
                                      : "critical"
                                }`}
                              >
                                {ctrl.status.toUpperCase()}
                              </span>
                            </td>
                            <td style={{ padding: "8px 12px" }}>{ctrl.finding_count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ))}
              </div>
            )}
          </section>
        ) : activeTab === "sbom" ? (
          <ScanSbomTab projectId={scan.project_id} scanId={scan.id} />
        ) : scanning ? null : findingsLoading ? (

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
        ) : (
          <>
            {/* Phase 6A Correlation Callout Banner */}
            {(scan.raw_findings_count && scan.raw_findings_count > (scan.correlated_findings_count ?? findings.length)) ||
            (scan.kev_findings_count ?? 0) > 0 ? (
              <DeduplicationCalloutBanner
                rawCount={scan.raw_findings_count || findings.length}
                correlatedCount={scan.correlated_findings_count || findings.length}
                kevCount={scan.kev_findings_count || 0}
              />
            ) : null}

            {/* 5x5 Quantitative Risk Assessment Matrix */}
            {!scanning && sorted.length > 0 ? (
              <RiskMatrixCard
                findings={sorted}
                selectedCell={matrixCell}
                onSelectCell={setMatrixCell}
              />
            ) : null}

            {/* Quick Filter Bar */}
            <FindingQuickFilterBar
              activeFilter={quickFilter}
              onSelectFilter={setQuickFilter}
              findings={phase6aFindings}
            />

            {!filteredFindings.length ? (
              <div className="empty-state compact">
                {findings.length === 0
                  ? "No findings."
                  : "No findings match the selected quick filter."}
              </div>
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
                  {filteredFindings.map((f) => (
                    <li key={f.id}>
                      <button
                        type="button"
                        className="finding-row-btn"
                        onClick={() => {
                          setSelected(f);
                          setFixPlan(null);
                        }}
                      >
                        <span className={`badge ${f.severity}`}>{f.severity}</span>
                        <span className="finding-row-main">
                          <b>{f.title}</b>
                          <span className="muted small">
                            {f.engine}
                            {f.file_path
                              ? ` · ${f.file_path}${f.line_start ? `:${f.line_start}` : ""}`
                              : ""}
                            {f.ai_verdict ? ` · AI ${f.ai_verdict}` : ""}
                          </span>
                          <Phase6AFindingBadges
                            finding={toPhase6AFinding(f, scan.project_id)}
                          />
                        </span>
                        <span className="finding-row-status">
                          {f.status.replace(/_/g, " ")}
                        </span>
                        <span
                          className="finding-row-risk"
                          title={`Risk Score: ${f.risk_score.toFixed(1)} | Effective Priority Score: ${(f.effective_priority_score ?? f.risk_score).toFixed(1)}`}
                        >
                          {(f.effective_priority_score ?? f.risk_score).toFixed(1)}
                        </span>
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
          </>
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
                  <div style={{ marginTop: "10px", marginBottom: "10px" }}>
                    <Phase6AFindingBadges
                      finding={toPhase6AFinding(selected, scan.project_id)}
                    />
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

                  <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
                    <button
                      type="button"
                      className="btn"
                      disabled={fixPlanBusy}
                      onClick={async () => {
                        setFixPlanBusy(true);
                        try {
                          const plan = await api<{
                            branch_name: string;
                            commit_message: string;
                            pr_title: string;
                            pr_body: string;
                            unified_diff: string;
                          }>(`/workspace/findings/${selected.id}/fix-plan`, { method: "POST" });
                          setFixPlan(plan);
                        } finally {
                          setFixPlanBusy(false);
                        }
                      }}
                    >
                      {fixPlanBusy ? "Generating Patch…" : "Generate Fix Patch / PR"}
                    </button>
                  </div>

                  {fixPlan ? (
                    <div style={{ marginTop: 12, padding: 12, borderRadius: 8, border: "1px solid var(--border-subtle, #1e293b)" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                        <strong>Branch: <code>{fixPlan.branch_name}</code></strong>
                        <button
                          type="button"
                          className="btn ghost"
                          onClick={() => navigator.clipboard.writeText(fixPlan.unified_diff)}
                        >
                          Copy Unified Diff
                        </button>
                      </div>
                      <div className="muted small" style={{ marginBottom: 6 }}>
                        Commit: <code>{fixPlan.commit_message}</code>
                      </div>
                      <pre className="finding-snippet">{fixPlan.unified_diff}</pre>
                    </div>
                  ) : null}
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
                <div className="share-sheet-head">
                  <div>
                    <h2 id="share-report-title">Share report</h2>
                    <p className="share-sheet-meta">{caption}</p>
                  </div>
                  <button
                    type="button"
                    className="share-sheet-close"
                    aria-label="Close"
                    onClick={() => setShareOpen(false)}
                  >
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path
                        d="M18 6 6 18M6 6l12 12"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.75"
                        strokeLinecap="round"
                      />
                    </svg>
                  </button>
                </div>
                <div className="share-sheet-body">
                  {shareBusy ? <LoadingMark size="sm" label="Creating link…" /> : null}
                  {shareError ? (
                    <p className="notice error" role="alert">
                      {shareError}
                    </p>
                  ) : null}
                  {shareUrl ? (
                    <div className="share-link-row">
                      <input className="share-link-input" type="text" readOnly value={shareUrl} aria-label="Share link" onFocus={(e) => e.currentTarget.select()} />
                      <button type="button" className="btn share-copy-btn" onClick={() => void copyShare()}>
                        {copied ? "Copied" : "Copy"}
                      </button>
                    </div>
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
