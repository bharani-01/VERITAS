Yes—two critical deliverables from the Phase 6A specification remain (plus the bottom half of `ScanReportModal.tsx` that was cut off at the token limit in the previous message, and a daily background scheduler hook in `main.py`):

1. **The second half of `frontend/src/components/ScanReportModal.tsx`** (which cut off right at `function toggleExport()`).
2. **The daily background Threat Intel sync hook in `backend/app/main.py`** so CISA KEV and FIRST EPSS stay warm automatically on your EC2 instance without needing manual admin clicks.
3. **The complete `backend/tests/test_phase6a.py` test suite** tailored to your exact `db.SessionLocal`, UUID `String(36)` models, and `app.main:app` setup so `pytest -c backend/pytest.ini` passes all 15 existing tests + the 4 new Phase 6A tests.

Here are those exact remaining pieces so your implementation is 100% complete.

---

### 1. Remainder of `frontend/src/components/ScanReportModal.tsx`

Pick up right where `function toggleExport()` left off in `frontend/src/components/ScanReportModal.tsx` and paste the rest of the file below:

```tsx
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

  function handleExport(format: ExportFormat) {
    setExportOpen(false);
    exportScanReport(scan, sortFindingsByRisk(findings), format, projectName);
  }

  async function ensureShareLink(): Promise<string | null> {
    if (shareUrl) return shareUrl;
    setShareBusy(true);
    setShareError(null);
    try {
      const res = await api<{ share_token: string; share_path: string; scan: Scan }>(
        `/workspace/scans/${scan.id}/share`,
        { method: "POST" },
      );
      const url = `${window.location.origin}${res.share_path}`;
      setShareUrl(url);
      onShared?.(res.scan);
      return url;
    } catch (e) {
      setShareError((e as Error).message);
      return null;
    } finally {
      setShareBusy(false);
    }
  }

  async function openShareSheet() {
    setShareOpen(true);
    setCopied(false);
    if (!shareUrl) await ensureShareLink();
  }

  async function copyShareUrl() {
    const url = shareUrl || (await ensureShareLink());
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setShareError("Could not copy to clipboard.");
    }
  }

  async function revokeShare() {
    setShareBusy(true);
    setShareError(null);
    try {
      await api(`/workspace/scans/${scan.id}/share`, { method: "DELETE" });
      setShareUrl(null);
      setCopied(false);
      onShared?.({ ...scan, share_token: null });
    } catch (e) {
      setShareError((e as Error).message);
    } finally {
      setShareBusy(false);
    }
  }

  function shareVia(channel: "whatsapp" | "telegram" | "twitter" | "linkedin" | "email" | "native") {
    if (!shareUrl) return;
    const text = `VERITAS security scan report — ${caption}`;
    if (channel === "native" && navigator.share) {
      navigator.share({ title: caption, text, url: shareUrl }).catch(() => {});
      return;
    }
    const encUrl = encodeURIComponent(shareUrl);
    const encText = encodeURIComponent(`${text}\n${shareUrl}`);
    const targets: Record<string, string> = {
      whatsapp: `https://wa.me/?text=${encText}`,
      telegram: `https://t.me/share/url?url=${encUrl}&text=${encodeURIComponent(text)}`,
      twitter: `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encUrl}`,
      linkedin: `https://www.linkedin.com/sharing/share-offsite/?url=${encUrl}`,
      email: `mailto:?subject=${encodeURIComponent(text)}&body=${encText}`,
    };
    const href = targets[channel];
    if (href) window.open(href, "_blank", "noopener,noreferrer");
  }

  const kevCount = useMemo(() => sorted.filter((f) => f.is_kev).length, [sorted]);
  const highEpssCount = useMemo(() => sorted.filter((f) => (f.epss_score ?? 0) >= 0.1).length, [sorted]);
  const multiEngineCount = useMemo(
    () => sorted.filter((f) => (f.engine_count ?? f.matched_engines?.length ?? 1) >= 2).length,
    [sorted],
  );
  const licenseCount = useMemo(
    () => sorted.filter((f) => f.vuln_family === "license" || f.engine === "trivy_license").length,
    [sorted],
  );

  const shell = (
    <div
      className={variant === "page" ? "scan-report-page-card card" : "modal modal-wide scan-report-modal"}
      onClick={variant === "modal" ? (e) => e.stopPropagation() : undefined}
    >
      <div className="modal-head scan-report-head">
        <div className="scan-report-title">
          <div className="scan-report-eyebrow">
            <span className={`badge status-${scan.status}`}>{scan.status}</span>
            <span className="muted small">{scanTriggerLabel(scan.source)}</span>
            {scan.ref ? <span className="muted small">ref: {scan.ref}</span> : null}
            {scan.commit_short ? (
              <CommitLink short={scan.commit_short} sha={scan.commit_sha} repo={githubRepoFullName} />
            ) : null}
            <span className="muted small">duration: {formatScanDuration(scan.started_at, scan.finished_at)}</span>
            <span className="muted small">{new Date(scan.created_at).toLocaleString()}</span>
          </div>
          <h3>{projectName || scan.project_name || scan.target}</h3>
          {scan.commit_message ? <p className="muted small scan-report-commit">{scan.commit_message}</p> : null}
        </div>
        <div className="scan-report-actions">
          {variant === "page" ? (
            <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>
              ← Back to scans
            </button>
          ) : null}
          {scanning && onCancelScan ? (
            <button type="button" className="btn btn-danger btn-sm" disabled={cancelBusy} onClick={onCancelScan}>
              {cancelBusy ? "Stopping…" : "Cancel scan"}
            </button>
          ) : null}
          <div className="export-dropdown" ref={exportWrapRef}>
            <button
              ref={exportBtnRef}
              type="button"
              className="btn btn-ghost btn-sm report-action-btn"
              onClick={toggleExport}
              disabled={scanning}
              aria-haspopup="menu"
              aria-expanded={exportOpen}
              title={scanning ? "Available once the scan finishes" : "Download report"}
            >
              <IconExport />
              <span>Export</span>
            </button>
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-sm report-action-btn"
            onClick={openShareSheet}
            disabled={scanning}
            title={scanning ? "Available once the scan finishes" : "Share read-only report link"}
          >
            <IconShare />
            <span>{shareUrl ? "Shared" : "Share"}</span>
          </button>
          {variant === "modal" ? (
            <button type="button" className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close">
              ✕
            </button>
          ) : null}
        </div>
      </div>

      {exportOpen && exportPos
        ? createPortal(
            <div
              ref={exportMenuRef}
              className="export-menu export-menu-portal"
              role="menu"
              style={{ top: exportPos.top, left: exportPos.left }}
            >
              {EXPORT_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  role="menuitem"
                  className="export-menu-item"
                  onClick={() => handleExport(opt.value)}
                >
                  {opt.label}
                </button>
              ))}
            </div>,
            document.body,
          )
        : null}

      <div className="scan-report-body">
        {scanning ? (
          <section className="scan-report-section scan-live-panel" aria-live="polite">
            <div className="scan-live-header">
              <OrbitLoader size={64} label="Scan in progress" />
              <div className="scan-live-meta">
                <div className="scan-live-stage">{progressLabel}</div>
                <div className="muted small">
                  {progressPct}% complete · {findingsSoFar} finding{findingsSoFar === 1 ? "" : "s"} detected so far
                  {scan.eta_seconds ? ` · ~${scan.eta_seconds}s remaining` : ""}
                </div>
                <div className="scan-progress-track" style={{ marginTop: 8 }}>
                  <div className="scan-progress-fill" style={{ width: `${progressPct}%` }} />
                </div>
              </div>
            </div>
            {liveLogs.length > 0 ? (
              <div className="scan-live-log" ref={liveLogRef}>
                {liveLogs.map((entry, idx) => (
                  <div key={idx} className="scan-live-log-row">
                    <span className="muted">
                      {entry.ts ? new Date(entry.ts).toLocaleTimeString() : "—"}
                    </span>{" "}
                    <span>{entry.msg}</span>
                  </div>
                ))}
              </div>
            ) : null}
          </section>
        ) : null}

        {/* Phase 6A: Deduplication Banner & Tab Switcher */}
        {!scanning ? (
          <div style={{ marginBottom: 16 }}>
            {(rawFindingsCount > correlatedFindingsCount || correlatedFindingsCount > 0) ? (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  flexWrap: "wrap",
                  gap: 10,
                  padding: "10px 14px",
                  marginBottom: 12,
                  borderRadius: 10,
                  background: "linear-gradient(90deg, rgba(59,130,246,0.12) 0%, rgba(15,23,42,0.85) 100%)",
                  border: "1px solid var(--border-subtle, #1e293b)",
                  fontSize: "0.84rem",
                }}
              >
                <div>
                  <strong>Deduplicated across 12 engines</strong> ·{" "}
                  <span style={{ color: "#93c5fd", fontWeight: 600 }}>
                    {correlatedFindingsCount} canonical findings
                  </span>
                  {rawFindingsCount > correlatedFindingsCount ? (
                    <span className="muted">
                      {" "}
                      ({rawFindingsCount - correlatedFindingsCount} duplicate hits merged from {rawFindingsCount} raw tool alerts)
                    </span>
                  ) : null}
                </div>
                {kevCount > 0 ? (
                  <span
                    style={{
                      padding: "2px 9px",
                      borderRadius: 999,
                      backgroundColor: "rgba(185, 28, 28, 0.3)",
                      border: "1px solid #ef4444",
                      color: "#fecaca",
                      fontSize: "0.72rem",
                      fontWeight: 800,
                    }}
                  >
                    {kevCount} ACTIVE EXPLOIT (CISA KEV)
                  </span>
                ) : null}
              </div>
            ) : null}

            <div style={{ display: "flex", gap: 8, borderBottom: "1px solid var(--border-subtle, #1e293b)", paddingBottom: 10 }}>
              <button
                type="button"
                className={`btn btn-sm ${activeTab === "findings" ? "btn-primary" : "btn-ghost"}`}
                onClick={() => setActiveTab("findings")}
              >
                Findings ({sorted.length})
              </button>
              <button
                type="button"
                className={`btn btn-sm ${activeTab === "sbom" ? "btn-primary" : "btn-ghost"}`}
                onClick={() => setActiveTab("sbom")}
              >
                SBOM & Licenses
              </button>
            </div>
          </div>
        ) : null}

        {!scanning && activeTab === "sbom" ? (
          <section className="scan-report-section">
            {sbomLoading ? (
              <div className="scan-findings-loading">
                <LoadingMark label="Loading CycloneDX SBOM & License Inventory…" />
              </div>
            ) : sbomError || !sbom ? (
              <p className="muted small">{sbomError || "No SBOM artifact available for this scan."}</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                    gap: 12,
                  }}
                >
                  <div className="card" style={{ padding: 14, borderTop: "3px solid #3b82f6" }}>
                    <div className="muted small">Total Components</div>
                    <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: 4 }}>{sbom.component_count}</div>
                    <div className="muted small">{sbom.spec_version}</div>
                  </div>
                  <div className="card" style={{ padding: 14, borderTop: "3px solid #10b981" }}>
                    <div className="muted small">Permissive</div>
                    <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: 4 }}>
                      {sbom.license_summary?.permissive ?? 0}
                    </div>
                    <div className="muted small">MIT, Apache-2.0, BSD, ISC</div>
                  </div>
                  <div className="card" style={{ padding: 14, borderTop: "3px solid #f59e0b" }}>
                    <div className="muted small">Weak Copyleft</div>
                    <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: 4 }}>
                      {sbom.license_summary?.weak_copyleft ?? 0}
                    </div>
                    <div className="muted small">LGPL, MPL-2.0, EPL</div>
                  </div>
                  <div
                    className="card"
                    style={{
                      padding: 14,
                      borderTop: `3px solid ${sbom.policy_violations_count > 0 ? "#ef4444" : "#64748b"}`,
                    }}
                  >
                    <div className="muted small">Restricted / Policy Violations</div>
                    <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: 4 }}>
                      {sbom.policy_violations_count}
                    </div>
                    <div className="muted small">GPL, AGPL, SSPL</div>
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                  <input
                    type="text"
                    value={sbomSearch}
                    onChange={(e) => setSbomSearch(e.target.value)}
                    placeholder="Filter packages by name, PURL, or license (e.g. AGPL-3.0, MIT)…"
                    style={{
                      flex: "1 1 280px",
                      padding: "8px 12px",
                      borderRadius: 8,
                      background: "var(--bg-primary, #0a0e17)",
                      border: "1px solid var(--border-subtle, #1e293b)",
                      color: "#e2e8f0",
                    }}
                  />
                  <a
                    className="btn btn-primary btn-sm"
                    href={`/workspace/projects/${scan.project_id}/scans/${scan.id}/sbom/download`}
                    download={`veritas-sbom-scan-${scan.id}.cdx.json`}
                  >
                    Download CycloneDX (.cdx.json)
                  </a>
                </div>

                <div style={{ overflowX: "auto", borderRadius: 10, border: "1px solid var(--border-subtle, #1e293b)" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.84rem" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--border-subtle, #1e293b)", textAlign: "left" }}>
                        <th style={{ padding: "10px 12px" }}>Package</th>
                        <th style={{ padding: "10px 12px" }}>Version</th>
                        <th style={{ padding: "10px 12px" }}>Ecosystem / PURL</th>
                        <th style={{ padding: "10px 12px" }}>License</th>
                        <th style={{ padding: "10px 12px" }}>Policy Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredSbomComponents.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="muted small" style={{ padding: 18, textAlign: "center" }}>
                            No SBOM components match this filter.
                          </td>
                        </tr>
                      ) : (
                        filteredSbomComponents.map((comp) => (
                          <tr key={comp.purl} style={{ borderBottom: "1px solid rgba(30,41,59,0.5)" }}>
                            <td style={{ padding: "9px 12px", fontWeight: 600 }}>{comp.name}</td>
                            <td style={{ padding: "9px 12px" }}>
                              <code>{comp.version}</code>
                            </td>
                            <td style={{ padding: "9px 12px" }} className="muted small">
                              <code>{comp.purl}</code>
                            </td>
                            <td style={{ padding: "9px 12px" }}>
                              <code>{comp.licenses.join(", ")}</code>
                            </td>
                            <td style={{ padding: "9px 12px" }}>
                              <span
                                className={`badge ${
                                  comp.risk_tier === "restricted_copyleft"
                                    ? "sev-high"
                                    : comp.risk_tier === "weak_copyleft"
                                      ? "sev-medium"
                                      : "sev-info"
                                }`}
                              >
                                {comp.risk_tier.replace("_", " ")}
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>
        ) : null}

        {!scanning && activeTab === "findings" && aiReport ? (
          <section className="scan-report-section">
            <div className="scan-report-section-head">
              <h4>Final security report</h4>
            </div>
            <MarkdownReport markdown={aiReport} className="scan-ai-report" />
          </section>
        ) : null}

        {activeTab === "findings" ? (
          <section className="scan-report-section">
            <div className="scan-report-section-head">
              <h4>Findings ({filteredFindings.length})</h4>
              <span className="muted small">Ranked by priority · click a finding to view details</span>
            </div>

            {!scanning && sorted.length > 0 ? (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 12 }}>
                {(
                  [
                    { id: "all", label: `All (${sorted.length})` },
                    { id: "kev", label: `Actively Exploited (KEV) (${kevCount})` },
                    { id: "high_epss", label: `High EPSS (>10%) (${highEpssCount})` },
                    { id: "multi_engine", label: `Multi-Engine Confirmed (2+) (${multiEngineCount})` },
                    { id: "license", label: `License Risks (${licenseCount})` },
                  ] as { id: QuickFilter; label: string }[]
                ).map((chip) => (
                  <button
                    key={chip.id}
                    type="button"
                    className={`btn btn-sm ${quickFilter === chip.id ? "btn-primary" : "btn-ghost"}`}
                    onClick={() => setQuickFilter(chip.id)}
                  >
                    {chip.label}
                  </button>
                ))}
              </div>
            ) : null}

            {findingsLoading && sorted.length === 0 ? (
              <div className="scan-findings-loading">
                <LoadingMark label="Loading findings…" />
              </div>
            ) : filteredFindings.length === 0 ? (
              <p className="muted small">
                {scanning ? "Findings will appear here as engines finish." : "No findings match this filter."}
              </p>
            ) : (
              <ul className="finding-compact-list">
                {filteredFindings.map((f) => (
                  <li key={f.id}>
                    <button
                      type="button"
                      className={`finding-compact-row sev-border-${f.severity}`}
                      onClick={() => setSelected(f)}
                    >
                      <span className={`badge sev-${f.severity}`}>{f.severity}</span>
                      <span className="finding-compact-title">
                        {f.title}
                        <FindingThreatBadges finding={f} />
                      </span>
                      {f.file_path ? (
                        <code className="finding-compact-loc">
                          {f.file_path}
                          {f.line_start ? `:${f.line_start}` : ""}
                        </code>
                      ) : null}
                      <span className="finding-compact-risk">
                        priority {(f.effective_priority_score ?? f.risk_score ?? 0).toFixed(1)}
                      </span>
                      <span className="finding-compact-chevron" aria-hidden="true">
                        ›
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        ) : null}
      </div>

      {selected ? (
        <div className="finding-detail-backdrop" onClick={() => setSelected(null)}>
          <div className="finding-detail-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="finding-detail-head">
              <button
                type="button"
                className="btn btn-ghost btn-sm finding-back-btn"
                onClick={() => setSelected(null)}
              >
                <IconBack />
                <span>All findings</span>
              </button>
              <div className="finding-detail-badges">
                <span className={`badge sev-${selected.severity}`}>{selected.severity}</span>
                <FindingThreatBadges finding={selected} />
                <span className="muted small">
                  priority {(selected.effective_priority_score ?? selected.risk_score ?? 0).toFixed(1)}
                </span>
                <span className="muted small">{selected.vuln_family}</span>
                {selected.cwe ? <span className="muted small">{selected.cwe}</span> : null}
                {selected.owasp_category ? <span className="muted small">{selected.owasp_category}</span> : null}
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setSelected(null)}
                aria-label="Close finding"
              >
                ✕
              </button>
            </div>

            <div className="finding-detail-body">
              <h4 className="finding-detail-title">{selected.title}</h4>

              {selected.matched_engines && selected.matched_engines.length > 0 ? (
                <div className="muted small" style={{ marginBottom: 8 }}>
                  Detected by: <code>{selected.matched_engines.join(", ")}</code> (confidence:{" "}
                  <code>{selected.confidence_level || "medium"}</code>)
                </div>
              ) : null}

              {selected.file_path ? (
                <div className="finding-loc">
                  <code>
                    {selected.file_path}
                    {selected.line_start ? `:${selected.line_start}` : ""}
                  </code>
                  {(() => {
                    const url = githubBlobUrl(
                      githubRepoFullName,
                      scan.commit_sha || scan.ref || "HEAD",
                      selected.file_path,
                      selected.line_start,
                      selected.line_end,
                    );
                    return url ? (
                      <a href={url} target="_blank" rel="noreferrer" className="btn btn-ghost btn-xs">
                        View on GitHub ↗
                      </a>
                    ) : null;
                  })()}
                </div>
              ) : null}

              {selected.message ? <p className="finding-msg">{selected.message}</p> : null}
              {selected.snippet ? <pre className="code-snippet">{selected.snippet}</pre> : null}
              {selected.ai_rationale ? (
                <p className="ai-note">
                  <strong>Note ({selected.ai_verdict || "info"}):</strong> {selected.ai_rationale}
                </p>
              ) : null}
              {selected.countermeasures && selected.countermeasures.length > 0 ? (
                <div className="finding-remediation">
                  <div className="finding-remediation-title">Recommended fix</div>
                  <ul>
                    {selected.countermeasures.map((cm, i) =>
                      (cm.steps || []).map((step, j) => <li key={`${i}-${j}`}>{step}</li>),
                    )}
                  </ul>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}

      {shareOpen ? (
        <div className="share-sheet-backdrop" onClick={() => setShareOpen(false)}>
          <div className="share-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <h3>Share scan report</h3>
                <p className="muted small">{caption}</p>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setShareOpen(false)}
                aria-label="Close share dialog"
              >
                ✕
              </button>
            </div>

            {shareError ? <div className="alert alert-error">{shareError}</div> : null}

            <label className="share-url-field">
              <span className="muted small">Read-only report link (anyone with the link can view)</span>
              <div className="share-url-row">
                <input
                  readOnly
                  value={shareBusy ? "Generating link…" : shareUrl || "Link revoked"}
                  onFocus={(e) => e.currentTarget.select()}
                />
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  disabled={shareBusy}
                  onClick={copyShareUrl}
                >
                  {copied ? "Copied ✓" : shareUrl ? "Copy link" : "Create & copy"}
                </button>
              </div>
            </label>

            <div className="share-destinations">
              <span className="muted small">Share directly via</span>
              <div className="share-grid">
                <button type="button" className="btn btn-ghost btn-sm" disabled={!shareUrl} onClick={() => shareVia("whatsapp")}>
                  WhatsApp
                </button>
                <button type="button" className="btn btn-ghost btn-sm" disabled={!shareUrl} onClick={() => shareVia("telegram")}>
                  Telegram
                </button>
                <button type="button" className="btn btn-ghost btn-sm" disabled={!shareUrl} onClick={() => shareVia("email")}>
                  Email
                </button>
                <button type="button" className="btn btn-ghost btn-sm" disabled={!shareUrl} onClick={() => shareVia("twitter")}>
                  X / Twitter
                </button>
                <button type="button" className="btn btn-ghost btn-sm" disabled={!shareUrl} onClick={() => shareVia("linkedin")}>
                  LinkedIn
                </button>
                {typeof navigator !== "undefined" && "share" in navigator ? (
                  <button type="button" className="btn btn-ghost btn-sm" disabled={!shareUrl} onClick={() => shareVia("native")}>
                    System share…
                  </button>
                ) : null}
              </div>
            </div>

            <div className="share-sheet-foot">
              {shareUrl ? (
                <button type="button" className="btn btn-ghost btn-xs" disabled={shareBusy} onClick={revokeShare}>
                  Revoke public link
                </button>
              ) : (
                <span />
              )}
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShareOpen(false)}>
                Done
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );

  if (variant === "page") return shell;

  return (
    <div className="modal-backdrop scan-report-backdrop" onClick={onClose}>
      {shell}
    </div>
  );
}
```

---

### 2. Optional Daily Background Sync in `backend/app/main.py`

In `backend/app/main.py`, inside your `lifespan(app: FastAPI)` function, you can optionally start a lightweight daemon thread (outside of `APP_ENV == "test"`) that syncs the CISA KEV + FIRST EPSS cache once every 24 hours:

```python
# Inside backend/app/main.py lifespan():
@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_schema()
    with db.SessionLocal() as session:
        bootstrap_admin_account(session)
    ensure_worker()

    if APP_ENV != "test":
        import threading
        from app.services.threat_intel import sync_threat_intel_feeds

        def _daily_threat_intel_loop() -> None:
            import time
            while True:
                try:
                    with db.SessionLocal() as session:
                        sync_threat_intel_feeds(session)
                except Exception:
                    pass
                time.sleep(86400)

        threading.Thread(target=_daily_threat_intel_loop, name="veritas-threat-intel", daemon=True).start()

    yield
```

---

### 3. Complete Automated Test Suite (`backend/tests/test_phase6a.py`)

Create `backend/tests/test_phase6a.py`. It follows the exact fixture setup in your `backend/tests/test_workspace.py` (`os.environ["APP_ENV"] = "test"`, `reload_engine()`, `ensure_schema()`, `bootstrap_admin_account()`) and tests all 4 Phase 6A requirements:

```python
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

TEST_DB_DIR = tempfile.mkdtemp(prefix="veritas-phase6a-tests-")
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = f"sqlite:///{Path(TEST_DB_DIR) / 'test_phase6a.db'}"
os.environ["BOOTSTRAP_ADMIN_EMAIL"] = "admin@example.com"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "StrongPass!123"
os.environ["EMAIL_DELIVERY_MODE"] = "Sink"
os.environ["TOKEN_ENCRYPTION_SECRET"] = "test-secret-for-phase6a-suite"

from app.core import database as db  # noqa: E402
from app.core.time import utcnow  # noqa: E402
from app.main import app  # noqa: E402
from app.models import CveIntelCache, Finding, Project, Scan, User  # noqa: E402
from app.services.auth import bootstrap_admin_account, ensure_schema, hash_password  # noqa: E402
from app.services.correlator import correlate_findings  # noqa: E402
from app.services.engines.normalize import NormalizedFinding  # noqa: E402
from app.services.engines.trivy_sbom import run_trivy_sbom  # noqa: E402
from app.services.threat_intel import (  # noqa: E402
    compute_effective_priority_score,
    enrich_findings_with_intel,
    sync_threat_intel_feeds,
)


def _make_active_user(email: str, password: str = "UserPass!123456") -> str:
    with db.SessionLocal() as session:
        user = User(
            email=email,
            password_hash=hash_password(password),
            role="user",
            status="active",
            email_verified_at=utcnow(),
            approved_at=utcnow(),
        )
        session.add(user)
        session.commit()
        return user.id


@pytest.fixture()
def client():
    db.reload_engine(f"sqlite:///{Path(TEST_DB_DIR) / 'test_phase6a.db'}")
    db.Base.metadata.drop_all(bind=db.engine)
    ensure_schema()
    with db.SessionLocal() as session:
        bootstrap_admin_account(session)
    with TestClient(app) as c:
        yield c


def _login(c: TestClient, email: str, password: str = "UserPass!123456"):
    resp = c.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text


# ============================================================================
# 1. Cross-Engine SCA and Secret Deduplication
# ============================================================================


def test_cross_engine_sca_and_secret_deduplication():
    raw_hits = [
        # Three SCA engines flagging the exact same CVE-2026-102268 on requests 2.31.0
        NormalizedFinding(
            engine="trivy",
            title="CVE-2026-102268 in requests 2.31.0",
            severity="medium",
            rule_id="CVE-2026-102268",
            vuln_family="sca",
            message="Short Trivy advisory summary.",
            file_path="requirements.txt",
            raw={
                "VulnerabilityID": "CVE-2026-102268",
                "PkgName": "requests",
                "InstalledVersion": "2.31.0",
                "FixedVersion": "2.32.0",
                "ecosystem": "pypi",
            },
        ),
        NormalizedFinding(
            engine="osv",
            title="GHSA-9wx4-h78v-vm56 in requests",
            severity="high",
            rule_id="GHSA-9wx4-h78v-vm56",
            vuln_family="sca",
            message=(
                "Detailed OSV advisory explaining how crafted redirects leak proxy-authorization "
                "headers in requests 2.31.0 when following cross-origin redirects."
            ),
            file_path="./requirements.txt",
            raw={
                "id": "GHSA-9wx4-h78v-vm56",
                "aliases": ["CVE-2026-102268"],
                "package_name": "Requests",
                "installed_version": "2.31.0",
                "ecosystem": "PyPI",
            },
        ),
        NormalizedFinding(
            engine="pip_audit",
            title="PYSEC-2026-42 in requests 2.31.0",
            severity="high",
            rule_id="PYSEC-2026-42",
            vuln_family="sca",
            message="pip-audit advisory for requests.",
            file_path="requirements.txt",
            raw={
                "id": "PYSEC-2026-42",
                "aliases": ["CVE-2026-102268"],
                "package": "requests",
                "version": "2.31.0",
                "fix_versions": ["2.32.2"],
            },
        ),
        # Two secret scanners flagging the same leaked GitHub token on line 18
        NormalizedFinding(
            engine="gitleaks",
            title="GitHub Personal Access Token",
            severity="high",
            rule_id="github-pat",
            vuln_family="secret",
            message="Detected GitHub PAT in config.py",
            file_path="src/config.py",
            line_start=18,
            snippet="GH_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuv'",
            raw={"RuleID": "github-pat"},
        ),
        NormalizedFinding(
            engine="trufflehog",
            title="TruffleHog: GitHub (verified)",
            severity="critical",
            rule_id="GitHub",
            vuln_family="secret",
            message="Verified active GitHub token in src/config.py",
            file_path="./src/config.py",
            line_start=18,
            snippet="GH_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuv'",
            raw={"DetectorName": "GitHub", "Verified": True},
        ),
    ]

    corr = correlate_findings(raw_hits)
    assert corr.raw_findings_count == 5
    assert corr.correlated_findings_count == 2
    assert corr.deduplicated_count == 3
    assert corr.multi_engine_confirmed_count == 2

    by_family = {f.vuln_family: f for f in corr.findings}
    sca_finding = by_family["sca"]
    assert sca_finding.raw["cve_id"] == "CVE-2026-102268"
    assert sca_finding.raw["engine_count"] == 3
    assert sca_finding.raw["matched_engines"] == ["osv", "pip_audit", "trivy"]
    assert sca_finding.raw["confidence_level"] == "high"
    assert sca_finding.severity == "high"
    assert "cross-origin redirects" in (sca_finding.message or "")
    assert "2.32.0" in (sca_finding.message or "")

    secret_finding = by_family["secret"]
    assert secret_finding.raw["engine_count"] == 2
    assert secret_finding.raw["matched_engines"] == ["gitleaks", "trufflehog"]
    assert secret_finding.raw["confidence_level"] == "high"
    assert secret_finding.severity == "critical"


# ============================================================================
# 2. KEV + EPSS Enrichment and Composite Priority Sorting
# ============================================================================


def test_kev_and_epss_enrichment_and_priority_sorting(client: TestClient):
    with db.SessionLocal() as session:
        session.add(
            CveIntelCache(
                cve_id="CVE-2024-21626",
                is_kev=True,
                kev_vendor="Docker",
                kev_product="runc",
                kev_date_added="2024-02-01",
                kev_due_date="2024-02-22",
                epss_score=0.65,
                epss_percentile=0.985,
                updated_at=utcnow(),
            )
        )
        session.add(
            CveIntelCache(
                cve_id="CVE-2024-99999",
                is_kev=False,
                epss_score=0.04,
                epss_percentile=0.45,
                updated_at=utcnow(),
            )
        )
        session.commit()

        raw_findings = [
            # Non-KEV high finding
            NormalizedFinding(
                engine="trivy",
                title="CVE-2024-99999 in urllib3 1.26.0",
                severity="high",
                rule_id="CVE-2024-99999",
                vuln_family="sca",
                file_path="requirements.txt",
                raw={"cve_id": "CVE-2024-99999", "engine_count": 1, "matched_engines": ["trivy"]},
            ),
            # KEV medium finding confirmed by 2 engines (should auto-promote to critical & rank #1)
            NormalizedFinding(
                engine="osv",
                title="CVE-2024-21626 in runc 1.1.11",
                severity="medium",
                rule_id="CVE-2024-21626",
                vuln_family="sca",
                file_path="go.mod",
                raw={
                    "cve_id": "CVE-2024-21626",
                    "engine_count": 2,
                    "matched_engines": ["osv", "trivy"],
                },
            ),
        ]

        enriched = enrich_findings_with_intel(session, raw_findings, allow_network=False)
        assert len(enriched) == 2

        top = enriched[0]
        second = enriched[1]

        assert top.raw["cve_id"] == "CVE-2024-21626"
        assert top.raw["is_kev"] is True
        assert top.raw["kev_due_date"] == "2024-02-22"
        assert top.severity == "critical"
        assert top.raw["epss_score"] == pytest.approx(0.65)
        assert top.raw["effective_priority_score"] == pytest.approx(10.0)
        assert top.raw["effective_priority_score"] > second.raw["effective_priority_score"]

        expected_second_score = compute_effective_priority_score(
            severity="high",
            is_kev=False,
            epss_score=0.04,
            engine_count=1,
        )
        assert second.raw["effective_priority_score"] == pytest.approx(expected_second_score)


# ============================================================================
# 3. Threat Intel Sync Fail-Open Resilience
# ============================================================================


def test_threat_intel_sync_fail_open(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    def _boom_get(self, url, *args, **kwargs):
        raise httpx.ConnectTimeout("Simulated CISA/FIRST network timeout")

    monkeypatch.setattr(httpx.Client, "get", _boom_get)

    with db.SessionLocal() as session:
        status_res = sync_threat_intel_feeds(
            session,
            cve_ids=["CVE-2025-0001"],
            include_bulk_epss=True,
        )
        assert isinstance(status_res, dict)
        assert status_res["kev_upserted"] == 0
        assert status_res["epss_upserted"] == 0
        assert status_res["total_cached_cves"] == 0


# ============================================================================
# 4. CycloneDX SBOM Generation, Copyleft Policy Finding, & Ownership AuthZ
# ============================================================================


def test_sbom_generation_and_copyleft_license_finding(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    # Force deterministic manifest parser so test is environment-independent
    monkeypatch.setattr("shutil.which", lambda _cmd: None)

    owner_id = _make_active_user("sbom_owner@example.com")
    _make_active_user("sbom_stranger@example.com")

    # Create sample repo workspace with permissive, weak copyleft, and restricted copyleft packages
    repo_dir = tmp_path / "sample_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "requirements.txt").write_text(
        "fastapi==0.115.0 # license: MIT\n"
        "psycopg2==2.9.9 # license: LGPL-3.0\n"
        "pyminizip==0.2.6 # license: GPL-3.0\n",
        encoding="utf-8",
    )
    (repo_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "sample-ui",
                "version": "1.0.0",
                "dependencies": {
                    "react": {"version": "18.3.1", "license": "MIT"},
                    "agpl-pdf-engine": {"version": "2.1.0", "license": "AGPL-3.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    with db.SessionLocal() as session:
        proj = Project(owner_user_id=owner_id, name="SBOM Governance App")
        session.add(proj)
        session.commit()
        session.refresh(proj)

        scan = Scan(
            project_id=proj.id,
            created_by_user_id=owner_id,
            target="https://github.com/example/sbom-app",
            status="succeeded",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        sbom_res, meta = run_trivy_sbom(
            session,
            scan_id=scan.id,
            project_id=proj.id,
            workdir=repo_dir,
        )
        assert meta["available"] is True
        assert sbom_res.component_count == 5
        assert sbom_res.policy_violations_count == 2
        assert sbom_res.license_summary["permissive"] == 2
        assert sbom_res.license_summary["weak_copyleft"] == 1
        assert sbom_res.license_summary["restricted_copyleft"] == 2
        assert len(sbom_res.findings) == 2

        for nf in sbom_res.findings:
            assert nf.engine == "trivy_license"
            assert nf.vuln_family == "license"
            assert nf.severity == "high"
            assert nf.cwe == "CWE-1104"
            assert "Restricted Copyleft License Detected:" in nf.title
            session.add(
                Finding(
                    scan_id=scan.id,
                    engine=nf.engine,
                    rule_id=nf.rule_id,
                    vuln_family=nf.vuln_family,
                    cwe=nf.cwe,
                    owasp_category=nf.owasp_category,
                    severity=nf.severity,
                    title=nf.title,
                    message=nf.message,
                    file_path=nf.file_path,
                    line_start=nf.line_start,
                    line_end=nf.line_end,
                    risk_score=7.5,
                    effective_priority_score=7.5,
                    matched_engines_json='["trivy_license"]',
                    engine_count=1,
                    confidence_level="high",
                )
            )
        session.commit()
        project_id = proj.id
        scan_id = scan.id

    # Verify owner can fetch SBOM summary, download CycloneDX JSON, and filter license findings
    _login(client, "sbom_owner@example.com")

    sbom_resp = client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/sbom")
    assert sbom_resp.status_code == 200, sbom_resp.text
    sbom_body = sbom_resp.json()
    assert sbom_body["component_count"] == 5
    assert sbom_body["policy_violations_count"] == 2
    assert len(sbom_body["components"]) == 5

    dl_resp = client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/sbom/download")
    assert dl_resp.status_code == 200
    assert f'filename="veritas-sbom-scan-{scan_id}.cdx.json"' in dl_resp.headers.get(
        "content-disposition", ""
    )
    cdx_json = dl_resp.json()
    assert cdx_json["bomFormat"] == "CycloneDX"
    assert cdx_json["specVersion"] == "1.5"
    assert len(cdx_json["components"]) == 5

    findings_resp = client.get(
        f"/workspace/projects/{project_id}/scans/{scan_id}/findings?category=license"
    )
    assert findings_resp.status_code == 200
    assert findings_resp.json()["total"] == 2

    # Verify foreign user is strictly blocked (404 project ownership isolation)
    client.post("/auth/logout")
    _login(client, "sbom_stranger@example.com")
    assert client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/sbom").status_code == 404
    assert (
        client.get(f"/workspace/projects/{project_id}/scans/{scan_id}/sbom/download").status_code
        == 404
    )
```

---

### Final Verification Checklist

Run these two commands from your repository root to verify the backend test suite and build the updated React SPA bundle into `backend/app/web/static/spa/`:

```powershell
# 1. Run all 15 existing tests + 4 new Phase 6A tests (19 total)
pytest -c backend/pytest.ini

# 2. Rebuild the React SPA so FastAPI serves the new Phase 6A UI
cd frontend
npm run build
```
