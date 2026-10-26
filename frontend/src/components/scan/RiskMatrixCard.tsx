import React, { useMemo } from "react";
import type { Finding } from "../../lib/workspace";

export type RiskCellCoord = { likelihood: number; impact: number };

export function computeFindingRiskCell(finding: Finding): RiskCellCoord {
  const sev = (finding.severity || "info").toLowerCase();
  const impact =
    sev === "critical" ? 5 : sev === "high" ? 4 : sev === "medium" ? 3 : sev === "low" ? 2 : 1;

  const epss = finding.epss_score ?? 0;
  const conf = (finding.confidence_level || "medium").toLowerCase();
  const engineCount = finding.engine_count ?? finding.matched_engines?.length ?? 1;

  let likelihood = 2;
  if (finding.is_kev || epss >= 0.3) {
    likelihood = 5;
  } else if (epss >= 0.1 || (conf === "high" && engineCount >= 2) || finding.engine === "veritas_dast") {
    likelihood = 4;
  } else if (epss >= 0.02 || conf === "high") {
    likelihood = 3;
  } else if (conf === "medium") {
    likelihood = 2;
  } else {
    likelihood = 1;
  }

  return { likelihood, impact };
}

export type RiskTierInfo = {
  tier: "extreme" | "high" | "medium" | "low";
  name: string;
  bg: string;
  border: string;
  color: string;
  badgeBg: string;
  badgeColor: string;
  description: string;
};

export function getRiskTier(likelihood: number, impact: number): RiskTierInfo {
  const product = likelihood * impact;
  if (product >= 16 || (impact === 5 && likelihood >= 3)) {
    return {
      tier: "extreme",
      name: "Extreme Risk",
      bg: "#fef2f2",
      border: "#fca5a5",
      color: "#991b1b",
      badgeBg: "#dc2626",
      badgeColor: "#ffffff",
      description: "Critical CVE / RCE with verified active exploitability (KEV / high EPSS). Immediate 24h SLA.",
    };
  }
  if (product >= 10) {
    return {
      tier: "high",
      name: "High Risk",
      bg: "#fff7ed",
      border: "#fdba74",
      color: "#9a3412",
      badgeBg: "#ea580c",
      badgeColor: "#ffffff",
      description: "High impact flaw with proven exploit vector or multi-engine confirmation. Remediate in 7-14 days.",
    };
  }
  if (product >= 5) {
    return {
      tier: "medium",
      name: "Medium Risk",
      bg: "#fefce8",
      border: "#fde047",
      color: "#854d0e",
      badgeBg: "#ca8a04",
      badgeColor: "#ffffff",
      description: "Moderate impact; requires specific preconditions or complex chained exploit conditions.",
    };
  }
  return {
    tier: "low",
    name: "Low Risk",
    bg: "#f0fdf4",
    border: "#86efac",
    color: "#166534",
    badgeBg: "#16a34a",
    badgeColor: "#ffffff",
    description: "Low severity, informational disclosure, or security hygiene hardening recommendations.",
  };
}

const IMPACT_METADATA: Record<number, { title: string; subtitle: string }> = {
  5: { title: "5 · Catastrophic", subtitle: "Critical CVE / Full Takeover" },
  4: { title: "4 · Major", subtitle: "High Impact / Data Breach" },
  3: { title: "3 · Moderate", subtitle: "Medium / Logic Privilege" },
  2: { title: "2 · Minor", subtitle: "Low / Limited Leak" },
  1: { title: "1 · Negligible", subtitle: "Info / Best Practice" },
};

const LIKELIHOOD_METADATA: Record<number, { title: string; subtitle: string }> = {
  1: { title: "1 · Rare", subtitle: "Theoretical / Air-gapped" },
  2: { title: "2 · Unlikely", subtitle: "Auth Required / Low Exploit" },
  3: { title: "3 · Possible", subtitle: "Known Public Exploit Path" },
  4: { title: "4 · Likely", subtitle: "High EPSS / Confirmed (2+)" },
  5: { title: "5 · Almost Certain", subtitle: "Actively Exploited (KEV)" },
};

export function RiskMatrixCard({
  findings,
  selectedCell,
  onSelectCell,
}: {
  findings: Finding[];
  selectedCell: RiskCellCoord | null;
  onSelectCell: (cell: RiskCellCoord | null) => void;
}) {
  const { grid } = useMemo(() => {
    const matrix: Record<string, number> = {};

    for (const f of findings) {
      if (f.status !== "false_positive" && f.status !== "fixed") {
        const { likelihood, impact } = computeFindingRiskCell(f);
        const key = `${likelihood}-${impact}`;
        matrix[key] = (matrix[key] || 0) + 1;
      }
    }

    return { grid: matrix };
  }, [findings]);

  const activeTier = selectedCell ? getRiskTier(selectedCell.likelihood, selectedCell.impact) : null;

  return (
    <div
      style={{
        padding: "20px 24px",
        marginBottom: 20,
        borderRadius: 12,
        backgroundColor: "var(--surface, #ffffff)",
        border: "1px solid var(--line, #e2e8f0)",
        boxShadow: "0 1px 3px rgba(15, 23, 42, 0.05), 0 6px 16px -2px rgba(15, 23, 42, 0.03)",
        color: "var(--ink, #0f172a)",
      }}
    >
      {/* Header bar */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 12,
          marginBottom: 16,
          paddingBottom: 14,
          borderBottom: "1px solid var(--line, #e2e8f0)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              width: 26,
              height: 26,
              borderRadius: 6,
              backgroundColor: "rgba(37, 99, 235, 0.1)",
              color: "#2563eb",
              fontWeight: 700,
              fontSize: "0.85rem",
            }}
          >
            ⊞
          </span>
          <h4 style={{ margin: 0, fontSize: "1.05rem", fontWeight: 700, color: "var(--ink, #0f172a)" }}>
            Risk Assessment Matrix
          </h4>
        </div>

        {selectedCell ? (
          <button
            type="button"
            onClick={() => onSelectCell(null)}
            style={{
              padding: "4px 10px",
              borderRadius: 20,
              fontSize: "0.76rem",
              fontWeight: 600,
              backgroundColor: "#fee2e2",
              border: "1px solid #f87171",
              color: "#991b1b",
              cursor: "pointer",
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
            }}
          >
            Clear Filter (L{selectedCell.likelihood} × I{selectedCell.impact}) ✕
          </button>
        ) : null}
      </div>

      {/* Active filter notification banner */}
      {selectedCell && activeTier ? (
        <div
          style={{
            padding: "8px 14px",
            marginBottom: 14,
            borderRadius: 8,
            backgroundColor: activeTier.bg,
            border: `1px solid ${activeTier.border}`,
            color: activeTier.color,
            fontSize: "0.82rem",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div>
            <strong>Active Matrix Filter:</strong> {activeTier.name} — Likelihood {selectedCell.likelihood} × Impact {selectedCell.impact} (Score: {selectedCell.likelihood * selectedCell.impact}/25).
            {" "}<span style={{ opacity: 0.9 }}>{activeTier.description}</span>
          </div>
          <button
            type="button"
            onClick={() => onSelectCell(null)}
            style={{
              background: "none",
              border: "none",
              color: activeTier.color,
              fontWeight: 700,
              cursor: "pointer",
              textDecoration: "underline",
              padding: "2px 6px",
            }}
          >
            Reset filter
          </button>
        </div>
      ) : null}

      {/* Grid container with educational labels */}
      <div style={{ overflowX: "auto", paddingBottom: 6 }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "170px repeat(5, minmax(110px, 1fr))",
            gap: 8,
            alignItems: "stretch",
          }}
        >
          {/* Header Row: Column Titles (Likelihood Levels) */}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              justifyContent: "flex-end",
              padding: "0 8px 8px 0",
              fontWeight: 700,
              fontSize: "0.74rem",
              color: "var(--muted, #64748b)",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              borderBottom: "2px solid var(--line, #e2e8f0)",
            }}
          >
            <span>IMPACT ↓ / LIKELIHOOD →</span>
          </div>
          {[1, 2, 3, 4, 5].map((l) => (
            <div
              key={l}
              style={{
                textAlign: "center",
                padding: "8px 4px",
                borderBottom: "2px solid var(--line, #e2e8f0)",
                backgroundColor: "rgba(248, 250, 252, 0.7)",
                borderRadius: "6px 6px 0 0",
              }}
            >
              <div style={{ fontWeight: 700, fontSize: "0.8rem", color: "var(--ink, #0f172a)" }}>
                {LIKELIHOOD_METADATA[l].title}
              </div>
              <div style={{ fontSize: "0.68rem", color: "var(--muted, #64748b)", marginTop: 2 }}>
                {LIKELIHOOD_METADATA[l].subtitle}
              </div>
            </div>
          ))}

          {/* Impact Rows 5 down to 1 */}
          {[5, 4, 3, 2, 1].map((impact) => (
            <React.Fragment key={impact}>
              {/* Row Header: Impact Level */}
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "center",
                  padding: "6px 10px",
                  backgroundColor: "rgba(248, 250, 252, 0.7)",
                  borderRadius: "6px 0 0 6px",
                  borderLeft: "3px solid var(--line-strong, #cbd5e1)",
                }}
              >
                <div style={{ fontWeight: 700, fontSize: "0.82rem", color: "var(--ink, #0f172a)" }}>
                  {IMPACT_METADATA[impact].title}
                </div>
                <div style={{ fontSize: "0.68rem", color: "var(--muted, #64748b)", marginTop: 2 }}>
                  {IMPACT_METADATA[impact].subtitle}
                </div>
              </div>

              {/* 5 Likelihood Columns for this Impact */}
              {[1, 2, 3, 4, 5].map((likelihood) => {
                const count = grid[`${likelihood}-${impact}`] || 0;
                const isSelected =
                  selectedCell?.likelihood === likelihood && selectedCell?.impact === impact;
                const tier = getRiskTier(likelihood, impact);
                const score = likelihood * impact;

                return (
                  <button
                    key={`${likelihood}-${impact}`}
                    type="button"
                    onClick={() => onSelectCell(isSelected ? null : { likelihood, impact })}
                    style={{
                      backgroundColor: tier.bg,
                      border: isSelected ? "2.5px solid #2563eb" : `1.5px solid ${tier.border}`,
                      borderRadius: 8,
                      padding: "10px 6px",
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                      justifyContent: "space-between",
                      minHeight: 70,
                      cursor: "pointer",
                      position: "relative",
                      outline: "none",
                      boxShadow: isSelected
                        ? "0 0 0 3px rgba(37, 99, 235, 0.25), 0 4px 12px rgba(37, 99, 235, 0.15)"
                        : "0 1px 2px rgba(15, 23, 42, 0.03)",
                      transform: isSelected ? "scale(1.03)" : "none",
                      transition: "all 0.15s ease",
                    }}
                    title={`Likelihood ${likelihood} × Impact ${impact} = Score ${score}/25 (${tier.name})\n${tier.description}\nOpen findings: ${count}`}
                  >
                    {/* Tiny score indicator */}
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        width: "100%",
                        padding: "0 4px",
                        fontSize: "0.66rem",
                        fontWeight: 700,
                        color: tier.color,
                        opacity: 0.8,
                      }}
                    >
                      <span>{tier.name.split(" ")[0]}</span>
                      <span>{score}</span>
                    </div>

                    {/* Prominent count badge */}
                    <div style={{ margin: "4px 0", textAlign: "center" }}>
                      {count > 0 ? (
                        <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                          <span
                            style={{
                              backgroundColor: tier.badgeBg,
                              color: tier.badgeColor,
                              fontWeight: 800,
                              fontSize: "1rem",
                              lineHeight: 1,
                              padding: "4px 12px",
                              borderRadius: 14,
                              boxShadow: "0 2px 4px rgba(0, 0, 0, 0.12)",
                              display: "inline-block",
                            }}
                          >
                            {count}
                          </span>
                          <span
                            style={{
                              fontSize: "0.62rem",
                              fontWeight: 700,
                              color: tier.color,
                              marginTop: 3,
                              textTransform: "uppercase",
                              letterSpacing: "0.03em",
                            }}
                          >
                            {count === 1 ? "finding" : "findings"}
                          </span>
                        </div>
                      ) : (
                        <span
                          style={{
                            fontSize: "0.85rem",
                            fontWeight: 600,
                            color: tier.color,
                            opacity: 0.35,
                          }}
                        >
                          0
                        </span>
                      )}
                    </div>

                    <div style={{ height: 2 }} />
                  </button>
                );
              })}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Educational Study Guide / Legend Bar */}
      <div
        style={{
          marginTop: 18,
          paddingTop: 14,
          borderTop: "1px solid var(--line, #e2e8f0)",
          display: "flex",
          flexWrap: "wrap",
          gap: 16,
          alignItems: "center",
          justifyContent: "space-between",
          fontSize: "0.78rem",
          color: "var(--muted, #64748b)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
          <strong style={{ color: "var(--ink, #0f172a)", fontSize: "0.8rem" }}>Risk Severity Tiers:</strong>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              style={{
                width: 12,
                height: 12,
                borderRadius: 3,
                backgroundColor: "#dc2626",
                display: "inline-block",
              }}
            />
            <span style={{ fontWeight: 600, color: "#991b1b" }}>Extreme (16–25)</span>
            <span style={{ fontSize: "0.73rem" }}>— Active KEV / Critical (24h SLA)</span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              style={{
                width: 12,
                height: 12,
                borderRadius: 3,
                backgroundColor: "#ea580c",
                display: "inline-block",
              }}
            />
            <span style={{ fontWeight: 600, color: "#9a3412" }}>High (10–15)</span>
            <span style={{ fontSize: "0.73rem" }}>— High Impact / Confirmed (7–14d SLA)</span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              style={{
                width: 12,
                height: 12,
                borderRadius: 3,
                backgroundColor: "#ca8a04",
                display: "inline-block",
              }}
            />
            <span style={{ fontWeight: 600, color: "#854d0e" }}>Medium (5–9)</span>
            <span style={{ fontSize: "0.73rem" }}>— Moderate Flaws</span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              style={{
                width: 12,
                height: 12,
                borderRadius: 3,
                backgroundColor: "#16a34a",
                display: "inline-block",
              }}
            />
            <span style={{ fontWeight: 600, color: "#166534" }}>Low (1–4)</span>
            <span style={{ fontSize: "0.73rem" }}>— Hygiene & Hardening</span>
          </div>
        </div>

        <div style={{ fontSize: "0.73rem", fontStyle: "italic", color: "var(--muted, #64748b)" }}>
          Standardized under ISO 27005 & NIST SP 800-30 Quantitative Matrix
        </div>
      </div>
    </div>
  );
}
