import React, { useMemo, useState } from "react";
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
  const [tiersOpen, setTiersOpen] = useState(false);
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
        marginBottom: 16,
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
          marginBottom: 10,
          paddingBottom: 8,
          borderBottom: "1px solid var(--line, #e2e8f0)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <h4 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 700, color: "var(--ink, #0f172a)" }}>
            Risk Assessment Matrix
          </h4>
        </div>

        {selectedCell ? (
          <button
            type="button"
            onClick={() => onSelectCell(null)}
            style={{
              padding: "3px 10px",
              borderRadius: 20,
              fontSize: "0.74rem",
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
            Clear Filter (L{selectedCell.likelihood} × I{selectedCell.impact}) x
          </button>
        ) : null}
      </div>

      {/* Active filter notification banner */}
      {selectedCell && activeTier ? (
        <div
          style={{
            padding: "6px 12px",
            marginBottom: 10,
            borderRadius: 6,
            backgroundColor: activeTier.bg,
            border: `1px solid ${activeTier.border}`,
            color: activeTier.color,
            fontSize: "0.8rem",
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

      {/* Grid container */}
      <div style={{ overflowX: "auto", paddingBottom: 2 }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "125px repeat(5, minmax(0, 1fr))",
            gap: 5,
            width: "100%",
          }}
        >
          {/* Header Row: Column Titles (Likelihood Levels) */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "flex-end",
              padding: "4px 8px",
              fontWeight: 700,
              fontSize: "0.68rem",
              color: "var(--muted, #64748b)",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
            }}
          >
            <span>Impact ↓ \ Likelihood →</span>
          </div>
          {[1, 2, 3, 4, 5].map((l) => (
            <div
              key={l}
              title={`${LIKELIHOOD_METADATA[l].title}: ${LIKELIHOOD_METADATA[l].subtitle}`}
              style={{
                textAlign: "center",
                padding: "6px 2px",
                fontWeight: 600,
                fontSize: "0.74rem",
                color: "var(--ink-soft, #334155)",
              }}
            >
              {l === 5 ? "5 · Certain" : LIKELIHOOD_METADATA[l].title}
            </div>
          ))}

          {/* Impact Rows 5 down to 1 */}
          {[5, 4, 3, 2, 1].map((impact) => (
            <React.Fragment key={impact}>
              {/* Row Header: Impact Level */}
              <div
                title={`${IMPACT_METADATA[impact].title}: ${IMPACT_METADATA[impact].subtitle}`}
                style={{
                  display: "flex",
                  alignItems: "center",
                  padding: "4px 8px",
                  fontWeight: 600,
                  fontSize: "0.74rem",
                  color: "var(--ink-soft, #334155)",
                  whiteSpace: "nowrap",
                }}
              >
                {IMPACT_METADATA[impact].title}
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
                      height: 40,
                      backgroundColor: tier.bg,
                      border: isSelected ? "2.5px solid #2563eb" : `1px solid ${tier.border}`,
                      borderRadius: 6,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      cursor: "pointer",
                      position: "relative",
                      outline: "none",
                      boxShadow: isSelected
                        ? "0 0 0 2px rgba(37, 99, 235, 0.3)"
                        : "none",
                      transform: isSelected ? "scale(1.04)" : "none",
                      transition: "all 0.12s ease",
                    }}
                    title={`Likelihood ${likelihood} × Impact ${impact} = Score ${score}/25 (${tier.name})\n${count} finding${count === 1 ? "" : "s"}\nClick to filter`}
                  >
                    {count > 0 ? (
                      <span
                        style={{
                          minWidth: 22,
                          height: 22,
                          padding: "0 6px",
                          borderRadius: 11,
                          backgroundColor: tier.badgeBg,
                          color: tier.badgeColor,
                          fontWeight: 800,
                          fontSize: "0.8rem",
                          lineHeight: "22px",
                          textAlign: "center",
                          boxShadow: "0 1px 3px rgba(0, 0, 0, 0.18)",
                        }}
                      >
                        {count}
                      </span>
                    ) : (
                      <span
                        style={{
                          fontSize: "0.68rem",
                          fontWeight: 600,
                          color: tier.color,
                          opacity: 0.3,
                        }}
                      >
                        {score}
                      </span>
                    )}
                  </button>
                );
              })}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Expandable Severity Tiers */}
      <div
        style={{
          marginTop: 10,
          paddingTop: 8,
          borderTop: "1px solid var(--line, #e2e8f0)",
          display: "flex",
          flexDirection: "column",
          gap: 8,
        }}
      >
        <button
          type="button"
          onClick={() => setTiersOpen((prev) => !prev)}
          style={{
            background: "none",
            border: "none",
            padding: "2px 0",
            cursor: "pointer",
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            color: "var(--muted, #64748b)",
            fontSize: "0.76rem",
            fontWeight: 600,
            width: "fit-content",
          }}
        >
          <span
            style={{
              display: "inline-block",
              transform: tiersOpen ? "rotate(90deg)" : "rotate(0deg)",
              transition: "transform 0.15s ease",
              fontSize: "0.62rem",
            }}
          >
            ▶
          </span>
          <span>{tiersOpen ? "Hide Severity Tiers" : "Severity Tiers"}</span>
        </button>

        {tiersOpen && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 16,
              flexWrap: "wrap",
              fontSize: "0.76rem",
              paddingTop: 4,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: 2,
                  backgroundColor: "#dc2626",
                  display: "inline-block",
                }}
              />
              <span style={{ fontWeight: 600, color: "#991b1b" }}>Extreme (16–25)</span>
              <span style={{ fontSize: "0.72rem", color: "var(--muted, #64748b)" }}>
                — Active KEV / Critical (24h SLA)
              </span>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: 2,
                  backgroundColor: "#ea580c",
                  display: "inline-block",
                }}
              />
              <span style={{ fontWeight: 600, color: "#9a3412" }}>High (10–15)</span>
              <span style={{ fontSize: "0.72rem", color: "var(--muted, #64748b)" }}>
                — High Impact / Confirmed (7–14d SLA)
              </span>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: 2,
                  backgroundColor: "#ca8a04",
                  display: "inline-block",
                }}
              />
              <span style={{ fontWeight: 600, color: "#854d0e" }}>Medium (5–9)</span>
              <span style={{ fontSize: "0.72rem", color: "var(--muted, #64748b)" }}>
                — Moderate Flaws
              </span>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: 2,
                  backgroundColor: "#16a34a",
                  display: "inline-block",
                }}
              />
              <span style={{ fontWeight: 600, color: "#166534" }}>Low (1–4)</span>
              <span style={{ fontSize: "0.72rem", color: "var(--muted, #64748b)" }}>
                — Hygiene & Hardening
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
