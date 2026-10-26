import React from "react";
import type {
  FindingQuickFilter,
  ScanFindingPhase6A,
} from "../../types/phase6a";

export const DeduplicationCalloutBanner: React.FC<{
  rawCount: number;
  correlatedCount: number;
  kevCount?: number;
}> = ({ rawCount, correlatedCount, kevCount = 0 }) => {
  const saved = Math.max(0, rawCount - correlatedCount);

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexWrap: "wrap",
        gap: "12px",
        padding: "10px 16px",
        marginBottom: "16px",
        borderRadius: "10px",
        background: "linear-gradient(90deg, #eff6ff 0%, #f8fafc 100%)",
        border: "1px solid #bfdbfe",
        color: "#1e3a8a",
        fontSize: "0.85rem",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <span
          style={{
            display: "inline-block",
            width: "8px",
            height: "8px",
            borderRadius: "50%",
            backgroundColor: "#2563eb",
            boxShadow: "0 0 6px rgba(37, 99, 235, 0.4)",
          }}
        />
        <span>
          <strong style={{ color: "#0f172a" }}>Deduplicated across 12 engines</strong> &middot;{" "}
          <span style={{ color: "#1d4ed8", fontWeight: 700 }}>
            {correlatedCount} canonical findings
          </span>
          {saved > 0 && (
            <span style={{ color: "#475569" }}>
              {" "}
              ({saved} duplicate tool hits merged from {rawCount} raw alerts)
            </span>
          )}
        </span>
      </div>

      {kevCount > 0 && (
        <span
          style={{
            padding: "3px 10px",
            borderRadius: "999px",
            backgroundColor: "#fee2e2",
            border: "1px solid #ef4444",
            color: "#991b1b",
            fontWeight: 700,
            fontSize: "0.75rem",
            letterSpacing: "0.04em",
          }}
        >
          {kevCount} CISA KEV ACTIVE EXPLOIT{kevCount > 1 ? "S" : ""}
        </span>
      )}
    </div>
  );
};

export const Phase6AFindingBadges: React.FC<{
  finding: ScanFindingPhase6A;
}> = ({ finding }) => {
  const epssPct =
    finding.epss_score !== null && finding.epss_score !== undefined
      ? finding.epss_score * 100
      : null;

  const getEpssStyles = (pct: number): React.CSSProperties => {
    if (pct >= 30) {
      return {
        backgroundColor: "#fef2f2",
        border: "1px solid #f87171",
        color: "#991b1b",
      };
    }
    if (pct >= 10) {
      return {
        backgroundColor: "#fffbeb",
        border: "1px solid #f59e0b",
        color: "#92400e",
      };
    }
    return {
      backgroundColor: "#f8fafc",
      border: "1px solid #cbd5e1",
      color: "#334155",
    };
  };

  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "6px",
      }}
    >
      {/* 1. CISA KEV Badge */}
      {finding.is_kev && (
        <span
          title={
            finding.kev_due_date
              ? `CISA KEV Mandate Due: ${finding.kev_due_date}`
              : "Listed in CISA Known Exploited Vulnerabilities Catalog"
          }
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "5px",
            padding: "2px 8px",
            borderRadius: "6px",
            backgroundColor: "#fee2e2",
            border: "1px solid #ef4444",
            color: "#991b1b",
            fontSize: "0.7rem",
            fontWeight: 800,
            letterSpacing: "0.05em",
            textTransform: "uppercase",
            boxShadow: "0 0 6px rgba(239, 68, 68, 0.15)",
          }}
        >
          ACTIVE EXPLOIT &middot; KEV
        </span>
      )}

      {/* 2. CVE Identifier Pill */}
      {finding.cve_id && (
        <span
          style={{
            padding: "2px 7px",
            borderRadius: "6px",
            backgroundColor: "#eff6ff",
            border: "1px solid #bfdbfe",
            color: "#1d4ed8",
            fontSize: "0.72rem",
            fontFamily: "monospace",
            fontWeight: 700,
          }}
        >
          {finding.cve_id}
        </span>
      )}

      {/* 3. EPSS Probability Pill */}
      {epssPct !== null && (
        <span
          title={
            finding.epss_percentile
              ? `30-day exploit probability (${(
                  finding.epss_percentile * 100
                ).toFixed(1)}th percentile)`
              : "FIRST EPSS 30-day exploit probability"
          }
          style={{
            padding: "2px 7px",
            borderRadius: "6px",
            fontSize: "0.72rem",
            fontWeight: 700,
            ...getEpssStyles(epssPct),
          }}
        >
          EPSS: {epssPct.toFixed(1)}%
        </span>
      )}

      {/* 4. Multi-Engine Confirmation Pill */}
      {finding.engine_count > 1 && (
        <span
          title={`Confirmed by: ${finding.matched_engines.join(", ")}`}
          style={{
            padding: "2px 8px",
            borderRadius: "6px",
            backgroundColor: "#ecfdf5",
            border: "1px solid #10b981",
            color: "#065f46",
            fontSize: "0.72rem",
            fontWeight: 700,
            cursor: "help",
          }}
        >
          Confirmed by {finding.engine_count} engines
        </span>
      )}

      {/* 5. Effective Priority Score Badge */}
      <span
        title="Composite VERITAS Priority Score (Severity + CISA KEV + EPSS + Multi-Engine Consensus)"
        style={{
          padding: "2px 7px",
          borderRadius: "6px",
          backgroundColor: "#f1f5f9",
          border: "1px solid #cbd5e1",
          color: "#0f172a",
          fontSize: "0.72rem",
          fontFamily: "monospace",
          fontWeight: 700,
        }}
      >
        P-Score: {finding.effective_priority_score.toFixed(1)}/10
      </span>

      {/* 6. SLA Tracking Pill */}
      {finding.sla_breached ? (
        <span
          style={{
            padding: "1px 6px",
            borderRadius: "5px",
            backgroundColor: "#fee2e2",
            border: "1px solid #ef4444",
            color: "#991b1b",
            fontSize: "0.68rem",
            fontWeight: 700,
          }}
        >
          SLA BREACHED
        </span>
      ) : finding.sla_due_at && finding.status === "open" ? (
        <span
          style={{
            padding: "1px 6px",
            borderRadius: "5px",
            backgroundColor: "#f1f5f9",
            border: "1px solid #cbd5e1",
            color: "#334155",
            fontSize: "0.68rem",
            fontWeight: 600,
          }}
        >
          SLA: {Math.max(0, Math.ceil((new Date(finding.sla_due_at).getTime() - Date.now()) / 86400000))}d left
        </span>
      ) : null}
    </div>
  );
};

export const FindingQuickFilterBar: React.FC<{
  activeFilter: FindingQuickFilter;
  onSelectFilter: (filter: FindingQuickFilter) => void;
  findings: ScanFindingPhase6A[];
}> = ({ activeFilter, onSelectFilter, findings }) => {
  const kevCount = findings.filter((f) => f.is_kev).length;
  const highEpssCount = findings.filter(
    (f) => (f.epss_score ?? 0) >= 0.1
  ).length;
  const multiEngineCount = findings.filter((f) => f.engine_count >= 2).length;
  const licenseCount = findings.filter(
    (f) => f.category === "license" || f.engine === "trivy_license"
  ).length;

  const chips: Array<{
    id: FindingQuickFilter;
    label: string;
    count: number;
    accent: string;
  }> = [
    { id: "all", label: "All", count: findings.length, accent: "#2563eb" },
    {
      id: "kev",
      label: "Actively Exploited (KEV)",
      count: kevCount,
      accent: "#dc2626",
    },
    {
      id: "high_epss",
      label: "High EPSS (>10%)",
      count: highEpssCount,
      accent: "#d97706",
    },
    {
      id: "multi_engine",
      label: "Multi-Engine Confirmed (2+)",
      count: multiEngineCount,
      accent: "#059669",
    },
    {
      id: "license",
      label: "License Risks",
      count: licenseCount,
      accent: "#7c3aed",
    },
  ];

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "8px",
        marginBottom: "14px",
      }}
    >
      {chips.map((chip) => {
        const isActive = activeFilter === chip.id;
        return (
          <button
            key={chip.id}
            type="button"
            onClick={() => onSelectFilter(chip.id)}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              padding: "6px 14px",
              borderRadius: "999px",
              fontSize: "0.8rem",
              fontWeight: 600,
              cursor: "pointer",
              transition: "all 0.15s ease",
              backgroundColor: isActive ? chip.accent : "#ffffff",
              border: isActive ? `1.5px solid ${chip.accent}` : "1.5px solid #cbd5e1",
              color: isActive ? "#ffffff" : "#334155",
              boxShadow: isActive ? `0 2px 6px ${chip.accent}33` : "none",
            }}
          >
            <span>{chip.label}</span>
            <span
              style={{
                padding: "1px 7px",
                borderRadius: "999px",
                fontSize: "0.72rem",
                fontWeight: 700,
                backgroundColor: isActive ? "rgba(255, 255, 255, 0.28)" : "#f1f5f9",
                color: isActive ? "#ffffff" : "#475569",
                border: isActive ? "none" : "1px solid #e2e8f0",
              }}
            >
              {chip.count}
            </span>
          </button>
        );
      })}
    </div>
  );
};
