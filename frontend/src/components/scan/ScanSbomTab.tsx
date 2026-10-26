import React, { useEffect, useMemo, useState } from "react";
import type { LicenseRiskTier, ScanSbomResponse } from "../../types/phase6a";

interface ScanSbomTabProps {
  projectId: string | number;
  scanId: string | number;
}

const TIER_BADGE_STYLES: Record<
  LicenseRiskTier,
  { label: string; bg: string; border: string; color: string }
> = {
  permissive: {
    label: "Permissive",
    bg: "#ecfdf5",
    border: "#10b981",
    color: "#065f46",
  },
  weak_copyleft: {
    label: "Weak Copyleft",
    bg: "#fffbeb",
    border: "#f59e0b",
    color: "#92400e",
  },
  restricted_copyleft: {
    label: "Restricted Copyleft · Violation",
    bg: "#fee2e2",
    border: "#ef4444",
    color: "#991b1b",
  },
  unknown: {
    label: "Unknown / Unmapped",
    bg: "#f8fafc",
    border: "#cbd5e1",
    color: "#334155",
  },
};

export const ScanSbomTab: React.FC<ScanSbomTabProps> = ({
  projectId,
  scanId,
}) => {
  const [sbom, setSbom] = useState<ScanSbomResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [tierFilter, setTierFilter] = useState<string>("all");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    fetch(`/workspace/projects/${projectId}/scans/${scanId}/sbom`, {
      credentials: "include",
    })
      .then(async (res) => {
        if (!res.ok) {
          const errBody = await res.json().catch(() => ({}));
          throw new Error(errBody.detail || `Failed to load SBOM (${res.status})`);
        }
        return res.json() as Promise<ScanSbomResponse>;
      })
      .then((data) => {
        if (!cancelled) {
          setSbom(data);
        }
      })
      .catch((err: Error) => {
        if (!cancelled) {
          setError(err.message);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [projectId, scanId]);

  const filteredComponents = useMemo(() => {
    if (!sbom) return [];
    const q = searchQuery.trim().toLowerCase();
    return sbom.components.filter((comp) => {
      if (tierFilter !== "all" && comp.risk_tier !== tierFilter) {
        return false;
      }
      if (!q) return true;
      return (
        comp.name.toLowerCase().includes(q) ||
        comp.version.toLowerCase().includes(q) ||
        comp.purl.toLowerCase().includes(q) ||
        comp.licenses.some((lic) => lic.toLowerCase().includes(q))
      );
    });
  }, [sbom, searchQuery, tierFilter]);

  const handleDownloadCycloneDx = () => {
    window.location.href = `/workspace/projects/${projectId}/scans/${scanId}/sbom/download`;
  };

  if (loading) {
    return (
      <div
        style={{
          padding: "32px",
          textAlign: "center",
          color: "var(--muted, #64748b)",
          backgroundColor: "var(--surface, #ffffff)",
          border: "1px solid var(--line, #e2e8f0)",
          borderRadius: "12px",
        }}
      >
        Loading CycloneDX 1.5 Software Bill of Materials...
      </div>
    );
  }

  if (error || !sbom) {
    return (
      <div
        style={{
          padding: "24px",
          color: "#991b1b",
          backgroundColor: "#fee2e2",
          border: "1px solid #ef4444",
          borderRadius: "12px",
        }}
      >
        {error || "No SBOM artifact available for this scan."}
      </div>
    );
  }

  const summaryCards = [
    {
      title: "Total Components",
      value: sbom.component_count,
      subtitle: sbom.spec_version,
      accent: "#2563eb",
    },
    {
      title: "Permissive",
      value: sbom.license_summary.permissive ?? 0,
      subtitle: "MIT, Apache-2.0, BSD, ISC",
      accent: "#059669",
    },
    {
      title: "Weak Copyleft",
      value: sbom.license_summary.weak_copyleft ?? 0,
      subtitle: "LGPL, MPL-2.0, EPL",
      accent: "#d97706",
    },
    {
      title: "Restricted / Policy Violations",
      value: sbom.policy_violations_count,
      subtitle: "GPL, AGPL, SSPL",
      accent: sbom.policy_violations_count > 0 ? "#dc2626" : "#64748b",
    },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "18px" }}>
      {/* 1. Four Summary Cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "14px",
        }}
      >
        {summaryCards.map((card) => (
          <div
            key={card.title}
            style={{
              padding: "16px 18px",
              borderRadius: "12px",
              backgroundColor: "var(--surface, #ffffff)",
              border: "1px solid var(--line, #e2e8f0)",
              borderTop: `3px solid ${card.accent}`,
              boxShadow: "0 1px 3px rgba(0,0,0,0.05)",
            }}
          >
            <div style={{ fontSize: "0.78rem", color: "var(--muted, #64748b)", fontWeight: 600 }}>
              {card.title}
            </div>
            <div
              style={{
                fontSize: "1.65rem",
                fontWeight: 700,
                color: "var(--ink, #0f172a)",
                margin: "6px 0 4px",
              }}
            >
              {card.value}
            </div>
            <div style={{ fontSize: "0.72rem", color: "var(--muted, #64748b)" }}>
              {card.subtitle}
            </div>
          </div>
        ))}
      </div>

      {/* 2. Search, Filter & Download Bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "12px",
          padding: "12px 16px",
          borderRadius: "10px",
          backgroundColor: "var(--surface, #ffffff)",
          border: "1px solid var(--line, #e2e8f0)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            flex: "1 1 320px",
          }}
        >
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by package name, PURL, or SPDX license (e.g. AGPL-3.0, MIT)..."
            style={{
              flex: 1,
              padding: "8px 12px",
              borderRadius: "8px",
              backgroundColor: "var(--surface, #ffffff)",
              border: "1px solid var(--line-strong, #cbd5e1)",
              color: "var(--ink, #0f172a)",
              fontSize: "0.84rem",
            }}
          />

          <select
            value={tierFilter}
            onChange={(e) => setTierFilter(e.target.value)}
            style={{
              padding: "8px 12px",
              borderRadius: "8px",
              backgroundColor: "var(--surface, #ffffff)",
              border: "1px solid var(--line-strong, #cbd5e1)",
              color: "var(--ink, #0f172a)",
              fontSize: "0.84rem",
            }}
          >
            <option value="all">All Policy Tiers</option>
            <option value="restricted_copyleft">Restricted Copyleft</option>
            <option value="weak_copyleft">Weak Copyleft</option>
            <option value="permissive">Permissive</option>
            <option value="unknown">Unknown</option>
          </select>
        </div>

        <button
          type="button"
          onClick={handleDownloadCycloneDx}
          style={{
            padding: "8px 16px",
            borderRadius: "8px",
            backgroundColor: "var(--accent, #2563eb)",
            border: "none",
            color: "#ffffff",
            fontWeight: 600,
            fontSize: "0.84rem",
            cursor: "pointer",
          }}
        >
          Download CycloneDX (.cdx.json)
        </button>
      </div>

      {/* 3. Component Table */}
      <div
        style={{
          overflowX: "auto",
          borderRadius: "12px",
          border: "1px solid var(--line, #e2e8f0)",
          backgroundColor: "var(--surface, #ffffff)",
        }}
      >
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            textAlign: "left",
            fontSize: "0.84rem",
            color: "var(--ink, #0f172a)",
          }}
        >
          <thead>
            <tr
              style={{
                borderBottom: "1px solid var(--line, #e2e8f0)",
                backgroundColor: "var(--bg, #f8fafc)",
                color: "var(--ink-soft, #334155)",
                fontSize: "0.75rem",
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.06em",
              }}
            >
              <th style={{ padding: "12px 16px" }}>Package</th>
              <th style={{ padding: "12px 16px" }}>Version</th>
              <th style={{ padding: "12px 16px" }}>Ecosystem / PURL</th>
              <th style={{ padding: "12px 16px" }}>License</th>
              <th style={{ padding: "12px 16px" }}>Policy Status</th>
            </tr>
          </thead>
          <tbody>
            {filteredComponents.length === 0 ? (
              <tr>
                <td
                  colSpan={5}
                  style={{
                    padding: "24px",
                    textAlign: "center",
                    color: "var(--muted, #64748b)",
                  }}
                >
                  No components match the current filter.
                </td>
              </tr>
            ) : (
              filteredComponents.map((comp) => {
                const badge =
                  TIER_BADGE_STYLES[comp.risk_tier] || TIER_BADGE_STYLES.unknown;
                return (
                  <tr
                    key={comp.purl}
                    style={{
                      borderBottom: "1px solid var(--line, #e2e8f0)",
                    }}
                  >
                    <td style={{ padding: "11px 16px", fontWeight: 600, color: "var(--ink, #0f172a)" }}>
                      {comp.name}
                    </td>
                    <td
                      style={{
                        padding: "11px 16px",
                        fontFamily: "monospace",
                        color: "var(--accent, #2563eb)",
                        fontWeight: 600,
                      }}
                    >
                      {comp.version}
                    </td>
                    <td
                      style={{
                        padding: "11px 16px",
                        fontFamily: "monospace",
                        fontSize: "0.76rem",
                        color: "var(--muted, #64748b)",
                      }}
                    >
                      {comp.purl}
                    </td>
                    <td
                      style={{
                        padding: "11px 16px",
                        fontFamily: "monospace",
                        fontSize: "0.78rem",
                        color: "var(--ink-soft, #334155)",
                      }}
                    >
                      {comp.licenses.join(", ")}
                    </td>
                    <td style={{ padding: "11px 16px" }}>
                      <span
                        style={{
                          display: "inline-block",
                          padding: "3px 9px",
                          borderRadius: "999px",
                          fontSize: "0.72rem",
                          fontWeight: 700,
                          backgroundColor: badge.bg,
                          border: `1px solid ${badge.border}`,
                          color: badge.color,
                        }}
                      >
                        {badge.label}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
