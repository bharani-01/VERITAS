export type SortOption =
  | "risk_desc"
  | "risk_asc"
  | "priority_desc"
  | "severity_desc"
  | "severity_asc"
  | "epss_desc"
  | "title_asc"
  | "title_desc"
  | "engine_asc"
  | "sla_asc";

export type GroupByOption =
  | "none"
  | "severity"
  | "vuln_family"
  | "engine"
  | "status"
  | "exploitability";

export type ThreatFilter = "all" | "kev" | "high_epss" | "multi_engine" | "license";

interface FindingsToolbarProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  sortBy: SortOption;
  onSortChange: (sort: SortOption) => void;
  groupBy: GroupByOption;
  onGroupChange: (group: GroupByOption) => void;
  severityFilter: string;
  onSeverityFilterChange: (sev: string) => void;
  threatFilter: ThreatFilter;
  onThreatFilterChange: (th: ThreatFilter) => void;
  totalCount: number;
  filteredCount: number;
  onResetFilters: () => void;
  hasActiveFilters: boolean;
}

export function FindingsToolbar({
  searchQuery,
  onSearchChange,
  sortBy,
  onSortChange,
  groupBy,
  onGroupChange,
  severityFilter,
  onSeverityFilterChange,
  threatFilter,
  onThreatFilterChange,
  totalCount,
  filteredCount,
  onResetFilters,
  hasActiveFilters,
}: FindingsToolbarProps) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 10,
        marginBottom: 12,
        paddingBottom: 10,
        borderBottom: "1px solid var(--line, #e2e8f0)",
      }}
    >
      {/* Top row: Search input + Results summary */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: 10,
        }}
      >
        <div style={{ position: "relative", flex: "1 1 240px", minWidth: 200, maxWidth: 360 }}>
          <input
            type="text"
            placeholder="Search title, file, CVE, or rule ID…"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            style={{
              width: "100%",
              padding: "6px 10px 6px 30px",
              fontSize: "0.82rem",
              borderRadius: 6,
              border: "1px solid var(--line, #cbd5e1)",
              backgroundColor: "var(--bg, #f8fafc)",
              color: "var(--ink, #0f172a)",
              outline: "none",
            }}
          />
          <svg
            viewBox="0 0 20 20"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.75"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
            style={{
              position: "absolute",
              left: 9,
              top: "50%",
              transform: "translateY(-50%)",
              width: 14,
              height: 14,
              color: "var(--muted, #64748b)",
              pointerEvents: "none",
            }}
          >
            <circle cx="8.5" cy="8.5" r="5.5" />
            <path d="M16 16l-3.6-3.6" />
          </svg>
          {searchQuery ? (
            <button
              type="button"
              onClick={() => onSearchChange("")}
              style={{
                position: "absolute",
                right: 8,
                top: "50%",
                transform: "translateY(-50%)",
                background: "none",
                border: "none",
                color: "var(--muted, #64748b)",
                cursor: "pointer",
                fontSize: "0.85rem",
                padding: "2px 4px",
                lineHeight: 1,
              }}
              title="Clear search"
            >
              x
            </button>
          ) : null}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: "0.8rem" }}>
          <span style={{ color: "var(--muted, #64748b)" }}>
            Showing <strong>{filteredCount}</strong> of <strong>{totalCount}</strong> findings
          </span>
          {hasActiveFilters ? (
            <button
              type="button"
              onClick={onResetFilters}
              style={{
                background: "none",
                border: "none",
                color: "var(--accent, #2563eb)",
                fontSize: "0.8rem",
                fontWeight: 600,
                cursor: "pointer",
                padding: "2px 6px",
                textDecoration: "underline",
              }}
            >
              Reset filters
            </button>
          ) : null}
        </div>
      </div>

      {/* Controls row: Sort By, Group By, Threat, Severity */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 10,
          fontSize: "0.8rem",
        }}
      >
        {/* Sort By */}
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <label style={{ fontWeight: 600, color: "var(--ink-soft, #334155)", whiteSpace: "nowrap" }}>
            Sort by:
          </label>
          <select
            value={sortBy}
            onChange={(e) => onSortChange(e.target.value as SortOption)}
            style={{
              padding: "4px 8px",
              borderRadius: 6,
              border: "1px solid var(--line, #cbd5e1)",
              backgroundColor: "var(--bg, #f8fafc)",
              color: "var(--ink, #0f172a)",
              fontSize: "0.8rem",
              fontWeight: 500,
              cursor: "pointer",
              outline: "none",
            }}
          >
            <option value="risk_desc">Risk Score (High to Low)</option>
            <option value="risk_asc">Risk Score (Low to High)</option>
            <option value="priority_desc">Priority / Exploit Score (High to Low)</option>
            <option value="severity_desc">Severity (Critical to Info)</option>
            <option value="severity_asc">Severity (Info to Critical)</option>
            <option value="epss_desc">EPSS Score (Highest Exploitability)</option>
            <option value="title_asc">Title (A to Z)</option>
            <option value="title_desc">Title (Z to A)</option>
            <option value="engine_asc">Detection Engine (A to Z)</option>
            <option value="sla_asc">SLA Due Date (Urgent / Breached)</option>
          </select>
        </div>

        {/* Group By */}
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <label style={{ fontWeight: 600, color: "var(--ink-soft, #334155)", whiteSpace: "nowrap" }}>
            Group by:
          </label>
          <select
            value={groupBy}
            onChange={(e) => onGroupChange(e.target.value as GroupByOption)}
            style={{
              padding: "4px 8px",
              borderRadius: 6,
              border: "1px solid var(--line, #cbd5e1)",
              backgroundColor: "var(--bg, #f8fafc)",
              color: "var(--ink, #0f172a)",
              fontSize: "0.8rem",
              fontWeight: 500,
              cursor: "pointer",
              outline: "none",
            }}
          >
            <option value="none">None (Flat list)</option>
            <option value="severity">Severity (Critical, High, Medium, Low)</option>
            <option value="vuln_family">Vulnerability Category (SAST, SCA, Secret)</option>
            <option value="engine">Detection Engine (Semgrep, Trivy, Gitleaks)</option>
            <option value="status">Finding Status (Open, Triaged, Fixed)</option>
            <option value="exploitability">Threat Level (KEV, High EPSS, Standard)</option>
          </select>
        </div>

        {/* Threat Filter (KEV / EPSS / Multi-Engine / License) */}
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <label style={{ fontWeight: 600, color: "var(--ink-soft, #334155)", whiteSpace: "nowrap" }}>
            Threat:
          </label>
          <select
            value={threatFilter}
            onChange={(e) => onThreatFilterChange(e.target.value as ThreatFilter)}
            style={{
              padding: "4px 8px",
              borderRadius: 6,
              border: threatFilter !== "all" ? "1px solid #2563eb" : "1px solid var(--line, #cbd5e1)",
              backgroundColor: threatFilter !== "all" ? "#eff6ff" : "var(--bg, #f8fafc)",
              color: threatFilter !== "all" ? "#1e40af" : "var(--ink, #0f172a)",
              fontSize: "0.8rem",
              fontWeight: threatFilter !== "all" ? 600 : 500,
              cursor: "pointer",
              outline: "none",
            }}
          >
            <option value="all">All Findings</option>
            <option value="kev">Actively Exploited (KEV)</option>
            <option value="high_epss">High EPSS (&gt;10%)</option>
            <option value="multi_engine">Multi-Engine Confirmed (2+)</option>
            <option value="license">License Risks</option>
          </select>
        </div>

        {/* Severity Filter */}
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <label style={{ fontWeight: 600, color: "var(--ink-soft, #334155)", whiteSpace: "nowrap" }}>
            Severity:
          </label>
          <select
            value={severityFilter}
            onChange={(e) => onSeverityFilterChange(e.target.value)}
            style={{
              padding: "4px 8px",
              borderRadius: 6,
              border: severityFilter !== "all" ? "1px solid #2563eb" : "1px solid var(--line, #cbd5e1)",
              backgroundColor: severityFilter !== "all" ? "#eff6ff" : "var(--bg, #f8fafc)",
              color: severityFilter !== "all" ? "#1e40af" : "var(--ink, #0f172a)",
              fontSize: "0.8rem",
              fontWeight: severityFilter !== "all" ? 600 : 500,
              cursor: "pointer",
              outline: "none",
            }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>
    </div>
  );
}
