export type ConfidenceLevel = "high" | "medium" | "low";
export type LicenseRiskTier =
  | "permissive"
  | "weak_copyleft"
  | "restricted_copyleft"
  | "unknown";

export interface ScanFindingPhase6A {
  id: number | string;
  scan_id: number | string;
  project_id: number | string;
  engine: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  file_path: string;
  line_number: number;
  cwe?: string | null;
  owasp?: string | null;
  code_snippet?: string | null;
  countermeasure?: string | null;
  fingerprint: string;
  status: "open" | "triage" | "fixed" | "false_positive";
  is_suppressed: boolean;
  // Phase 6A fields
  cve_id?: string | null;
  matched_engines: string[];
  engine_count: number;
  confidence_level: ConfidenceLevel;
  epss_score?: number | null;
  epss_percentile?: number | null;
  is_kev: boolean;
  kev_due_date?: string | null;
  effective_priority_score: number;
  sla_due_at?: string | null;
  sla_breached?: boolean;
}


export interface SbomComponentItem {
  name: string;
  version: string;
  purl: string;
  ecosystem: string;
  licenses: string[];
  risk_tier: LicenseRiskTier;
  source_file?: string;
}

export interface SbomLicenseSummary {
  permissive: number;
  weak_copyleft: number;
  restricted_copyleft: number;
  unknown: number;
  by_license: Record<string, number>;
}

export interface ScanSbomResponse {
  scan_id: number | string;
  project_id: number | string;
  spec_version: string;
  component_count: number;
  policy_violations_count: number;
  license_summary: SbomLicenseSummary;
  components: SbomComponentItem[];
  created_at?: string | null;
}

export type FindingQuickFilter =
  | "all"
  | "kev"
  | "high_epss"
  | "multi_engine"
  | "license";
