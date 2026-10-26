export type Project = {
  id: string;
  name: string;
  description: string;
  github_repo_id: number | null;
  github_repo_full_name: string | null;
  github_default_branch: string | null;
  github_html_url: string | null;
  security_level?: string;
  base_url?: string | null;
  criticality?: string;
  notify_email_default?: boolean;
  notify_in_app_default?: boolean;
  auto_scan_on_push?: boolean;
  auto_scan_branch?: string | null;
  scan_options?: {
    engines?: string[];
    path_excludes?: string[];
    fail_severity?: string;
    scan_mode?: string;
    scan_scope?: string;
    code_review?: boolean;
  };
  created_at: string;
  updated_at: string;
};

export type ScanProgressLog = {
  t?: string;
  msg: string;
};

export type ScanProgress = {
  phase?: string;
  label?: string;
  percent?: number;
  eta_remaining_seconds?: number | null;
  logs?: ScanProgressLog[];
  findings_so_far?: number;
};

export type GitCommit = {
  sha: string;
  short: string;
  message: string;
  author: string;
  date: string;
};

export type Scan = {
  id: string;
  project_id: string;
  project_name?: string | null;
  target: string;
  source: string;
  status: string;
  security_level?: string;
  scan_mode?: string;
  scan_scope?: string;
  ref?: string | null;
  commit_sha?: string | null;
  commit_short?: string | null;
  commit_message?: string | null;
  commit_author?: string | null;
  git_history?: GitCommit[];
  share_token?: string | null;
  shared?: boolean;
  progress?: ScanProgress | null;
  eta_seconds?: number | null;
  raw_findings_count?: number;
  correlated_findings_count?: number;
  kev_findings_count?: number;
  error_message?: string | null;
  cancel_requested?: boolean;
  summary?: {
    findings_count?: number;
    raw_findings_count?: number;
    correlated_findings_count?: number;
    deduplicated_count?: number;
    kev_count?: number;
    engine?: string;
    note?: string;
    by_severity?: Record<string, number>;
    by_family?: Record<string, number>;
    ai_status?: string;
    ai_report?: string | null;
    max_risk?: number;
    commit_short?: string;
    commit_sha?: string;
    engines?: Array<Record<string, unknown>>;
    options?: Record<string, unknown>;
    policy_failed?: boolean;
    fail_severity?: string;
  } | null;
  risk_summary?: { max_risk?: number; open_findings?: number; by_severity?: Record<string, number> } | null;
  notify_email?: boolean;
  notify_in_app?: boolean;
  options?: {
    engines?: string[];
    path_excludes?: string[];
    fail_severity?: string;
    code_review?: boolean;
  } | null;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
};

export type FindingStatus = "open" | "triage" | "fixed" | "false_positive";

export type Finding = {
  id: string;
  scan_id: string;
  engine: string;
  rule_id?: string | null;
  vuln_family: string;
  cwe?: string | null;
  owasp_category?: string | null;
  severity: string;
  title: string;
  message?: string | null;
  file_path?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  snippet?: string | null;
  risk_score: number;
  status: string;
  fingerprint?: string | null;
  ai_verdict?: string | null;
  ai_rationale?: string | null;
  countermeasures?: Array<{ title?: string; steps?: string[] }> | null;
  // Phase 6A fields
  cve_id?: string | null;
  matched_engines?: string[];
  engine_count?: number;
  confidence_level?: "high" | "medium" | "low";
  epss_score?: number | null;
  epss_percentile?: number | null;
  is_kev?: boolean;
  kev_due_date?: string | null;
  effective_priority_score?: number;
  // Phase 6B fields
  sla_due_at?: string | null;
  sla_breached?: boolean;
};


export type SbomComponent = {
  name: string;
  version: string;
  purl: string;
  ecosystem: string;
  licenses: string[];
  risk_tier: "permissive" | "weak_copyleft" | "restricted_copyleft" | "unknown" | string;
  source_file?: string;
};

export type ScanSbomResponse = {
  id: string;
  scan_id: string;
  project_id: string;
  spec_version: string;
  component_count: number;
  policy_violations_count: number;
  license_summary: {
    permissive?: number;
    weak_copyleft?: number;
    restricted_copyleft?: number;
    unknown?: number;
    by_license?: Record<string, number>;
  };
  components: SbomComponent[];
  created_at?: string | null;
};

export type GitHubStatus = {
  configured: boolean;
  missing?: string[];
  env_file_found?: boolean;
  connected: boolean;
  needs_reauth?: boolean;
  github_login: string | null;
  avatar_url: string | null;
  scopes?: string | null;
  connected_at: string | null;
};

export type GitHubRepo = {
  id: number;
  full_name: string;
  name: string;
  private: boolean;
  default_branch: string | null;
  html_url: string | null;
  description: string;
  updated_at?: string | null;
};

export type GitRef = { name: string; type: "branch" | "tag" | string };

export type WorkspaceDashboard = {
  totals: { projects: number; scans_this_week: number; open_findings?: number };
  github: GitHubStatus;
  recent_scans: Scan[];
  projects: Project[];
  charts?: {
    runs: Array<{
      id: string;
      project_id: string;
      project_name?: string | null;
      label: string;
      status: string;
      created_at: string;
      findings_count: number;
      by_severity: Record<string, number>;
      by_family: Record<string, number>;
    }>;
    open_by_severity: Record<string, number>;
    open_by_severity_by_project?: Record<string, Record<string, number>>;
    open_by_family: Record<string, number>;
    open_by_engine: Record<string, number>;
    scan_outcomes: Record<string, number>;
  };
};

export type ProjectMember = {
  id: string;
  project_id: string;
  user_id: string;
  email: string;
  username?: string | null;
  display_name?: string | null;
  role: "owner" | "security_lead" | "developer" | "auditor" | string;
  added_by_user_id?: string | null;
  created_at: string;
};

export type FindingSuppressionItem = {
  id: string;
  project_id: string;
  fingerprint: string;
  reason?: string | null;
  status: "pending_approval" | "approved" | "rejected" | "expired" | string;
  suppression_type: "false_positive" | "risk_accepted" | "compensating_control" | string;
  justification?: string | null;
  created_by_user_id: string;
  requested_by_user_id?: string | null;
  reviewed_by_user_id?: string | null;
  reviewed_at?: string | null;
  expires_at?: string | null;
  created_at: string;
};

export type ComplianceControlResult = {
  control_id: string;
  title: string;
  description: string;
  status: "pass" | "warn" | "fail";
  finding_count: number;
  finding_counts: Record<string, number>;
  sample_findings: Array<{
    id: string;
    title: string;
    severity: string;
    cwe?: string | null;
    cve_id?: string | null;
    is_kev?: boolean;
    file_path?: string | null;
  }>;
};

export type ComplianceFrameworkReport = {
  name: string;
  readiness_score: number;
  verdict: string;
  pass_count: number;
  warn_count: number;
  fail_count: number;
  total_controls: number;
  controls: ComplianceControlResult[];
};

export type ScanComplianceResponse = {
  scan_id: string;
  project_id: string;
  project_name: string;
  target: string;
  commit_sha?: string | null;
  evaluated_at: string;
  overall_readiness_score: number;
  overall_verdict: string;
  total_open_findings: number;
  total_suppressed_findings: number;
  kev_open_count: number;
  total_overdue_sla: number;
  pending_suppressions_count: number;
  sbom_verified: boolean;
  sbom_component_count: number;
  sbom_policy_violations: number;
  frameworks: {
    owasp_top_10: ComplianceFrameworkReport;
    soc2: ComplianceFrameworkReport;
    iso27001: ComplianceFrameworkReport;
  };
};

export type FindingFixPlan = {
  finding_id: string;
  scan_id: string;
  project_id: string;
  branch_name: string;
  commit_message: string;
  pr_title: string;
  pr_body: string;
  unified_diff: string;
};

export type BlockedIpEntry = {
  ip_address: string;
  reason: string;
  attack_category: string;
  hit_count: number;
  blocked_at?: string | null;
  expires_at?: string | null;
  created_by: string;
  active: boolean;
};


