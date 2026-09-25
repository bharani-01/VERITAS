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
  error_message?: string | null;
  cancel_requested?: boolean;
  summary?: {
    findings_count?: number;
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
