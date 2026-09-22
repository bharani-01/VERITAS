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
  created_at: string;
  updated_at: string;
};

export type ScanProgress = {
  phase?: string;
  label?: string;
  percent?: number;
  eta_remaining_seconds?: number | null;
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
  summary?: {
    findings_count?: number;
    engine?: string;
    note?: string;
    by_severity?: Record<string, number>;
    by_family?: Record<string, number>;
    ai_status?: string;
    max_risk?: number;
    commit_short?: string;
    commit_sha?: string;
    engines?: Array<Record<string, unknown>>;
  } | null;
  risk_summary?: { max_risk?: number; open_findings?: number } | null;
  notify_email?: boolean;
  notify_in_app?: boolean;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
};

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
  risk_score: number;
  status: string;
  ai_verdict?: string | null;
  ai_rationale?: string | null;
  countermeasures?: Array<{ title?: string; steps?: string[] }> | null;
};

export type GitHubStatus = {
  configured: boolean;
  missing?: string[];
  env_file_found?: boolean;
  connected: boolean;
  github_login: string | null;
  avatar_url: string | null;
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
};

export type WorkspaceDashboard = {
  totals: { projects: number; scans_this_week: number; open_findings?: number };
  github: GitHubStatus;
  recent_scans: Scan[];
  projects: Project[];
};
