export type Project = {
  id: string;
  name: string;
  description: string;
  github_repo_id: number | null;
  github_repo_full_name: string | null;
  github_default_branch: string | null;
  github_html_url: string | null;
  created_at: string;
  updated_at: string;
};

export type Scan = {
  id: string;
  project_id: string;
  project_name?: string | null;
  target: string;
  source: string;
  status: string;
  summary?: { findings_count?: number; engine?: string; note?: string } | null;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
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
  totals: { projects: number; scans_this_week: number };
  github: GitHubStatus;
  recent_scans: Scan[];
  projects: Project[];
};
