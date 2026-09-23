import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { LoadingMark } from "../components/LoadingMark";
import { ScanReportModal } from "../components/ScanReportModal";
import { api } from "../lib/api";
import { useDocumentTitle } from "../lib/documentTitle";
import type { Finding, Project, Scan } from "../lib/workspace";

/** Full-page scan details (Render-style row click target). */
export function UserScanDetailPage() {
  const { projectId, scanId } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState<Project | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const short = (scan?.commit_short || scan?.commit_sha || "").slice(0, 7);
  useDocumentTitle(
    project
      ? `${short || "Scan"} · ${project.name}`
      : "Scan details",
  );

  useEffect(() => {
    if (!projectId || !scanId) return;
    let cancelled = false;
    setError(null);
    Promise.all([
      api<{ project: Project }>(`/workspace/projects/${projectId}`),
      api<{ scan: Scan }>(`/workspace/scans/${scanId}`),
    ])
      .then(([proj, scanRes]) => {
        if (cancelled) return;
        if (scanRes.scan.project_id !== projectId) {
          setError("Scan not found in this project.");
          return;
        }
        setProject(proj.project);
        setScan(scanRes.scan);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, scanId]);

  useEffect(() => {
    if (!scanId || !scan) return;
    if (scan.status !== "completed" && scan.status !== "failed") {
      setFindings([]);
      setFindingsLoading(false);
      return;
    }
    let cancelled = false;
    setFindingsLoading(true);
    api<{ items: Finding[] }>(`/workspace/scans/${scanId}/findings`)
      .then((data) => {
        if (!cancelled) setFindings(data.items);
      })
      .catch(() => {
        if (!cancelled) setFindings([]);
      })
      .finally(() => {
        if (!cancelled) setFindingsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, scan?.status]);

  if (error) {
    return (
      <main className="admin-main">
        <div className="notice error" role="alert">
          {error}
        </div>
        <Link to={projectId ? `/user/projects/${projectId}` : "/user/projects"}>Back to scans</Link>
      </main>
    );
  }

  if (!project || !scan) {
    return (
      <main className="admin-main">
        <LoadingMark label="Loading scan…" />
      </main>
    );
  }

  return (
    <ScanReportModal
      variant="page"
      scan={scan}
      findings={findings}
      findingsLoading={findingsLoading}
      projectName={project.name}
      githubRepoFullName={project.github_repo_full_name}
      onClose={() => navigate(`/user/projects/${projectId}`)}
      onShared={(updated) => setScan((prev) => (prev ? { ...prev, ...updated } : updated))}
      onFindingsChange={setFindings}
    />
  );
}
