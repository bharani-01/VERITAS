/** Build a GitHub commit URL for owner/repo + SHA (full or short). */
export function githubCommitUrl(repoFullName: string | null | undefined, sha: string | null | undefined): string | null {
  const repo = (repoFullName || "").trim();
  const commit = (sha || "").trim();
  if (!repo || !commit || !repo.includes("/")) return null;
  return `https://github.com/${repo}/commit/${commit}`;
}
