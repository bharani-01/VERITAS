/** Build a GitHub commit URL for owner/repo + SHA (full or short). */
export function githubCommitUrl(repoFullName: string | null | undefined, sha: string | null | undefined): string | null {
  const repo = (repoFullName || "").trim();
  const commit = (sha || "").trim();
  if (!repo || !commit || !repo.includes("/")) return null;
  return `https://github.com/${repo}/commit/${commit}`;
}

/** Blob URL with optional line anchor. */
export function githubBlobUrl(
  repoFullName: string | null | undefined,
  sha: string | null | undefined,
  filePath: string | null | undefined,
  line?: number | null,
): string | null {
  const repo = (repoFullName || "").trim();
  const ref = (sha || "").trim() || "HEAD";
  const path = (filePath || "").replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "");
  if (!repo || !path || !repo.includes("/")) return null;
  const base = `https://github.com/${repo}/blob/${ref}/${path}`;
  return line && line > 0 ? `${base}#L${line}` : base;
}
