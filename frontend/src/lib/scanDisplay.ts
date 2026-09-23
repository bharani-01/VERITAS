import type { Scan } from "./workspace";

/** Always show exactly 7 characters of a commit SHA when available. */
export function shortCommit(sha: string | null | undefined, fallback?: string | null): string | null {
  const full = (sha || fallback || "").trim();
  if (!full) return null;
  return full.slice(0, 7);
}

export function scanTriggerLabel(scan: Scan): string {
  if (scan.source === "github_push") return "Auto-scan";
  if (scan.source === "github_repo") return "Manual";
  return "Manual";
}

export function formatScanDuration(scan: Scan): string {
  if (scan.status === "queued" || scan.status === "running") {
    const eta = scan.progress?.eta_remaining_seconds ?? scan.eta_seconds;
    if (eta == null) return "…";
    return `~${formatSeconds(eta)} left`;
  }
  const start = scan.started_at ? Date.parse(scan.started_at) : Date.parse(scan.created_at);
  const end = scan.finished_at ? Date.parse(scan.finished_at) : NaN;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return "—";
  return formatSeconds((end - start) / 1000);
}

function formatSeconds(raw: number): string {
  const sec = Math.max(0, Math.round(raw));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm ? `${h}h ${rm}m` : `${h}h`;
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const diff = Math.max(0, Date.now() - t);
  const sec = Math.floor(diff / 1000);
  if (sec < 45) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 60) return `${day}d ago`;
  const mo = Math.floor(day / 30);
  if (mo < 24) return `${mo}mo ago`;
  return `${Math.floor(day / 365)}y ago`;
}

export function scanHeadline(scan: Scan): string {
  const msg = (scan.commit_message || "").trim();
  if (msg) return msg.split("\n")[0].slice(0, 120);
  if (scan.status === "queued" || scan.status === "running") return "Scanning…";
  if (scan.status === "failed") return scan.error_message || "Scan failed";
  if (scan.status === "cancelled") return "Scan cancelled";
  return scan.target || "Scan";
}

export function findingsCountLabel(scan: Scan): string {
  if (scan.status === "queued" || scan.status === "running") return "…";
  const n = scan.summary?.findings_count;
  if (n == null) return "—";
  return String(n);
}
