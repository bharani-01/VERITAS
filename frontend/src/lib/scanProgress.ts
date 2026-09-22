/** Friendly Claude-style progress copy — never show raw engine names to users. */
const PHASE_LABELS: Record<string, string> = {
  queued: "Getting ready…",
  cloning: "Pulling your repository…",
  secrets: "Looking for exposed secrets…",
  sca: "Checking dependencies…",
  semgrep: "Reading through the code…",
  ai_triage: "Reviewing what stands out…",
  reporting: "Putting the report together…",
  completed: "Done",
  failed: "Something went wrong",
};

export function scanProgressLabel(progress?: { phase?: string; label?: string } | null, status?: string): string {
  if (progress?.label) return progress.label;
  const phase = progress?.phase || (status === "queued" ? "queued" : undefined);
  if (phase && PHASE_LABELS[phase]) return PHASE_LABELS[phase];
  if (status === "running") return "Working…";
  if (status === "queued") return PHASE_LABELS.queued;
  return "";
}
