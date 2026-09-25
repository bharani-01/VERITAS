/**
 * Heuristic cleanup for AI final reports that use title-case section lines
 * instead of real Markdown headings (common with Groq JSON summaries).
 */
export function normalizeAiReportMarkdown(source: string): string {
  const raw = source.replace(/\r\n/g, "\n").trim();
  if (!raw) return "";

  // Already structured enough — leave alone.
  if (/^#{1,3}\s+\S/m.test(raw) && (raw.includes("\n- ") || raw.includes("\n* ") || /^\d+\.\s/m.test(raw))) {
    return raw;
  }

  const knownHeadings = new Set(
    [
      "veritas scan executive summary",
      "executive summary",
      "critical issues",
      "high-severity secrets",
      "high‑severity secrets",
      "high severity secrets",
      "medium-severity configuration & code issues",
      "medium‑severity configuration & code issues",
      "medium-severity configuration and code issues",
      "low-severity code hygiene",
      "low‑severity code hygiene",
      "low severity code hygiene",
      "themes",
      "prioritized fixes",
      "recommended next steps",
      "summary",
      "findings overview",
      "risk themes",
    ].map((s) => s.toLowerCase()),
  );

  const lines = raw.split("\n");
  const out: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed) {
      out.push("");
      continue;
    }

    if (/^#{1,6}\s/.test(trimmed) || /^([-*+]|\d+\.)\s+/.test(trimmed) || /^```/.test(trimmed)) {
      out.push(line);
      continue;
    }

    const lower = trimmed.toLowerCase().replace(/\s+/g, " ");
    const isKnown = knownHeadings.has(lower);
    const looksLikeTitle =
      trimmed.length <= 80 &&
      !/[.!?]$/.test(trimmed) &&
      !/[–—]/.test(trimmed) &&
      !/^\[[0-9]+\]/.test(trimmed) &&
      !/^p\d+\s*:/i.test(trimmed) &&
      /^[A-Z0-9][\w/&'’\-‑ ]*$/.test(trimmed);

    if (isKnown || (looksLikeTitle && (i === 0 || !lines[i - 1]?.trim()))) {
      const level = i === 0 || lower.includes("executive summary") || lower.startsWith("veritas") ? "#" : "##";
      out.push(`${level} ${trimmed}`);
      continue;
    }

    const pMatch = trimmed.match(/^(p\d+)\s*:\s*(.+)$/i);
    if (pMatch) {
      out.push(`- **${pMatch[1].toUpperCase()}:** ${pMatch[2]}`);
      continue;
    }

    if (/^\[\d+\]\s+/.test(trimmed)) {
      out.push(`- ${trimmed}`);
      continue;
    }

    const themeMatch = trimmed.match(/^([A-Z][\w &/-]{2,40})\s+[–—-]\s+(.+)$/);
    if (themeMatch && trimmed.length < 220) {
      out.push(`- **${themeMatch[1]}:** ${themeMatch[2]}`);
      continue;
    }

    out.push(line);
  }

  return out.join("\n").replace(/\n{3,}/g, "\n\n").trim();
}
