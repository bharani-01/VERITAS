import type { Finding, Scan } from "./workspace";

export type ExportFormat = "md" | "json" | "csv" | "html" | "sarif";

const SEVERITY_SARIF: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export function sortFindingsByRisk(items: Finding[]): Finding[] {
  return [...items].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
}

function esc(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

export function buildMarkdownReport(scan: Scan, findings: Finding[], projectName?: string): string {
  const sorted = sortFindingsByRisk(findings);
  const lines: string[] = [
    `# VERITAS scan report`,
    ``,
    `- **Project:** ${projectName || scan.project_name || "—"}`,
    `- **Target:** ${scan.target}`,
    `- **Status:** ${scan.status}`,
    `- **Mode:** ${(scan.scan_mode || "rules_only").replace(/_/g, " ")}`,
    `- **Git:** ${scan.commit_short || "n/a"}${scan.commit_sha ? ` (\`${scan.commit_sha}\`)` : ""}`,
    `- **Commit:** ${scan.commit_message || "—"}`,
    `- **Author:** ${scan.commit_author || "—"}`,
    `- **Findings:** ${sorted.length}`,
    `- **Max risk:** ${scan.risk_summary?.max_risk ?? scan.summary?.max_risk ?? "—"}`,
    ``,
  ];
  lines.push(`## Findings (risk-sorted)`, ``);
  if (!sorted.length) {
    lines.push(`_No findings._`, ``);
  } else {
    lines.push(`| Risk | Severity | Title | Location | Engine |`, `| ---: | --- | --- | --- | --- |`);
    for (const f of sorted) {
      const loc = f.file_path ? `${f.file_path}${f.line_start ? `:${f.line_start}` : ""}` : "—";
      lines.push(
        `| ${f.risk_score.toFixed(1)} | ${f.severity} | ${esc(f.title)} | ${esc(loc)} | ${f.engine} |`,
      );
    }
    lines.push(``);
    for (const f of sorted) {
      lines.push(`### ${f.title}`);
      lines.push(`- Risk **${f.risk_score.toFixed(1)}** · ${f.severity} · ${f.vuln_family} · ${f.engine}`);
      if (f.file_path) lines.push(`- Location: \`${f.file_path}${f.line_start ? `:${f.line_start}` : ""}\``);
      if (f.message) lines.push(``, f.message, ``);
      if (f.countermeasures?.[0]?.steps?.length) {
        lines.push(`**Remediation**`);
        for (const step of f.countermeasures[0].steps) lines.push(`- ${step}`);
        lines.push(``);
      }
    }
  }
  return lines.join("\n");
}

export function buildCsvReport(findings: Finding[]): string {
  const sorted = sortFindingsByRisk(findings);
  const header = ["risk_score", "severity", "title", "family", "engine", "file", "line", "cwe"];
  const rows = sorted.map((f) =>
    [
      f.risk_score,
      f.severity,
      JSON.stringify(f.title),
      f.vuln_family,
      f.engine,
      JSON.stringify(f.file_path || ""),
      f.line_start ?? "",
      f.cwe || "",
    ].join(","),
  );
  return [header.join(","), ...rows].join("\n");
}

export function buildHtmlReport(scan: Scan, findings: Finding[], projectName?: string): string {
  const md = buildMarkdownReport(scan, findings, projectName)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return `<!doctype html><html><head><meta charset="utf-8"/><title>VERITAS report</title>
<style>body{font-family:system-ui,sans-serif;max-width:920px;margin:2rem auto;padding:0 1rem;line-height:1.45;white-space:pre-wrap}</style>
</head><body><pre>${md}</pre></body></html>`;
}

/** SARIF 2.1.0 — for GitHub Code Scanning / IDE import. */
export function buildSarifReport(scan: Scan, findings: Finding[], projectName?: string): string {
  const sorted = sortFindingsByRisk(findings);
  const rulesByKey = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();
  const results = sorted.map((f) => {
    const ruleId = f.rule_id || `${f.engine}:${f.vuln_family}`;
    if (!rulesByKey.has(ruleId)) {
      rulesByKey.set(ruleId, {
        id: ruleId,
        name: f.title.slice(0, 120),
        shortDescription: { text: f.title.slice(0, 200) },
      });
    }
    const result: Record<string, unknown> = {
      ruleId,
      level: SEVERITY_SARIF[(f.severity || "").toLowerCase()] || "warning",
      message: { text: f.message || f.title },
      properties: {
        severity: f.severity,
        engine: f.engine,
        family: f.vuln_family,
        risk_score: f.risk_score,
        status: f.status,
      },
    };
    if (f.file_path) {
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file_path.replace(/\\/g, "/") },
            region: {
              startLine: f.line_start || 1,
              ...(f.line_end ? { endLine: f.line_end } : {}),
              ...(f.snippet ? { snippet: { text: f.snippet.slice(0, 500) } } : {}),
            },
          },
        },
      ];
    }
    return result;
  });

  const document = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "VERITAS",
            informationUri: "https://veritas.trackifyapp.co.in",
            version: "1.0.0",
            rules: [...rulesByKey.values()],
          },
        },
        properties: {
          project: projectName || scan.project_name || null,
          scan_id: scan.id,
          target: scan.target,
          commit_sha: scan.commit_sha || null,
          security_level: scan.security_level || null,
          scan_mode: scan.scan_mode || null,
        },
        results,
      },
    ],
  };
  return JSON.stringify(document, null, 2);
}

function buildMarkdownWithAi(scan: Scan, findings: Finding[], projectName?: string): string {
  let md = buildMarkdownReport(scan, findings, projectName);
  const report = scan.summary?.ai_report?.trim();
  if (report) {
    md += `\n## AI final report\n\n${report}\n`;
  }
  return md;
}

export function downloadReport(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportScanReport(
  format: ExportFormat,
  scan: Scan,
  findings: Finding[],
  projectName?: string,
) {
  const base = `veritas-scan-${(scan.commit_short || scan.id).slice(0, 12)}`;
  if (format === "json") {
    downloadReport(
      `${base}.json`,
      JSON.stringify({ scan, findings: sortFindingsByRisk(findings) }, null, 2),
      "application/json",
    );
    return;
  }
  if (format === "csv") {
    downloadReport(`${base}.csv`, buildCsvReport(findings), "text/csv");
    return;
  }
  if (format === "html") {
    downloadReport(`${base}.html`, buildHtmlReport(scan, findings, projectName), "text/html");
    return;
  }
  if (format === "sarif") {
    downloadReport(`${base}.sarif`, buildSarifReport(scan, findings, projectName), "application/sarif+json");
    return;
  }
  downloadReport(`${base}.md`, buildMarkdownWithAi(scan, findings, projectName), "text/markdown");
}
