/** Parse API timestamps. Naive ISO (no Z/offset) is treated as UTC — matches server storage. */
export function parseUtc(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const raw = iso.trim();
  if (!raw) return null;
  const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(raw);
  const normalized = hasZone ? raw : `${raw}Z`;
  const t = Date.parse(normalized);
  if (!Number.isFinite(t)) return null;
  return new Date(t);
}

export function formatLocalDateTime(iso: string | null | undefined): string {
  const d = parseUtc(iso);
  return d ? d.toLocaleString() : "—";
}

export function formatLocalDate(iso: string | null | undefined): string {
  const d = parseUtc(iso);
  return d ? d.toLocaleDateString() : "—";
}
