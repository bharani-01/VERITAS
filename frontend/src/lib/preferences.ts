export type UserPreferences = {
  emailSecurityAlerts: boolean;
  emailProductUpdates: boolean;
  emailWeeklyDigest: boolean;
};

const KEY = "veritas.user.preferences";

const DEFAULTS: UserPreferences = {
  emailSecurityAlerts: true,
  emailProductUpdates: false,
  emailWeeklyDigest: false,
};

export function readPreferences(): UserPreferences {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULTS };
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULTS };
  }
}

export function writePreferences(next: UserPreferences) {
  localStorage.setItem(KEY, JSON.stringify(next));
}

export function initialsFromName(name: string): string {
  const parts = (name || "").trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}
