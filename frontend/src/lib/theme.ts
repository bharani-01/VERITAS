export type ThemeId = "dark";

const KEY = "veritas.theme";

/** VERITAS is dark-only (Render-style). Legacy localStorage values are ignored. */
export function readTheme(): ThemeId {
  return "dark";
}

export function applyTheme(_theme?: ThemeId) {
  document.documentElement.setAttribute("data-theme", "dark");
  document.documentElement.style.colorScheme = "dark";
  try {
    localStorage.setItem(KEY, "dark");
  } catch {
    /* ignore */
  }
}

export function cycleTheme(_current?: ThemeId): ThemeId {
  applyTheme("dark");
  return "dark";
}

export function themeLabel(_theme?: ThemeId): string {
  return "Dark";
}
