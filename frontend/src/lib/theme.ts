export type ThemeId = "light";

const KEY = "veritas.theme";

/** VERITAS is light-only — one shared palette for auth, admin, and user. */
export function readTheme(): ThemeId {
  return "light";
}

export function applyTheme(_theme?: ThemeId) {
  document.documentElement.setAttribute("data-theme", "light");
  document.documentElement.style.colorScheme = "light";
  try {
    localStorage.setItem(KEY, "light");
  } catch {
    /* ignore */
  }
}

export function cycleTheme(_current?: ThemeId): ThemeId {
  applyTheme("light");
  return "light";
}

export function themeLabel(_theme?: ThemeId): string {
  return "Light";
}
