export type ThemeId = "light" | "dark" | "miro";

const KEY = "veritas.theme";

export function readTheme(): ThemeId {
  try {
    const value = localStorage.getItem(KEY);
    if (value === "dark" || value === "miro" || value === "light") return value;
  } catch {
    /* ignore */
  }
  return "light";
}

export function applyTheme(theme: ThemeId) {
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* ignore */
  }
}

export function cycleTheme(current: ThemeId): ThemeId {
  const order: ThemeId[] = ["light", "dark", "miro"];
  const next = order[(order.indexOf(current) + 1) % order.length];
  applyTheme(next);
  return next;
}

export function themeLabel(theme: ThemeId): string {
  if (theme === "dark") return "Dark";
  if (theme === "miro") return "Miro black";
  return "Light";
}
