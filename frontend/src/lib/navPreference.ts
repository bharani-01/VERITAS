export type NavArea = "admin" | "user";

function syncDocumentClass(collapsed: boolean): void {
  try {
    document.documentElement.classList.toggle("nav-pref-collapsed", collapsed);
  } catch {
    /* ignore */
  }
}

function storageKey(area: NavArea): string {
  return `veritas.${area}.navCollapsed`;
}

/** Per-area collapse preference — admin and user never share this state. */
export function readNavCollapsed(area: NavArea): boolean {
  try {
    const collapsed = localStorage.getItem(storageKey(area)) === "1";
    syncDocumentClass(collapsed);
    return collapsed;
  } catch {
    /* ignore */
  }
  syncDocumentClass(false);
  return false;
}

export function writeNavCollapsed(area: NavArea, collapsed: boolean): void {
  try {
    localStorage.setItem(storageKey(area), collapsed ? "1" : "0");
    localStorage.removeItem("veritas.navCollapsed");
  } catch {
    /* ignore */
  }
  syncDocumentClass(collapsed);
}
