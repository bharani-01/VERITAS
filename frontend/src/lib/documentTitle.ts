import { useEffect } from "react";

/** Set `document.title` for the current view. Restores base title on unmount. */
export function useDocumentTitle(title: string | null | undefined) {
  useEffect(() => {
    const prev = document.title;
    const next = (title || "").trim();
    document.title = next ? `${next} · VERITAS` : "VERITAS";
    return () => {
      document.title = prev;
    };
  }, [title]);
}
