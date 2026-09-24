const SITE_ORIGIN = "https://veritas.trackifyapp.co.in";
const DEFAULT_DESCRIPTION =
  "VERITAS is a vulnerability scanner for GitHub repositories: secrets, SCA, and SAST with verified identity, admin approval, and shareable security reports.";

function upsertMeta(attr: "name" | "property", key: string, content: string) {
  let el = document.head.querySelector(`meta[${attr}="${key}"]`) as HTMLMetaElement | null;
  if (!el) {
    el = document.createElement("meta");
    el.setAttribute(attr, key);
    document.head.appendChild(el);
  }
  el.setAttribute("content", content);
}

function upsertLink(rel: string, href: string) {
  let el = document.head.querySelector(`link[rel="${rel}"]`) as HTMLLinkElement | null;
  if (!el) {
    el = document.createElement("link");
    el.setAttribute("rel", rel);
    document.head.appendChild(el);
  }
  el.setAttribute("href", href);
}

/** Keep title / description / social tags in sync with the active route. */
export function applyRouteSeo(pathname: string, titlePart: string) {
  const pageTitle = titlePart.trim() ? `${titlePart.trim()} · VERITAS` : "VERITAS — Vulnerability Scanner";
  const description = descriptionForPath(pathname);
  const path = pathname.startsWith("/") ? pathname : `/${pathname}`;
  const url = `${SITE_ORIGIN}${path === "/" ? "/" : path}`;
  const noIndex = shouldNoIndex(pathname);

  document.title = pageTitle;
  upsertMeta("name", "description", description);
  upsertMeta("name", "robots", noIndex ? "noindex,nofollow" : "index,follow,max-image-preview:large");
  upsertMeta("property", "og:title", pageTitle);
  upsertMeta("property", "og:description", description);
  upsertMeta("property", "og:url", url);
  upsertMeta("name", "twitter:title", pageTitle);
  upsertMeta("name", "twitter:description", description);
  upsertLink("canonical", url);
}

function shouldNoIndex(pathname: string): boolean {
  return (
    pathname.startsWith("/admin") ||
    pathname.startsWith("/user") ||
    pathname.startsWith("/report/") ||
    pathname.startsWith("/reset")
  );
}

function descriptionForPath(pathname: string): string {
  if (pathname === "/" || pathname === "") {
    return "Sign in to VERITAS — verified identity and secure vulnerability scanning for your GitHub repositories.";
  }
  if (pathname.startsWith("/signup")) {
    return "Create a VERITAS account. Email verification and administrator approval are required before access.";
  }
  if (pathname.startsWith("/forgot") || pathname.startsWith("/reset")) {
    return "Reset your VERITAS password securely. Existing sessions are revoked after a successful reset.";
  }
  if (pathname.startsWith("/verify")) {
    return "Verify your VERITAS email address to continue account approval.";
  }
  if (pathname.startsWith("/report/")) {
    return "Shared VERITAS security scan report.";
  }
  if (pathname.startsWith("/admin")) {
    return "VERITAS administrator console — directory, approvals, and audit.";
  }
  if (pathname.startsWith("/user")) {
    return "VERITAS workspace — projects, scans, and security findings for your repositories.";
  }
  return DEFAULT_DESCRIPTION;
}
