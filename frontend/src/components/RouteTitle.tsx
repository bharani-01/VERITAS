import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { applyRouteSeo } from "../lib/seo";

/** Maps the active route to browser title + SEO meta tags. */
export function RouteTitle() {
  const { pathname } = useLocation();
  const title = titleForPath(pathname);

  useEffect(() => {
    applyRouteSeo(pathname, title === "VERITAS" ? "" : title);
  }, [pathname, title]);

  return null;
}

function titleForPath(pathname: string): string {
  if (pathname === "/" || pathname === "") return "Sign in";
  if (pathname.startsWith("/signup")) return "Create account";
  if (pathname.startsWith("/forgot")) return "Reset password";
  if (pathname.startsWith("/reset")) return "New password";
  if (pathname.startsWith("/verify")) return "Verify email";
  if (pathname.startsWith("/report/")) return "Shared report";

  if (pathname.startsWith("/admin/directory")) return "Directory";
  if (pathname.startsWith("/admin/files")) return "Files";
  if (pathname.startsWith("/admin/audit")) return "Audit";
  if (pathname.startsWith("/admin/security")) return "Security";
  if (pathname.startsWith("/admin/profile")) return "Profile";
  if (pathname.startsWith("/admin/settings")) return "Settings";
  if (pathname === "/admin" || pathname === "/admin/") return "Admin";

  if (pathname === "/user/projects/new") return "New project";
  if (/^\/user\/projects\/[^/]+\/scans\/[^/]+/.test(pathname)) return "Scan details";
  if (/^\/user\/projects\/[^/]+/.test(pathname)) return "Scans";
  if (pathname.startsWith("/user/projects")) return "Projects";
  if (pathname.startsWith("/user/profile")) return "Profile";
  if (pathname.startsWith("/user/settings")) return "Settings";
  if (pathname.startsWith("/user/integrations")) return "New project";
  if (pathname === "/user" || pathname === "/user/") return "Home";

  return "VERITAS";
}
