import { Navigate } from "react-router-dom";

/** Scans live under each project — keep /user/scans as a redirect. */
export function UserScansPage() {
  return <Navigate to="/user/projects" replace />;
}
