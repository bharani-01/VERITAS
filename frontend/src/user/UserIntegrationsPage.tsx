import { Navigate, useSearchParams } from "react-router-dom";

/** Integrations moved into the New project flow. */
export function UserIntegrationsPage() {
  const [params] = useSearchParams();
  const qs = params.toString();
  return <Navigate to={`/user/projects/new${qs ? `?${qs}` : ""}`} replace />;
}
