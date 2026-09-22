import { Navigate, Route, Routes } from "react-router-dom";
import { AdminAuditPage } from "./admin/AdminAuditPage";
import { AdminDashboardPage } from "./admin/AdminDashboardPage";
import { AdminProfilePage } from "./admin/AdminProfilePage";
import { AdminSettingsPage } from "./admin/AdminSettingsPage";
import { AdminShell } from "./admin/AdminShell";
import { AdminUsersPage } from "./admin/AdminUsersPage";
import { ForgotPage } from "./pages/ForgotPage";
import { LoginPage } from "./pages/LoginPage";
import { ResetPage } from "./pages/ResetPage";
import { SharedReportPage } from "./pages/SharedReportPage";
import { SignupPage } from "./pages/SignupPage";
import { VerifyPage } from "./pages/VerifyPage";
import { UserDashboardPage } from "./user/UserDashboardPage";
import { UserIntegrationsPage } from "./user/UserIntegrationsPage";
import { UserProfilePage } from "./user/UserProfilePage";
import { UserProjectDetailPage } from "./user/UserProjectDetailPage";
import { UserProjectsPage } from "./user/UserProjectsPage";
import { UserScansPage } from "./user/UserScansPage";
import { UserSettingsPage } from "./user/UserSettingsPage";
import { UserShell } from "./user/UserShell";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<LoginPage />} />
      <Route path="/signup" element={<SignupPage />} />
      <Route path="/forgot" element={<ForgotPage />} />
      <Route path="/reset" element={<ResetPage />} />
      <Route path="/verify" element={<VerifyPage />} />
      <Route path="/report/:token" element={<SharedReportPage />} />

      <Route path="/admin" element={<Navigate to="/admin/" replace />} />
      <Route element={<AdminShell />}>
        <Route path="/admin/" element={<AdminDashboardPage />} />
        <Route path="/admin/directory" element={<AdminUsersPage />} />
        <Route path="/admin/audit" element={<AdminAuditPage />} />
        <Route path="/admin/profile" element={<AdminProfilePage />} />
        <Route path="/admin/settings" element={<AdminSettingsPage />} />
      </Route>

      <Route path="/user" element={<Navigate to="/user/" replace />} />
      <Route element={<UserShell />}>
        <Route path="/user/" element={<UserDashboardPage />} />
        <Route path="/user/projects" element={<UserProjectsPage />} />
        <Route path="/user/projects/:projectId" element={<UserProjectDetailPage />} />
        <Route path="/user/scans" element={<UserScansPage />} />
        <Route path="/user/integrations" element={<UserIntegrationsPage />} />
        <Route path="/user/profile" element={<UserProfilePage />} />
        <Route path="/user/settings" element={<UserSettingsPage />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
