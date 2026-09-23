import { useState } from "react";
import { readPreferences, writePreferences, type UserPreferences } from "../lib/preferences";

/** Admin preferences — Render left/right rows. */
export function AdminSettingsPage() {
  const [prefs, setPrefs] = useState<UserPreferences>(() => readPreferences());
  const [saved, setSaved] = useState(false);

  function patchPrefs(partial: Partial<UserPreferences>) {
    const next = { ...prefs, ...partial };
    setPrefs(next);
    writePreferences(next);
    setSaved(true);
    window.setTimeout(() => setSaved(false), 1200);
  }

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Account</div>
          <h1>Settings</h1>
          <p>Email notification preferences for this browser.</p>
        </div>
        {saved ? (
          <span className="notice success" role="status">
            Saved
          </span>
        ) : null}
      </header>

      <section className="settings-section rr-row">
        <div className="rr-meta">
          <h2>Security alerts</h2>
          <p>Sign-in and administrator security notices.</p>
        </div>
        <div className="rr-controls">
          <label className="settings-toggle">
            <span>
              <b>Email me</b>
              <small>When something security-related happens</small>
            </span>
            <input
              type="checkbox"
              checked={prefs.emailSecurityAlerts}
              onChange={(e) => patchPrefs({ emailSecurityAlerts: e.target.checked })}
            />
          </label>
        </div>
      </section>

      <section className="settings-section rr-row">
        <div className="rr-meta">
          <h2>Product updates</h2>
          <p>Platform and identity changes.</p>
        </div>
        <div className="rr-controls">
          <label className="settings-toggle">
            <span>
              <b>Email me</b>
              <small>Occasional product announcements</small>
            </span>
            <input
              type="checkbox"
              checked={prefs.emailProductUpdates}
              onChange={(e) => patchPrefs({ emailProductUpdates: e.target.checked })}
            />
          </label>
        </div>
      </section>

      <section className="settings-section rr-row">
        <div className="rr-meta">
          <h2>Weekly digest</h2>
          <p>Identity and workspace totals.</p>
        </div>
        <div className="rr-controls">
          <label className="settings-toggle">
            <span>
              <b>Email me</b>
              <small>Once a week</small>
            </span>
            <input
              type="checkbox"
              checked={prefs.emailWeeklyDigest}
              onChange={(e) => patchPrefs({ emailWeeklyDigest: e.target.checked })}
            />
          </label>
        </div>
      </section>
    </main>
  );
}
