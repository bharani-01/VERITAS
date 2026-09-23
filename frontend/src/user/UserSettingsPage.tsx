import { useState } from "react";
import { readPreferences, writePreferences, type UserPreferences } from "../lib/preferences";

/** User preferences — email notification toggles (stored locally). */
export function UserSettingsPage() {
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

      <section className="settings-section">
        <h2>Email notifications</h2>
        <p className="settings-lede">Stored on this device until server-side prefs ship.</p>
        <div className="settings-toggles">
          <label className="settings-toggle">
            <span>
              <b>Security alerts</b>
              <small>Sign-in and account security notices</small>
            </span>
            <input
              type="checkbox"
              checked={prefs.emailSecurityAlerts}
              onChange={(e) => patchPrefs({ emailSecurityAlerts: e.target.checked })}
            />
          </label>
          <label className="settings-toggle">
            <span>
              <b>Product updates</b>
              <small>New workspace features</small>
            </span>
            <input
              type="checkbox"
              checked={prefs.emailProductUpdates}
              onChange={(e) => patchPrefs({ emailProductUpdates: e.target.checked })}
            />
          </label>
          <label className="settings-toggle">
            <span>
              <b>Weekly digest</b>
              <small>Workspace activity summary</small>
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
