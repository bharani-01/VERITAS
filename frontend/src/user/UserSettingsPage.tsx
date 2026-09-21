import { useState } from "react";
import { applyTheme, readTheme, type ThemeId } from "../lib/theme";
import { readPreferences, writePreferences, type UserPreferences } from "../lib/preferences";

/** User preferences — theme + email notification toggles (stored locally). */
export function UserSettingsPage() {
  const [theme, setTheme] = useState<ThemeId>(() => readTheme());
  const [prefs, setPrefs] = useState<UserPreferences>(() => readPreferences());
  const [saved, setSaved] = useState(false);

  function onTheme(next: ThemeId) {
    setTheme(next);
    applyTheme(next);
    flashSaved();
  }

  function patchPrefs(partial: Partial<UserPreferences>) {
    const next = { ...prefs, ...partial };
    setPrefs(next);
    writePreferences(next);
    flashSaved();
  }

  function flashSaved() {
    setSaved(true);
    window.setTimeout(() => setSaved(false), 1200);
  }

  return (
    <main className="admin-main">
      <header className="admin-header">
        <div>
          <div className="eyebrow">Account</div>
          <h1>Settings</h1>
          <p>Manage appearance and email notification preferences.</p>
        </div>
        {saved ? (
          <span className="notice success" role="status">
            Saved
          </span>
        ) : null}
      </header>

      <section className="settings-section">
        <h2>Colour theme</h2>
        <p className="settings-lede">Applies across VERITAS for this browser.</p>
        <div className="theme-picker" role="radiogroup" aria-label="Colour theme">
          {(
            [
              ["light", "Light", "Cool slate workspace"],
              ["dark", "Dark", "Charcoal board"],
              ["miro", "Miro black", "Pure black + yellow accent"],
            ] as const
          ).map(([id, label, hint]) => (
            <button
              key={id}
              type="button"
              className={`theme-option ${theme === id ? "active" : ""}`}
              role="radio"
              aria-checked={theme === id}
              onClick={() => onTheme(id)}
            >
              <span className={`theme-swatch theme-swatch-${id}`} aria-hidden="true" />
              <span>
                <b>{label}</b>
                <small>{hint}</small>
              </span>
            </button>
          ))}
        </div>
      </section>

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
              <small>New workspace features and integrations</small>
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
              <small>Summary of project and scan activity</small>
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
