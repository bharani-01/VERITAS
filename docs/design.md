# Design system

## Direction

**Railway / Render-style dark only** — near-black canvas, hairline dividers, dense Inter UI, solid accent active states. No light/miro themes. Prefer sectioned surfaces over separate card chrome.

## Surfaces

| Area | Path | Ownership |
|------|------|-----------|
| Auth | `/`, `/signup`, `/forgot`, `/reset`, `/verify` | Public |
| Admin | `/admin/`, `/admin/directory`, `/admin/profile` | `frontend/src/admin/` |
| User | `/user/`, `/user/projects`, `/user/projects/new`, `/user/scans`, `/user/profile` | `frontend/src/user/` |

No shared admin/user UI components. Shared `lib/` helpers OK.

## Tokens

| Token | Value | Role |
|------|------|------|
| Font | Inter Variable (self-hosted via `@fontsource-variable/inter`) | UI + titles |
| Body | 14px / 400 | Dense product UI |
| `--font-ui` / `--font-display` | `"Inter Variable", "Inter", system stack` | Same face everywhere |
| `--font-mono` | System UI mono stack | SHAs, code, IDs |
| `--bg` | `#0c0c0c` | Canvas |
| `--bg-deep` / `--nav-bg` | `#080808` | Nav / deep insets |
| `--surface` | `#0f0f0f` | Section fills |
| `--ink` | `#f2f2f2` | Primary text |
| `--muted` | `#8a8a8a` | Secondary text / uppercase labels |
| `--line` | `#262626` | Hairline dividers |
| `--accent` | `#4f8cff` | Primary actions + active nav |
| `--ok` | `#3ecf8e` | Success / completed |

## Brand assets

Source lockup lives under `frontend/public/brand/`. Use the right crop for each surface:

| Asset | Path | Use |
|------|------|-----|
| V mark | `/brand/veritas-mark.jpg` | Nav, compact headers (`BrandMark`) |
| Full lockup | `/brand/veritas-lockup.jpg` | Auth pane / splash (`BrandLockup`) |
| Splash stack | `/brand/veritas-splash.jpg` | Optional marketing / loading |
| App icon | `/brand/veritas-app-icon.jpg` | Large square mark |
| Favicon | `/favicon.jpg` | Browser tab |
| Apple touch | `/apple-touch-icon.jpg` | iOS home screen |

Do not redraw the mark as a generic triangle SVG.

## Rules

1. Dark theme only (`applyTheme("dark")`).
2. Prefer hairline separators and unified section frames over scattered bordered cards.
3. No purple gradients, glow stacks, or decorative grid motifs — keep VERITAS blue (accent aligned to the mark’s cyan tip).
4. Active nav uses a **solid accent fill** (white text), not a faint tint.
5. Uppercase micro-labels (eyebrows, table headers, panel titles) use muted ink + wide tracking.
6. Resource names underline on hover; status uses compact pills (completed / running / failed).
7. Projects index and project detail use flat `np-*` / `projects-wrap` language. **New project** is a progressive import flow (gate → search/select repo → configure → create); optional settings stay collapsed.
8. Typography: Inter Variable is self-hosted (not Google `@import`) so the face loads with the SPA and matches across browsers. Forms inherit body font.
9. App shell pages use full content width (including New project `.np-flow`). Settings/profile forms use Render-style rows (`.rr-row`: title left, controls right; stacks under 760px). Auth marketing column stays as designed.
10. Accessibility baseline: skip link to `#main-content`, visible `:focus-visible` rings, dark-theme `.notice` / `.badge` / audit tones, labeled collapsed nav, no nested interactive controls in scan history.
11. Update this file when tokens or brand assets change.
