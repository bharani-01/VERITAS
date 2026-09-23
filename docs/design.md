# Design system

## Direction

**Render-style dark only** — flat canvas, hairline dividers, dense Inter UI. No light/miro themes. No card chrome.

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
| `--bg` | `#111111` | Canvas |
| `--bg-deep` | `#0a0a0a` | Nav / insets |
| `--ink` | `#ededed` | Primary text |
| `--muted` | `#8b8b8b` | Secondary text |
| `--line` | `#2a2a2a` | Hairline dividers |
| `--accent` | `#4f8cff` | Links / primary actions |
| `--ok` | `#46a758` | Success |

## Rules

1. Dark theme only (`applyTheme("dark")`).
2. Prefer hairline separators over bordered cards/boxes.
3. No purple gradients, glow stacks, or decorative grid motifs.
4. Projects index and project detail use flat `np-*` / `projects-wrap` language. **New project** is a progressive import flow (gate → search/select repo → configure → create); optional settings stay collapsed.
5. Typography: Inter Variable is self-hosted (not Google `@import`) so the face loads with the SPA and matches across browsers. Forms inherit body font.
6. App shell pages use full content width (including New project `.np-flow`). Settings/profile forms use Render-style rows (`.rr-row`: title left, controls right; stacks under 760px). Auth marketing column stays as designed.
7. Accessibility baseline: skip link to `#main-content`, visible `:focus-visible` rings, dark-theme `.notice` / `.badge` / audit tones, labeled collapsed nav, no nested interactive controls in scan history.
8. Update this file when tokens change.
