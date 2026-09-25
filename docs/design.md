# Design system

## Direction

**Light theme only** — cool slate canvas (`#f4f6f8`), white surfaces, hairline dividers, dense Inter UI, solid blue accent. One shared palette for auth, admin, and user. Prefer sectioned surfaces over separate card chrome.

## Surfaces

| Area | Path | Ownership |
|------|------|-----------|
| Auth | `/`, `/signup`, `/forgot`, `/reset`, `/verify` | Public |
| Admin | `/admin/`, `/admin/directory`, `/admin/files`, `/admin/audit`, `/admin/security`, `/admin/profile` | `frontend/src/admin/` |
| User | `/user/`, `/user/projects`, `/user/projects/new`, `/user/scans`, `/user/profile` | `frontend/src/user/` |

No shared admin/user UI components. Shared `lib/` helpers OK.

## Tokens

| Token | Value | Role |
|------|------|------|
| Font | Inter Variable (self-hosted via `@fontsource-variable/inter`) | UI + titles |
| Body | 14px / 400 | Dense product UI |
| `--font-ui` / `--font-display` | `"Inter Variable", "Inter", system stack` | Same face everywhere |
| `--font-mono` | System UI mono stack | SHAs, code, IDs |
| `--bg` | `#f4f6f8` | Canvas |
| `--bg-deep` | `#e8ecf1` | Deep insets / brand pane |
| `--nav-bg` / `--surface` | `#ffffff` | Nav + elevated surfaces |
| `--ink` | `#0f172a` | Primary text |
| `--ink-soft` | `#334155` | Secondary body |
| `--muted` | `#64748b` | Labels / hints |
| `--line` | `#e2e8f0` | Hairline dividers |
| `--accent` | `#2563eb` | Primary actions + active nav |
| `--ok` | `#059669` | Success / completed |
| `--logo-chip` | `#0a0a0a` | Backdrop for the baked-black lockup |

## Brand assets

Use the stacked lockup from the brand sheet (V above VERITAS + tagline). Do not redraw as a generic SVG.

| Asset | Path | Use |
|------|------|-----|
| V mark | `/brand/veritas-mark.png` | Sidebar / nav / favicon (`BrandMark`) |
| Stacked lockup | `/brand/veritas-lockup.png` | Auth pane (`BrandLockup`) — transparent bg for light canvas |
| App icon | `/brand/veritas-app-icon.png` | Large square mark |
| Splash (opaque) | `/brand/veritas-splash.png` | Black-field original |

Black was knocked out of the lockup so the charcoal wordmark reads on the light theme.

## Rules

1. Light theme only (`applyTheme("light")`). Dark/miro data-theme attrs still map to the same light tokens.
2. Prefer hairline separators and unified section frames over scattered bordered cards.
3. No purple gradients, glow stacks, or decorative grid motifs — keep VERITAS blue from the mark.
4. Active nav uses a **solid accent fill** (white text), not a faint tint.
5. Uppercase micro-labels use muted ink + wide tracking.
6. Resource names underline on hover; status uses compact pills (completed / running / failed).
7. Projects index and project detail use flat `np-*` / `projects-wrap` language. **New project** is a progressive import flow (gate → search/select repo → configure → create).
8. Typography: Inter Variable is self-hosted (not Google `@import`).
9. App shell pages use full content width. Settings/profile forms use Render-style rows (`.rr-row`).
10. Accessibility: skip link to `#main-content`, visible `:focus-visible` rings, light-theme `.notice` / `.badge` / audit tones.
11. Update this file when tokens or brand assets change.
