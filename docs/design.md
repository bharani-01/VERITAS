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
| Font | Inter 400/500/600/700 | UI + titles |
| Body | 14px | Dense product UI |
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
4. Update this file when tokens change.
