# Design system

## Research baseline (MNC / enterprise products)

| Source | Typography | Color approach |
|--------|------------|----------------|
| **IBM Carbon** | IBM Plex | Neutral gray dominant; **Blue 60 `#0f62fe`** for primary actions; Gray 10 `#f4f4f4` light bg; Gray 100 `#161616` text/nav |
| **Atlassian** | Atlassian Sans (Inter-derived) | Neutral surfaces + semantic tokens; product type optimized for dense UI |
| **Linear / Notion ecosystem** | **Inter** | Single sans family, systemic scale, minimal chrome |
| **Stripe** | Söhne (licensed) | Neutrals + restrained brand accent; craft in spacing, not decoration |

**VERITAS choice:** Inter + Carbon Gray 10 / Blue 60 — free, MNC-proven, minimal, dense-UI friendly.

References:
- https://carbondesignsystem.com/elements/color/overview/
- https://atlassian.design/foundations/typography
- Industry notes: Inter as default SaaS/dashboard face; Carbon neutrals for enterprise light themes

## Surfaces

| Area | Path | Ownership |
|------|------|-----------|
| Auth | `/`, `/signup`, `/forgot`, `/reset`, `/verify` | Public |
| Admin | `/admin/`, `/admin/directory`, `/admin/profile` | `frontend/src/admin/` |
| User | `/user/`, `/user/projects`, `/user/scans`, `/user/integrations`, `/user/profile` | `frontend/src/user/` |

No shared admin/user UI components. Shared `lib/` helpers OK.

## Tokens

| Token | Value | Role |
|-------|-------|------|
| Font | Inter 400/500/600/700 | UI + titles |
| Body | 14px | Dense product UI |
| `--ink` / `--nav-bg` | `#0f172a` | Same slate — text & shell match |
| `--bg` | `#f8fafc` | Cool paper |
| `--accent` | `#1d4ed8` | Blue from the same cool family |
| `--accent-hover` | `#1e40af` | Darker step |

One chromatic family (slate + related blue) so nav, type, and CTAs feel like one product — not IBM Blue pasted onto unrelated charcoal.


## When changing UI

1. Own the correct tree
2. Extend tokens first
3. Prefer restraint
4. Update this file when tokens change
