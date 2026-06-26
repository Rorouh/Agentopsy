# FORENSIA Frontend AI Context

> **This file is operational context for AI assistants (Claude, Codex, etc.) working on
> the FORENSIA frontend.** It is not a changelog, not a journal, and not a replacement
> for `CLAUDE.md` or `ARCHITECTURE.md`. It answers one question: *what does an AI session
> need to know to touch frontend code without breaking things?*
>
> Keep it current. Do not turn it into a journal — use `docs/FRONTEND_JOURNAL.md` for that.

---

## Purpose

Provide an AI assistant with enough persistent context to work on the FORENSIA renderer
without requiring the human to re-explain architecture, decisions, or constraints every
session. This file should be read **instead of asking the user** how things are wired.

Companions for other areas should follow the same structure:
- `docs/ai/BACKEND_CONTEXT.md` — sidecar, FastAPI, forensic logic
- `docs/ai/FORENSIC_LOGIC_CONTEXT.md` — EvidenceManager, audit log, toolkit, agent

---

## When To Read This

Read this file at the start of any session that touches:

- anything under `desktop/renderer/`
- `desktop/main.cjs` or `desktop/preload.cjs`
- `desktop/package.json` (renderer scripts)
- theme, layout, navigation, chat UI, or the capabilities dashboard
- `window.forensia` API surface or `global.d.ts`

---

## Required Reading (in order)

1. `CLAUDE.md` — global rules, RULE 0 (no AI attribution), security invariants, stack lock
2. `docs/ARCHITECTURE.md` — full system architecture and wiring diagram
3. `docs/THREAT_MODEL.md` — security model; explains why the renderer must not hold the token
4. `docs/FRONTEND_JOURNAL.md` — chronological record of frontend decisions and changes
5. **This file** — condensed operational rules for AI sessions

Do not skip `CLAUDE.md`. It contains non-negotiable invariants that override anything here.

---

## Current Frontend Architecture

FORENSIA is an **Electron desktop app**, local-first. It is not a SaaS web app. There is
no cloud renderer, no external auth, no remote backend. The UI runs inside a Chromium
window managed by Electron.

```
┌─────────────────────────────────────────────────────┐
│  desktop/renderer/   React 18 + TypeScript + Vite 5  │
│  (this is what you're editing when touching frontend) │
└────────────────────┬────────────────────────────────┘
                     │  window.forensia.*  (contextBridge)
┌────────────────────▼────────────────────────────────┐
│  desktop/preload.cjs   contextBridge only            │
│  Exposes: connection · health · capabilities · query │
└────────────────────┬────────────────────────────────┘
                     │  ipcRenderer.invoke → ipcMain.handle
┌────────────────────▼────────────────────────────────┐
│  desktop/main.cjs   Electron main process            │
│  Starts sidecar, holds token, proxies all HTTP calls │
└────────────────────┬────────────────────────────────┘
                     │  HTTP to 127.0.0.1:<ephemeral> + X-Forensia-Token
┌────────────────────▼────────────────────────────────┐
│  backend/  Python / FastAPI sidecar (PyInstaller)    │
│  All forensic logic lives here                       │
└─────────────────────────────────────────────────────┘
```

**The renderer never knows the sidecar URL or token.** That is a security invariant
documented in `THREAT_MODEL.md` (gate 12). The `main.cjs` process owns both and proxies
every call. Never introduce a code path that bypasses this.

Electron security config (do not change without security review):
- `contextIsolation: true`
- `nodeIntegration: false`
- `sandbox: true`

---

## Current Renderer Structure

```
desktop/renderer/src/
├── index.css               Token system (CSS custom properties). Single source of truth for all design tokens.
├── global.d.ts             TypeScript declaration of window.forensia. Update this when backend adds endpoints.
├── main.tsx                Entry point. Just renders <App />.
├── App.tsx                 Root assembler. Calls health + capabilities, owns activeView state, wires mock data as props.
├── ThemeProvider.tsx       React context for theme. Reads localStorage, writes data-theme on <html>.
├── ThemeToggle.tsx         Pill UI control. Reads/writes through useTheme(). No local state. Lives only inside SettingsPage now — not in the global topbar.
├── navigation/
│   └── navItems.ts         ViewId union, NavItem interface, NAV_ITEMS (section: "primary"|"secondary"), DEFAULT_VIEW.
├── types/
│   └── domain.ts            Domain contracts meant to mirror future backend shapes: CaseSummary, EvidenceFile, ReportDocument, TimelineEvent, MitreTechniqueMatch, InvestigationFinding, GuideStep, LoadState.
├── mocks/
│   └── frontendPreviewData.ts  All mock data. Imported ONLY in App.tsx and passed down as typed props — pages never import mocks directly.
├── layout/
│   ├── AppShell.tsx        Visual frame: CSS grid (sidebar 260px + main), error banner via ErrorState. No topbar/ThemeToggle here anymore.
│   └── Sidebar.tsx         Brand, full nav list (8 items, primary + secondary sections), connection status dot + sidecar version.
├── pages/
│   ├── ChatPage.tsx        Full chat UI + send logic. Calls window.forensia.query(). Has ownership constraint (see below). NOT modified by the visual-demo work.
│   ├── GuidePage.tsx       Static onboarding/flow explainer. CTA → repository.
│   ├── RepositoryPage.tsx  "Casos y evidencias". Mock case form + evidence list + metrics. CTA → investigation.
│   ├── InvestigationPage.tsx  Wraps ChatPage unmodified, adds ContextBanner + findings side panel. CTA → timeline.
│   ├── TimelinePage.tsx    Mock chronological events with severity filter. CTA → document-viewer.
│   ├── DocumentViewerPage.tsx  Mock report list + viewer pane. CTA → mitre.
│   ├── MitreAttackPage.tsx Mock MITRE technique correlation grid. Last step in the flow, no onNavigate.
│   ├── SettingsPage.tsx    Apariencia (real theme toggle + persistence), Operador/Reportes (mock forms), Modelos/IA (reads real caps.models), Seguridad, Diagnóstico (CTA → system), Acerca de.
│   └── SystemStatusPage.tsx  Capabilities dashboard. Renders caps.tools and caps.models from window.forensia.capabilities().
└── ui/
    ├── Button.tsx, Card.tsx, StatusDot.tsx   Original primitives, unchanged.
    ├── Badge.tsx, EmptyState.tsx, LoadingState.tsx, ErrorState.tsx   Visual state primitives.
    ├── PageHeader.tsx, PageSection.tsx       Page-level layout primitives.
    ├── MetricCard.tsx, KeyValueList.tsx      Data display primitives.
    └── ContextBanner.tsx                      Shows active case/evidence; used on Repository/Investigation/Timeline/DocumentViewer/Mitre.
```

All of the above (pages, navigation, mocks, types, ui primitives) is a **visual-only demo layer**: no new `window.forensia` calls, no `fetch`, no real persistence except theme. It exists to make the app navigable and screenshot-ready while the real backend wiring lands incrementally through `App.tsx`.

### App.tsx — what it does and does not do

`App.tsx` is the root assembler. It:
- calls `window.forensia.health()` and `window.forensia.capabilities()` on mount
- derives `isConnected` from the presence of `version` and absence of `error`
- owns the `activeView: ViewId` state (8 views now, see `navigation/navItems.ts`)
- imports all mock data from `mocks/frontendPreviewData.ts` and passes it down as typed props
- passes `onNavigate={setActiveView}` to pages that have a flow CTA
- delegates everything else to `AppShell` and the page components

It does **not** contain any UI, any business logic, or any direct DOM manipulation. When real backend data arrives, this is the only file that needs to change — pages keep their prop contracts.

### ChatPage.tsx — ownership constraint

`ChatPage.tsx` has an implicit co-ownership constraint: it contains the only consumer of
`window.forensia.query()` and its behavior directly depends on the agent's response format.
**Do not refactor `ChatPage.tsx` without coordinating with whoever owns the agent/backend.**
Specifically:
- Do not change the `query()` call shape without updating `global.d.ts` and the backend router.
- Do not "fix" or clean up inline styles without verifying the owner is aware.
- The code was intentionally moved literally from the monolith — ugliness is preserved on purpose.

---

## Frontend Working Rules

These rules apply to all AI sessions touching frontend code.

**Styling**
- All new styles must use CSS custom properties: `var(--token-name)`. Never hardcode a hex color in new CSS.
- Do not introduce Tailwind, styled-components, or any CSS-in-JS library without a strong reason discussed with the team.
- Do not change tokens in `:root` or `[data-theme="dark"]` in `index.css` without understanding that it affects every component simultaneously.
- The app layout is fixed-width desktop (1200×800 baseline). Do not add responsive breakpoints for hypothetical mobile use.

**React / TypeScript**
- Run `npm run typecheck` from `desktop/` before opening any PR that touches renderer code. It takes under 5 seconds.
- Do not introduce React Router while only two tabs exist. A `useState<"chat" | "system">` is sufficient.
- Do not introduce Zustand, Redux, or any global state manager while state is manageable with props and context.
- Do not add error handling for scenarios that cannot happen inside the controlled Electron environment.
- Do not add comments explaining what the code does. Add one only if the WHY is non-obvious.
- No multi-paragraph docstrings or JSDoc blocks.

**Refactoring**
- Prefer incremental, surgical changes over large rewrites.
- When moving code between files, move it literally. Do not improve, clean, or refactor while moving — that conflates two separate concerns into one diff.
- A refactor PR should not change observable behavior. If it does, it is two PRs, not one.

**Commits**
- Follow RULE 0 from `CLAUDE.md`: no AI attribution, no "Co-Authored-By: Claude", no "generated with" anywhere in commit messages, code, or docs.

---

## Electron / Backend Integration Rules

These are the hardest constraints in this codebase. Break them and you break the security model.

**The IPC chain is the only allowed path from renderer to sidecar:**

```
React component
  → window.forensia.methodName(args)          [preload.cjs exposes this]
    → ipcRenderer.invoke("forensia:channel", args)
      → ipcMain.handle("forensia:channel", ...)  [main.cjs handles this]
        → sidecarFetch() or sidecarPost()         [main.cjs calls sidecar with token]
```

Never use `fetch()` from React to call the sidecar directly. The renderer does not know
the sidecar URL and must not receive the session token.

**Adding a new sidecar endpoint requires touching all four files in the same PR:**

| Step | File | What to add |
|---|---|---|
| 1 | `backend/forensia/routers/<router>.py` | New route (thin adapter, no logic) |
| 2 | `desktop/main.cjs` | `ipcMain.handle("forensia:yourChannel", () => sidecarFetch("/api/your-path"))` |
| 3 | `desktop/preload.cjs` | `yourMethod: () => ipcRenderer.invoke("forensia:yourChannel")` |
| 4 | `desktop/renderer/src/global.d.ts` | Add `yourMethod(): Promise<YourReturnType>` to the `forensia` interface |

A PR that adds a backend endpoint without updating `preload.cjs` and `global.d.ts` is
incomplete — the renderer cannot call it and TypeScript will reject any attempt.

**Never:**
- Pass the sidecar token to the renderer
- Bypass `contextBridge` with `ipcRenderer` directly in component code
- Enable `nodeIntegration` or disable `contextIsolation`
- Use `shell: true` in `subprocess.run` on the backend side (documented in `CLAUDE.md`)

---

## UI / Theme Conventions

**How theming works:**

```
ThemeProvider (React context)
  → reads localStorage("forensia-theme") on init
  → sets document.documentElement.setAttribute("data-theme", "light"|"dark")
  → [data-theme="dark"] block in index.css overrides :root tokens
```

**Token reference (index.css `:root`):**

| Token | Purpose |
|---|---|
| `--bg` | Page / window background |
| `--surface` | Card / elevated surface background |
| `--sidebar-bg` | Sidebar background |
| `--border` | All 1px borders |
| `--text-primary` | Main readable text |
| `--text-secondary` | Secondary labels |
| `--text-muted` | Placeholders, hints |
| `--accent` | Interactive / brand color (indigo) |
| `--accent-bg` | Accent tint background |
| `--accent-text` | Accent text on light surfaces |
| `--success` / `--danger` / `--warning` | Semantic status colors |
| `--font-sans` | System UI font stack (no network font) |
| `--font-mono` | Monospace stack |
| `--radius-card` | 8px — card corners |
| `--radius-pill` | 999px — pill/badge corners |

Note: `--font-sans` uses `system-ui` intentionally — the app runs on air-gapped forensic
workstations where Google Fonts are not available.

**Persistence:** theme preference is in `localStorage` with key `"forensia-theme"`. There
is a `TODO` in `ThemeProvider.tsx` to migrate to `electron-store` via IPC. Do not implement
that TODO without coordinating with whoever owns the Electron persistence layer — it touches
`main.cjs`, `preload.cjs`, and `ThemeProvider.tsx` simultaneously.

---

## Current Technical Debt

Know this before making changes. Some debt is intentional.

| Debt | Location | Intentional? | Risk if touched blindly |
|---|---|---|---|
| Manual markdown parser | `ChatPage.tsx:11–99` | No — temporary | Parser is fragile; breaks on complex agent responses |
| Inline styles with hardcoded hex | `ChatPage.tsx` throughout | Yes (literal move) | Cleaning them up breaks dark mode in chat |
| `evidence_id` sent as `""` | `ChatPage.tsx:147` | Temporary | Agent receives no evidence context; forensic analysis is disconnected from UI |
| No API/hook abstraction layer | `ChatPage.tsx:133–163` | Temporary | All fetch logic lives inside the component; untestable in isolation |
| ~~`getGreeting()` defined but unused~~ | — | **Resolved 2026-06-25** | Removed — it was never called anywhere, zero behavior change. |
| ~~`typecheck` not in CI~~ | — | **Resolved 2026-06-25** | `ci.yml`'s `renderer` job now runs `npm run typecheck` (it already ran an equivalent `tsc` command; now it calls the actual npm script so there is one source of truth). |
| `@types/react: ^19.2.17` with `react: ^18.3.0` | `desktop/package.json` | **Intentional** | Do not "fix" this. The combination is compatible. Do not upgrade React to 19 without team review. |
| TODO `electron-store` for theme | `ThemeProvider.tsx:32` | Temporary | Low priority; localStorage works for now |

---

## Recommended Next Refactors

In priority order, accounting for team coordination requirements:

1. **Define the `evidence_id` contract with backend/logic team** before touching `ChatPage.tsx`.
   This is the biggest gap between UI and real forensic workflow. Everything else in chat
   depends on it.

2. **Extract `useChatApi` hook** in `src/hooks/useChatApi.ts` — wrap the `window.forensia.query()`
   call, `busy` state, and error handling. No new libraries needed. Do this only after the
   evidence contract is settled.

3. **Replace manual markdown parser** with `react-markdown` once the agent returns structured
   markdown in real responses. Do not do this speculatively.

4. **Migrate inline styles in `ChatPage.tsx` to tokens** — coordinate with chat owner. Must not
   change layout or spacing, only replace hardcoded colors with `var(--token)`.

5. ~~Connect `npm run typecheck` to CI~~ — done 2026-06-25.

6. **Frontend tests** — write only after hooks and components are stable. Start with the
   hook layer (`useChatApi`), not with component snapshots.

---

## Things Not To Do Yet

| What | Why not |
|---|---|
| Migrate to SaaS web / remove Electron | Core architecture decision. Locked in `ARCHITECTURE.md`. |
| Add React Router | `useState<ViewId>` in `App.tsx` is still sufficient (8 views as of 2026-06-24, see `navItems.ts`). The journal's original threshold ("revisit past 4-5 views") has technically been crossed — flagged as an open question for the team, not yet a decision to act on. Router still adds history/URL complexity with no real benefit in a desktop app with no URLs. |
| Add Zustand / Redux | State is flat and lives in `App.tsx`. No cross-tree sharing problem yet. |
| Add a UI component library (MUI, shadcn, etc.) | Adds weight and overrides the CSS token system. Evaluate only if primitive count grows significantly. |
| Add responsive / mobile layout | This is an Electron desktop app with a fixed window. Not a target use case. |
| Implement `electron-store` for theme | `localStorage` works. The IPC plumbing for this should be done as part of a broader persistence story, not just for theme. |
| Rewrite `ChatPage.tsx` unilaterally | It has implicit co-ownership with the agent/backend team. A unilateral rewrite risks breaking the query contract. |
| Change the sidecar transport (HTTP → IPC direct) | Not a frontend decision. Would require coordination across all layers. |
| Stream responses without backend agreement | Streaming requires WebSocket or SSE support in the sidecar. Frontend-only change is not enough. |

---

## Team Coordination Notes

These are standing notes for when frontend changes touch other teams' boundaries.

- **Backend adds a new endpoint →** backend team must also provide the `global.d.ts` type
  for the return value. A PR that lands without the type update will break the renderer at
  compile time.

- **Agent changes `query()` response shape →** update `global.d.ts` and verify `ChatPage.tsx`
  handles the new fields. The current type is `{ status: string; reply: string; evidence_id: string; os_profile: string }`.

- **Backend changes `Capabilities` shape →** update `global.d.ts` `Capabilities` interface
  and verify `SystemStatusPage.tsx` renders correctly. Adding fields is safe; removing or
  renaming fields is a breaking change.

- **Connecting real evidence to the UI** requires a new endpoint (`window.forensia.loadEvidence()`
  or similar) plus a UI flow for file selection. Coordinate the contract (what `EvidenceManager`
  returns as a handle, what the renderer needs to display) before building either side.

- **If the agent supports streaming** (SSE or WebSocket), the frontend integration touches
  `main.cjs` (websocket proxy or SSE forwarding), `preload.cjs` (new bridge method), and
  `ChatPage.tsx` (streaming state). All three must land together.

- **Changing global CSS tokens** (`:root` or `[data-theme="dark"]`) affects every component.
  Announce in the team channel before merging; it is a visual breaking change.

---

## How Future AI Sessions Should Work

If you are an AI assistant starting a new session to work on the FORENSIA frontend:

1. **Read this file first.** Do not ask the user to explain the architecture.
2. **Read `CLAUDE.md`.** RULE 0 (no AI attribution) applies to every commit, comment, and doc.
3. **Check `docs/FRONTEND_JOURNAL.md`** for recent decisions and context not yet reflected here.
4. **Before touching any file**, confirm the scope with the user. Do not apply changes speculatively.
5. **Show the full proposed change** (file content or diff) before applying. Wait for explicit approval.
6. **Run `npm run typecheck`** after every change to the renderer. Report the result before continuing.
7. **Do not treat this file as a journal.** Do not add dated entries here. Use `FRONTEND_JOURNAL.md`.
8. **Do not invent new libraries or patterns.** Match existing conventions in the codebase.
9. **Do not refactor while moving code.** These are separate operations.
10. **If unsure about a decision's scope**, ask the user rather than assuming. The Electron security
    model has real constraints; a wrong assumption here has security consequences, not just style ones.

When this file is out of date (new components, new endpoints, new decisions), update it as part of
the PR that introduces the change. The goal is that opening this file is always enough to start
working without asking the user "how does X work."
