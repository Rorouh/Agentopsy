# Agentopsy Frontend AI Context

> **This file is operational context for AI assistants (Claude, Codex, etc.) working on
> the Agentopsy frontend.** It is not a changelog, not a journal, and not a replacement
> for `CLAUDE.md` or `arquitectura.md`. It answers one question: *what does an AI session
> need to know to touch frontend code without breaking things?*
>
> Keep it current. Do not turn it into a journal — use `docs/operacion/frontend-journal.md` for that.

---

## Purpose

Provide an AI assistant with enough persistent context to work on the Agentopsy frontend
without requiring the human to re-explain architecture, decisions, or constraints every
session. This file should be read **instead of asking the user** how things are wired.

Companions for other areas should follow the same structure:
- `docs/ai-context/backend.md` — `api` service, FastAPI, forensic logic
- `docs/ai-context/forensic-logic.md` — EvidenceManager, audit log, toolkit, agent

---

## The 2026-07-02 pivot — read this first

Agentopsy is a **self-hosted web tool deployed with Docker Compose** (propuesta v1.2).
The frontend is a **React SPA served by the `web` compose service**, used from the
analyst's own browser at `http://127.0.0.1:5173`. There is no Electron shell, no native
installer, no auto-update — delivery is `git clone` + `docker compose up --build`,
identical on the three host OSs.

This reverts the earlier "native desktop / Electron" direction. The React code carries
over; the shell around it does not:

| Electron model (gone) | Compose model (current) |
|---|---|
| Chromium window managed by Electron | Analyst's browser at `http://127.0.0.1:5173` |
| `main.cjs` starts the sidecar, holds the token, proxies every HTTP call | `api` service started by compose; the SPA calls it over HTTP with the session token |
| `window.forensia.*` via `preload.cjs` contextBridge + IPC | Typed HTTP client module inside the SPA (`fetch` to `/api/*`) |
| PyInstaller sidecar on an ephemeral loopback port | `api` container; published ports bind `127.0.0.1` only |
| electron-builder installers + code signing per OS | No packaging at all — the compose builds the images |

**Landed 2026-07-02.** The SPA now lives at **`web/`** (repo root) as a standalone
Vite + React app with its own `package.json` — no Electron dependencies. The transport
is the typed HTTP client at `web/src/api/client.ts` (types in `web/src/api/types.ts`);
`window.forensia` and `global.d.ts` are gone from the SPA. The session token is obtained
once from `GET /api/session` (readable only same-origin; see
`backend/forensia/routers/session.py`) and lives in tab memory. In production nginx
(the `web` service) serves `dist/` and proxies `/api` + `/ws` to `api:8000`; in dev the
Vite proxy reproduces the same topology, so the app is always same-origin with its backend.

The Electron shell (`desktop/`) was removed on 2026-07-02, together with the rest of
the old delivery model (`vendor/`, `docker/agent/`, the PyInstaller spec, the release
workflow). The SPA at `web/` is the only frontend in the repo.

---

## When To Read This

Read this file at the start of any session that touches:

- anything under `web/` (the React SPA)
- theme, layout, navigation, chat UI, or the capabilities dashboard
- the frontend↔`api` contract (`web/src/api/client.ts` + `web/src/api/types.ts`)

---

## Required Reading (in order)

1. `CLAUDE.md` — global rules, RULE 0 (no AI attribution), security invariants, stack lock
2. `docs/arquitectura.md` — full system architecture and wiring diagram
3. `docs/modelo-amenazas.md` — security model; the gates the UI must respect (exact-origin
   CORS, Host-header check, session token, `textContent` rendering)
4. `docs/operacion/frontend-journal.md` — chronological record of frontend decisions and changes
5. **This file** — condensed operational rules for AI sessions

Do not skip `CLAUDE.md`. It contains non-negotiable invariants that override anything here.

---

## Current Frontend Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Analyst's browser — http://127.0.0.1:5173                │
└────────────────────────┬─────────────────────────────────┘
                         │  HTTP — published ports bind 127.0.0.1 ONLY
┌────────────────────────▼─────────────────────────────────┐
│  web    nginx serving the React SPA (built from web/)    │
│         React 18 + TypeScript + Vite                      │
│         proxies /api and /ws → api:8000 (same-origin)     │
└────────────────────────┬─────────────────────────────────┘
                         │  HTTP on the compose-internal network + session token
┌────────────────────────▼─────────────────────────────────┐
│  api    FastAPI (backend/forensia) — ALL the logic        │
│         routers/ are thin adapters; the UI holds none     │
└──────────────────────────────────────────────────────────┘
```

Security constraints that shape frontend work (gate numbers from `modelo-amenazas.md`):

- Every port the compose publishes binds `127.0.0.1`; nothing is reachable from outside
  the host (gate 1).
- The `api` accepts only the exact UI origin (CORS allowlist, no `localhost` regex) and
  checks the Host header (gate 2). Side-effecting endpoints additionally require
  Origin/Referer **and** the session token (gate 3).
- The session token lives in memory only — never in `localStorage`, never in a URL
  (gate 12). The SPA bootstraps it from `GET /api/session`, which is readable only by
  the allowlisted UI origin (exact CORS + Host-check make it an anti-CSRF capability).
- Evidence-derived content renders as text (`textContent`), never as HTML — evidence is
  hostile data (gate 11).

---

## Current SPA Structure

```
web/src/                       ← the SPA (own package.json + vite.config.ts at web/)
├── index.css               Token system (CSS custom properties). Single source of truth for all design tokens.
├── api/
│   ├── client.ts           THE HTTP client module: token bootstrap (/api/session), ApiError with the backend's actionable detail, every endpoint call.
│   └── types.ts            Request/response types mirrored 1:1 (snake_case) from the routers.
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
├── utils/
│   ├── format.ts            Pure formatting helpers (formatBytes, formatDate, shortHash).
│   └── evidence.ts          SUPPORTED_EXTENSIONS (single source, mirrors toolkit/catalog.py + triage.py), fileExtension/isSupportedEvidence, EWF segment predicates (isEwfSegment/isEwfFirstSegment/isEwfContinuationSegment) and the uploadable-vs-registrable split (isUploadableEvidence ⊃ isRegistrableEvidence — mirrors forensia/evidence.py; backend re-validates), FILE_INPUT_ACCEPT_EXTENSIONS, DETECTED_KIND_LABEL.
├── components/              Presentational pieces of RepositoryPage (page keeps ALL state/data logic):
│   ├── CaseSearchModal.tsx  Command-palette case finder (opened from the "Buscar casos" header button — there is no left panel): client-side search/filter/sort + pagination (8/page) over the loaded Case[]; selecting a case activates it and closes the modal; error+retry state.
│   ├── ActiveCaseHeader.tsx Compact case header: name+badge, meta line, actions (Investigar/Editar/Más▾ menu with click-outside; closed case → "Reabrir" prominent), collapsible notes.
│   ├── EvidenceInbox.tsx    Register-evidence zone; states for closed case / uploading (real XHR progress, batch-aggregated) / registering (REAL progress bar from the register job: %, "segmento N/M", phase) / inbox not loaded / loading / empty / selectable sources (only registrable ones are clickable; EWF continuations are listed with a "segmento EWF · se registra desde el .E01" badge) / inline error+retry / 2s success flash / non-red upload notice (409 = already in the inbox). Real DnD + multi-select upload via the File API (POST /api/evidence/upload); no cancel on register — none exists server-side, and registration is atomic by design.
│   └── EvidenceTable.tsx    Semantic <table> of registered evidence: kind label, size, short hash + copy button, verification badge, per-row verify; client-side search (>5 rows) + pagination (10/page).
│   └── Pagination.tsx       Shared "‹ Anterior N/M Siguiente ›" client-side pager.
├── layout/
│   ├── AppShell.tsx        Visual frame: CSS grid (sidebar 260px + main), error banner via ErrorState. No topbar/ThemeToggle here anymore.
│   └── Sidebar.tsx         Brand + full nav list (8 items, primary + secondary sections) with aria-current="page" on the active item. No footer: connection + version moved to SystemStatusPage (2026-07-04).
├── pages/
│   ├── ChatPage.tsx        Full chat UI + send logic via api.query(). Executor selector (4 chips; unavailable ones disabled with the actionable reason as tooltip) + a cloud-egress warning (the per-case consent flow and the /api/agent/cloud-consent endpoint were removed 2026-07-16 — the warning no longer blocks send). Has ownership constraint (see below).
│   ├── GuidePage.tsx       Static onboarding/flow explainer. CTA → repository.
│   ├── RepositoryPage.tsx  "Casos y evidencias". Full-width case workspace; cases are located via CaseSearchModal (command-palette, "Buscar casos" header button — no side panel). Real case lifecycle (create in Modal — no os_profile field, the orchestrator derives it —, edit inline, close with confirm Modal, reopen, DELETE with a type-the-name confirm Modal) + evidence upload/registration from the /api/evidence/sources inbox (./evidence on the host) + hash verify. Registration goes through the BACKGROUND job (POST …/evidence/async, polled ~1s, re-attached on mount via …/evidence/jobs) — never the synchronous endpoint, which 504s on multi-GB images. Orchestrates state; presentational pieces live in components/. CTA → investigation (in ActiveCaseHeader).
│   ├── InvestigationPage.tsx  Wraps ChatPage, adds ContextBanner + findings side panel. CTA → timeline.
│   ├── TimelinePage.tsx    Mock chronological events with severity filter ("Vista demo" banner). CTA → document-viewer.
│   ├── DocumentViewerPage.tsx  Mock report list + viewer pane ("Vista demo" banner). CTA → mitre.
│   ├── MitreAttackPage.tsx Mock MITRE technique correlation grid ("Vista demo" banner). Last step in the flow, no onNavigate.
│   ├── SettingsPage.tsx    4 accessible tabs (tablist/tab/tabpanel): Ejecutores/IA (real: status of the 4 executors with local/cloud + reasons, capabilities refresh, DEFAULT_EXECUTOR select, OLLAMA_HOST/OLLAMA_MODEL, per-cloud-CLI model (CLAUDE_CODE_MODEL/CODEX_MODEL/GEMINI_MODEL, passed as --model; empty = CLI default)/FORENSIA_EXECUTOR_TIMEOUT, CLI-session/forensia-cli-auth explainer — no API keys anywhere), Operador y reportes (preview forms, disabled), Apariencia (real theme toggle + persistence), Sistema (security notes, diagnostics, about; CTA → system).
│   └── SystemStatusPage.tsx  Capabilities dashboard. Renders caps.tools, caps.toolkits and caps.executors from the capabilities endpoint + connection/version (ex-sidebar-footer).
└── ui/
    ├── Button.tsx, Card.tsx, StatusDot.tsx   Original primitives, unchanged.
    ├── Badge.tsx, EmptyState.tsx, LoadingState.tsx, ErrorState.tsx   Visual state primitives.
    ├── PageHeader.tsx, PageSection.tsx       Page-level layout primitives.
    ├── MetricCard.tsx, KeyValueList.tsx      Data display primitives.
    ├── Modal.tsx                              Minimal dialog: fixed backdrop + centered panel; closes on backdrop click / Escape / ×; optional panelClassName for variants. Used for case creation, close-case confirmation and the case search palette.
    └── ContextBanner.tsx                      Shows active case/evidence; used on Timeline/DocumentViewer/Mitre (Repository/Investigation render their own banners inline).
```

Most pages are a **visual demo layer**: mock data typed as props, no direct backend
calls, no real persistence except theme. They exist to make the app navigable and
screenshot-ready while the real backend wiring lands incrementally through `App.tsx`.

### App.tsx — what it does and does not do

`App.tsx` is the root assembler. It:
- calls the health + capabilities endpoints on mount (via `api` from `src/api/client.ts`)
- derives `isConnected` from the presence of `version` and absence of `error`
- owns the `activeView: ViewId` state (8 views now, see `navigation/navItems.ts`)
- imports all mock data from `mocks/frontendPreviewData.ts` and passes it down as typed props
- passes `onNavigate={setActiveView}` to pages that have a flow CTA
- delegates everything else to `AppShell` and the page components

It does **not** contain any UI, any business logic, or any direct DOM manipulation. When
real backend data arrives, this is the only file that needs to change — pages keep their
prop contracts. The migration to the HTTP client also concentrates here.

### ChatPage.tsx — ownership constraint

`ChatPage.tsx` has an implicit co-ownership constraint: it contains the only consumer of
the agent query call and its behavior directly depends on the agent's response format.
**Do not refactor `ChatPage.tsx` without coordinating with whoever owns the agent/backend.**
Specifically:
- Do not change the query call shape without updating the TS contract and the backend router.
- Do not "fix" or clean up inline styles without verifying the owner is aware.
- The code was intentionally moved literally from the monolith — ugliness is preserved on purpose.

---

## Frontend Working Rules

These rules apply to all AI sessions touching frontend code.

**Styling**
- All new styles must use CSS custom properties: `var(--token-name)`. Never hardcode a hex color in new CSS.
- Do not introduce Tailwind, styled-components, or any CSS-in-JS library without a strong reason discussed with the team.
- Do not change tokens in `:root` or `[data-theme="dark"]` in `index.css` without understanding that it affects every component simultaneously.
- The layout targets a desktop browser window (1200×800 baseline). Do not add responsive breakpoints for hypothetical mobile use.

**React / TypeScript**
- Run `npm run typecheck` from `web/` before opening any PR that touches SPA code. It takes under 5 seconds. (`npm run build` runs it too — the Docker build fails on type errors.)
- Do not introduce React Router, Zustand, Redux, or any global state manager while state is manageable with props and context.
- Do not add comments explaining what the code does. Add one only if the WHY is non-obvious.
- No multi-paragraph docstrings or JSDoc blocks.

**Refactoring**
- Prefer incremental, surgical changes over large rewrites.
- When moving code between files, move it literally. Do not improve, clean, or refactor while moving — that conflates two separate concerns into one diff.
- A refactor PR should not change observable behavior. If it does, it is two PRs, not one.

**Commits**
- Follow RULE 0 from `CLAUDE.md`: no AI attribution, no "Co-Authored-By: Claude", no "generated with" anywhere in commit messages, code, or docs.

---

## Web / Backend Integration Rules

These are the hardest constraints in this codebase. Break them and you break the security model.

**Target model (compose):** the SPA talks to the `api` service over HTTP through one
typed client layer.

```
React component
  → typed client function (single HTTP client module)
    → fetch("/api/…", { headers: session token })
      → api service (FastAPI router — thin adapter)
        → forensia/* (all the logic)
```

Adding a new `api` endpoint under the target model touches three places in the same PR:

| Step | Where | What to add |
|---|---|---|
| 1 | `backend/forensia/routers/<router>.py` | New route (thin adapter, no logic) |
| 2 | the SPA's HTTP client module | One typed client function for the route |
| 3 | the SPA's shared types | Request/response types the component consumes |

**Never:**
- Put business logic in the SPA — logic lives in `forensia/*` (RULE 3); the UI renders
  and calls endpoints.
- Scatter ad-hoc `fetch()` calls across components — all HTTP goes through the client module.
- Persist the session token (`localStorage`, cookies, URLs) — memory only (gate 12).
- Render api- or evidence-derived content as HTML — `textContent` only (gate 11).
- Weaken CORS / Host-header / token checks server-side for frontend convenience.

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
| `--focus-ring` | Keyboard :focus-visible outline color (aliases `--accent`) |
| `--font-sans` | System UI font stack (no network font) |
| `--font-mono` | Monospace stack |
| `--radius-card` | 8px — card corners |
| `--radius-pill` | 999px — pill/badge corners |

Note: `--font-sans` uses `system-ui` intentionally — the tool is self-hosted and may run
on air-gapped forensic workstations where Google Fonts are not reachable.

**Persistence:** theme preference is in `localStorage` with key `"forensia-theme"`. That
is the final model for a browser app. (The session token is the opposite: memory only,
never `localStorage` — gate 12.)

---

## Current Technical Debt

Know this before making changes. Some debt is intentional.

| Debt | Location | Intentional? | Risk if touched blindly |
|---|---|---|---|
| ~~Electron shell remains~~ | — | **Resolved 2026-07-02** | `desktop/` was deleted wholesale (with `vendor/` and `docker/agent/`); the SPA at `web/` is the only frontend. |
| Manual markdown parser | `ChatPage.tsx:11–99` | No — temporary | Parser is fragile; breaks on complex agent responses |
| Inline styles with hardcoded hex | `ChatPage.tsx` throughout | Yes (literal move) | Cleaning them up breaks dark mode in chat |
| `evidence_id` falls back to `""` without case evidence | `ChatPage.tsx` (send) | Temporary | With a case + registered evidence the real id is sent; the empty-string path only remains for the standalone chat, which the backend rejects with an actionable 422. |
| No hook abstraction over the client | `ChatPage.tsx` (send) | Temporary | HTTP now goes through `src/api/client.ts`, but busy/error state still lives inline in the component. Extract `useChatApi` when stable. |
| ~~`getGreeting()` defined but unused~~ | — | **Resolved 2026-06-25** | Removed — it was never called anywhere, zero behavior change. |
| ~~`typecheck` not in CI~~ | — | **Resolved 2026-06-25** | `ci.yml`'s `renderer` job (renamed `web` on 2026-07-02) now runs `npm run typecheck` (it already ran an equivalent `tsc` command; now it calls the actual npm script so there is one source of truth). |
| `@types/react: ^19.2.17` with `react: ^18.3.0` | `web/package.json` | **Intentional** | Do not "fix" this. The combination is compatible. Do not upgrade React to 19 without team review. |
| ~~TODO `electron-store` for theme~~ | — | **Resolved 2026-07-02** | The TODO was deleted with the migration; `localStorage` is the model in a browser app. |

---

## Recommended Next Refactors

The SPA migration into the `web` service **landed 2026-07-02**, and the dismantle of
the old delivery model (`desktop/`, `vendor/`, `docker/agent/`) landed the same day.
Next, in priority order:

1. **Extract `useChatApi` hook** in `src/hooks/useChatApi.ts` — wrap the agent query
   call, `busy` state, and error handling on top of `src/api/client.ts`. No new libraries.

2. **Replace manual markdown parser** with `react-markdown` once the agent returns structured
   markdown in real responses. Do not do this speculatively. Evidence-derived strings keep
   rendering as text (gate 11).

4. **Migrate inline styles in `ChatPage.tsx` to tokens** — coordinate with chat owner. Must not
   change layout or spacing, only replace hardcoded colors with `var(--token)`.

5. **Frontend tests** — write only after hooks and components are stable. Start with the
   hook layer (`useChatApi`), not with component snapshots.

---

## Things Not To Do Yet

| What | Why not |
|---|---|
| Add React Router | `useState<ViewId>` in `App.tsx` is still sufficient (8 views, see `navItems.ts`). Real URLs are now possible (the SPA is served by nginx) but not needed yet. |
| Add Zustand / Redux | State is flat and lives in `App.tsx`. No cross-tree sharing problem yet. |
| Add a UI component library (MUI, shadcn, etc.) | Adds weight and overrides the CSS token system. Evaluate only if primitive count grows significantly. |
| Add responsive / mobile layout | The tool targets the analyst's desktop browser with a fixed-baseline layout. Not a target use case. |
| Rewrite `ChatPage.tsx` unilaterally | It has implicit co-ownership with the agent/backend team. A unilateral rewrite risks breaking the query contract. |
| Invent an ad-hoc UI↔api transport (direct WebSocket, per-component fetch) | The transport is HTTP + session token through one client layer, governed by `modelo-amenazas.md`. Changes are cross-team. |
| Stream responses without backend agreement | Streaming requires SSE or WebSocket support in the `api` service. A frontend-only change is not enough. |

---

## Team Coordination Notes

These are standing notes for when frontend changes touch other teams' boundaries.

- **Backend adds a new endpoint →** the same PR must provide the client function in
  `web/src/api/client.ts` and the types in `web/src/api/types.ts`. A PR that lands
  without the type update breaks the SPA at compile time.

- **Agent changes the query response shape →** update `QueryResponse` in
  `web/src/api/types.ts` and verify `ChatPage.tsx` handles the new fields. The response
  now carries `executor: { id, name, local }` besides `reply`/`tool_calls`/`agent`.

- **Backend changes `Capabilities` shape →** update the `Capabilities` type
  and verify `SystemStatusPage.tsx` renders correctly. Adding fields is safe; removing or
  renaming fields is a breaking change. After the pivot, capabilities also report executor
  availability (Claude Code / Codex CLI / Gemini CLI / Ollama) — the UI must degrade
  explicitly per capability, never hide the failure (RULE 2).

- **Connecting real evidence to the UI** requires a new `api` endpoint plus a UI flow for
  selecting evidence from the read-only evidence mount. Coordinate the contract (what
  `EvidenceManager` returns as a handle, what the UI needs to display) before building
  either side.

- **If the agent supports streaming** (SSE or WebSocket), the integration touches the
  `api` service (endpoint), the HTTP client module (streaming state), and `ChatPage.tsx`.
  All must land together.

- **Changing global CSS tokens** (`:root` or `[data-theme="dark"]`) affects every component.
  Announce in the team channel before merging; it is a visual breaking change.

---

## How Future AI Sessions Should Work

If you are an AI assistant starting a new session to work on the Agentopsy frontend:

1. **Read this file first.** Do not ask the user to explain the architecture.
2. **Read `CLAUDE.md`.** RULE 0 (no AI attribution) applies to every commit, comment, and doc.
3. **Check `docs/operacion/frontend-journal.md`** for recent decisions and context not yet reflected here.
4. **Before touching any file**, confirm the scope with the user. Do not apply changes speculatively.
5. **Show the full proposed change** (file content or diff) before applying. Wait for explicit approval.
6. **Run `npm run typecheck`** after every change to the renderer. Report the result before continuing.
7. **Do not treat this file as a journal.** Do not add dated entries here. Use `frontend-journal.md`.
8. **Do not invent new libraries or patterns.** Match existing conventions in the codebase.
9. **Do not refactor while moving code.** These are separate operations.
10. **If unsure about a decision's scope**, ask the user rather than assuming. The web security
    model (exact-origin CORS, Host-header check, session token, `textContent` rendering) has real
    constraints; a wrong assumption here has security consequences, not just style ones.

When this file is out of date (new components, new endpoints, new decisions), update it as part of
the PR that introduces the change. The goal is that opening this file is always enough to start
working without asking the user "how does X work."
