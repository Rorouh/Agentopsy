# Graph Report - C:\Users\super\Desktop\TFM - Forensia\Forensia-AI\tools\graph\out\web  (2026-07-29)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 290 nodes · 649 edges · 10 communities
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 4 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a323b718`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- App.tsx
- types.ts
- RepositoryPage.tsx
- activeCase.tsx
- package.json
- ChatPage.tsx
- DocumentsPage.tsx
- Community 7
- TimelinePage.tsx

## God Nodes (most connected - your core abstractions)
1. `useActiveCase()` - 21 edges
2. `usePublishShellHeader()` - 18 edges
3. `ViewId` - 16 edges
4. `api` - 15 edges
5. `Case` - 11 edges
6. `RepositoryPage()` - 10 edges
7. `compilerOptions` - 10 edges
8. `EvidenceHandle` - 9 edges
9. `Capabilities` - 8 edges
10. `EvidenceInbox()` - 8 edges

## Surprising Connections (you probably didn't know these)
- `Sidebar()` --calls--> `useTheme()`  [EXTRACTED]
  src/layout/Sidebar.tsx → src/ThemeProvider.tsx
- `ExecutorLoginModalProps` --references--> `ExecutorId`  [EXTRACTED]
  src/components/ExecutorLoginModal.tsx → src/api/types.ts
- `CaseSearchModalProps` --references--> `Case`  [EXTRACTED]
  src/components/CaseSearchModal.tsx → src/api/types.ts
- `NewCaseModalProps` --references--> `Case`  [EXTRACTED]
  src/components/NewCaseModal.tsx → src/api/types.ts
- `ActiveCaseContextValue` --references--> `Case`  [EXTRACTED]
  src/state/activeCase.tsx → src/api/types.ts

## Import Cycles
- None detected.

## Communities (10 total, 0 thin omitted)

### Community 0 - "App.tsx"
Cohesion: 0.06
Nodes (54): AgentFinding, Capabilities, ExecutorCost, ToolUsage, App(), initialView(), AppShell(), AppShellProps (+46 more)

### Community 1 - "types.ts"
Cohesion: 0.06
Nodes (57): download(), getToken(), post(), readDetail(), request(), upload(), AdjudicateRequest, AgentJob (+49 more)

### Community 2 - "RepositoryPage.tsx"
Cohesion: 0.14
Nodes (31): EvidenceHandle, EvidenceRegisterJob, EvidenceSource, EvidenceInbox(), EvidenceInboxProps, FILE_INPUT_ACCEPT, FORMATS_HINT, PHASE_LABEL (+23 more)

### Community 3 - "activeCase.tsx"
Cohesion: 0.09
Nodes (25): api, Case, CaseFilter, CaseSearchModal(), CaseSearchModalProps, CaseSort, FILTER_LABEL, Pane (+17 more)

### Community 4 - "package.json"
Cohesion: 0.07
Nodes (26): dependencies, react, react-dom, description, devDependencies, @types/react, @types/react-dom, typescript (+18 more)

### Community 5 - "ChatPage.tsx"
Cohesion: 0.15
Nodes (18): AgentSummary, StreamEvent, alignOf(), CellAlign, ChatMessage, ChatPage(), ChatPageProps, clockOf() (+10 more)

### Community 6 - "DocumentsPage.tsx"
Cohesion: 0.16
Nodes (13): ApiError, DocumentBlock, DocumentFull, DocumentMeta, DocumentVerifyResult, GenerateReportRequest, DocumentsPage(), fmtDate() (+5 more)

### Community 7 - "Community 7"
Cohesion: 0.12
Nodes (15): compilerOptions, jsx, lib, module, moduleResolution, noEmit, skipLibCheck, strict (+7 more)

### Community 8 - "TimelinePage.tsx"
Cohesion: 0.20
Nodes (12): FsRelevantEvent, FsTimelineEvent, FsTimelineJob, FsTimelineResult, TimelineEvent, CATEGORY_LABEL, evidenceName(), fmtUtc() (+4 more)

## Knowledge Gaps
- **102 isolated node(s):** `name`, `version`, `private`, `description`, `type` (+97 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `api` connect `activeCase.tsx` to `App.tsx`, `types.ts`, `RepositoryPage.tsx`, `ChatPage.tsx`, `DocumentsPage.tsx`, `TimelinePage.tsx`?**
  _High betweenness centrality (0.023) - this node is a cross-community bridge._
- **Why does `useActiveCase()` connect `App.tsx` to `types.ts`, `RepositoryPage.tsx`, `activeCase.tsx`, `DocumentsPage.tsx`, `TimelinePage.tsx`?**
  _High betweenness centrality (0.022) - this node is a cross-community bridge._
- **Why does `ViewId` connect `App.tsx` to `types.ts`, `RepositoryPage.tsx`?**
  _High betweenness centrality (0.020) - this node is a cross-community bridge._
- **What connects `name`, `version`, `private` to the rest of the system?**
  _102 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `App.tsx` be split into smaller, more focused modules?**
  _Cohesion score 0.06490384615384616 - nodes in this community are weakly interconnected._
- **Should `types.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.05658381808566896 - nodes in this community are weakly interconnected._
- **Should `RepositoryPage.tsx` be split into smaller, more focused modules?**
  _Cohesion score 0.13513513513513514 - nodes in this community are weakly interconnected._