# Graph Report - C:\Users\super\Desktop\TFM - Forensia\Forensia-AI\tools\graph\out\web  (2026-08-03)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 298 nodes · 650 edges · 14 communities
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 4 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `8de0f3b5`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- App.tsx
- RepositoryPage.tsx
- package.json
- CaseSearchModal.tsx
- ChatPage.tsx
- client.ts
- types.ts
- DocumentsPage.tsx
- TimelinePage.tsx
- SettingsPage.tsx
- compilerOptions
- MitreAttackPage.tsx
- ThemeProvider.tsx

## God Nodes (most connected - your core abstractions)
1. `useActiveCase()` - 21 edges
2. `ViewId` - 16 edges
3. `api` - 15 edges
4. `Case` - 11 edges
5. `usePublishShellHeader()` - 10 edges
6. `compilerOptions` - 10 edges
7. `Capabilities` - 9 edges
8. `EvidenceHandle` - 9 edges
9. `RepositoryPage()` - 9 edges
10. `EvidenceInbox()` - 8 edges

## Surprising Connections (you probably didn't know these)
- `EvidenceTableProps` --references--> `EvidenceHandle`  [EXTRACTED]
  src/components/EvidenceTable.tsx → src/api/types.ts
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

## Communities (14 total, 0 thin omitted)

### Community 0 - "App.tsx"
Cohesion: 0.06
Nodes (55): api, AgentFinding, Capabilities, ExecutorCost, ToolUsage, App(), initialView(), AppShell() (+47 more)

### Community 1 - "RepositoryPage.tsx"
Cohesion: 0.14
Nodes (31): EvidenceHandle, EvidenceRegisterJob, EvidenceSource, EvidenceInbox(), EvidenceInboxProps, FILE_INPUT_ACCEPT, FORMATS_HINT, PHASE_LABEL (+23 more)

### Community 2 - "package.json"
Cohesion: 0.07
Nodes (26): dependencies, react, react-dom, description, devDependencies, @types/react, @types/react-dom, typescript (+18 more)

### Community 3 - "CaseSearchModal.tsx"
Cohesion: 0.11
Nodes (18): Case, CaseFilter, CaseSearchModal(), CaseSearchModalProps, CaseSort, FILTER_LABEL, Pane, EMPTY_FORM (+10 more)

### Community 4 - "ChatPage.tsx"
Cohesion: 0.14
Nodes (19): AgentSummary, StreamEvent, alignOf(), CellAlign, ChatMessage, ChatPage(), ChatPageProps, clockOf() (+11 more)

### Community 5 - "client.ts"
Cohesion: 0.14
Nodes (19): download(), getToken(), post(), readDetail(), request(), upload(), AdjudicateRequest, AgentJob (+11 more)

### Community 6 - "types.ts"
Cohesion: 0.11
Nodes (18): AnalysisCostEstimate, AnalysisCostTariff, AnalysisEstimate, AnalysisEstimateRange, ConfigKeyStatus, DocumentSection, ExecutorLoginState, ExecutorModelDetail (+10 more)

### Community 7 - "DocumentsPage.tsx"
Cohesion: 0.15
Nodes (15): DocumentBlock, DocumentFull, DocumentMeta, DocumentVerifyResult, FinalizeInvestigationRequest, ReportJob, DocumentsPage(), elapsed() (+7 more)

### Community 8 - "TimelinePage.tsx"
Cohesion: 0.17
Nodes (13): ApiError, FsRelevantEvent, FsTimelineEvent, FsTimelineJob, FsTimelineResult, TimelineEvent, CATEGORY_LABEL, evidenceName() (+5 more)

### Community 9 - "SettingsPage.tsx"
Cohesion: 0.15
Nodes (14): ConfigSnapshot, ExecutorId, ExecutorLoginCapability, ExecutorLoginStart, ExecutorModels, ExecutorStatus, ExecutorLoginModal(), ExecutorLoginModalProps (+6 more)

### Community 10 - "compilerOptions"
Cohesion: 0.12
Nodes (15): compilerOptions, jsx, lib, module, moduleResolution, noEmit, skipLibCheck, strict (+7 more)

### Community 11 - "MitreAttackPage.tsx"
Cohesion: 0.20
Nodes (10): MitreCatalog, MitreCoverageEntry, MitreStatus, MitreTechnique, MitreAttackPage(), Phase, PHASE_COLOR, Selection (+2 more)

### Community 12 - "ThemeProvider.tsx"
Cohesion: 0.33
Nodes (6): getInitialTheme(), Theme, ThemeContext, ThemeCtx, ThemeProvider(), useTheme()

## Knowledge Gaps
- **108 isolated node(s):** `name`, `version`, `private`, `description`, `type` (+103 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `useActiveCase()` connect `App.tsx` to `TimelinePage.tsx`, `RepositoryPage.tsx`, `MitreAttackPage.tsx`, `DocumentsPage.tsx`?**
  _High betweenness centrality (0.024) - this node is a cross-community bridge._
- **Why does `api` connect `App.tsx` to `RepositoryPage.tsx`, `CaseSearchModal.tsx`, `ChatPage.tsx`, `client.ts`, `DocumentsPage.tsx`, `TimelinePage.tsx`, `SettingsPage.tsx`, `MitreAttackPage.tsx`?**
  _High betweenness centrality (0.022) - this node is a cross-community bridge._
- **Why does `ViewId` connect `App.tsx` to `RepositoryPage.tsx`, `SettingsPage.tsx`?**
  _High betweenness centrality (0.019) - this node is a cross-community bridge._
- **What connects `name`, `version`, `private` to the rest of the system?**
  _108 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `App.tsx` be split into smaller, more focused modules?**
  _Cohesion score 0.0642243328810493 - nodes in this community are weakly interconnected._
- **Should `RepositoryPage.tsx` be split into smaller, more focused modules?**
  _Cohesion score 0.13513513513513514 - nodes in this community are weakly interconnected._
- **Should `package.json` be split into smaller, more focused modules?**
  _Cohesion score 0.07407407407407407 - nodes in this community are weakly interconnected._