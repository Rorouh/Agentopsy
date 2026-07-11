# Graph Report - C:\Users\super\Desktop\TFM - Forensia\Forensia-AI\tools\graph\out\web  (2026-07-11)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 249 nodes · 556 edges · 10 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS · INFERRED: 1 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `410fd11f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Community 0
- Community 1
- Community 2
- Community 3
- Community 4
- Community 5
- Community 6
- Community 7
- Community 8

## God Nodes (most connected - your core abstractions)
1. `ViewId` - 18 edges
2. `Button()` - 13 edges
3. `formatDate()` - 11 edges
4. `Capabilities` - 10 edges
5. `CaseSummary` - 10 edges
6. `EvidenceFile` - 10 edges
7. `Badge()` - 10 edges
8. `compilerOptions` - 10 edges
9. `Case` - 8 edges
10. `EvidenceHandle` - 8 edges

## Surprising Connections (you probably didn't know these)
- `SystemStatusPageProps` --references--> `Capabilities`  [EXTRACTED]
  src/pages/SystemStatusPage.tsx → src/api/types.ts
- `ActiveCaseHeaderProps` --references--> `Case`  [EXTRACTED]
  src/components/ActiveCaseHeader.tsx → src/api/types.ts
- `EvidenceTableProps` --references--> `EvidenceHandle`  [EXTRACTED]
  src/components/EvidenceTable.tsx → src/api/types.ts
- `CaseRow()` --calls--> `formatDate()`  [EXTRACTED]
  src/components/CaseSearchModal.tsx → src/utils/format.ts
- `RepositoryPageProps` --references--> `ViewId`  [EXTRACTED]
  src/pages/RepositoryPage.tsx → src/navigation/navItems.ts

## Import Cycles
- None detected.

## Communities (10 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.09
Nodes (39): api, ApiError, getToken(), post(), readDetail(), request(), AgentFinding, AgentSummary (+31 more)

### Community 1 - "Community 1"
Cohesion: 0.12
Nodes (31): DocumentViewerPage(), DocumentViewerPageProps, MitreAttackPage(), MitreAttackPageProps, SEVERITY_FILTERS, SEVERITY_LABEL, TimelinePageProps, CaseStatus (+23 more)

### Community 2 - "Community 2"
Cohesion: 0.09
Nodes (23): EditableKey, KEY_HINTS, KEY_LABELS, SettingsPage(), SettingsPageProps, TabId, TABS, SystemStatusPage() (+15 more)

### Community 3 - "Community 3"
Cohesion: 0.14
Nodes (22): EvidenceSource, ActiveCaseHeader(), ActiveCaseHeaderProps, EvidenceInbox(), EvidenceInboxProps, FORMATS_HINT, evidenceFileName(), EvidenceTable() (+14 more)

### Community 4 - "Community 4"
Cohesion: 0.13
Nodes (22): App(), AppShell(), AppShellProps, ICON_PROPS, NAV_ICONS, Sidebar(), SidebarProps, guideSteps (+14 more)

### Community 5 - "Community 5"
Cohesion: 0.07
Nodes (26): dependencies, react, react-dom, description, devDependencies, @types/react, @types/react-dom, typescript (+18 more)

### Community 6 - "Community 6"
Cohesion: 0.12
Nodes (19): CaseFilter, CaseRow(), CaseSearchModal(), CaseSearchModalProps, CaseSort, FILTER_LABEL, EMPTY_FORM, FormState (+11 more)

### Community 7 - "Community 7"
Cohesion: 0.12
Nodes (15): compilerOptions, jsx, lib, module, moduleResolution, noEmit, skipLibCheck, strict (+7 more)

### Community 8 - "Community 8"
Cohesion: 0.40
Nodes (3): MetricCardProps, MetricVariant, VARIANT_COLOR

## Knowledge Gaps
- **86 isolated node(s):** `name`, `version`, `private`, `description`, `type` (+81 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ViewId` connect `Community 4` to `Community 0`, `Community 1`, `Community 2`, `Community 6`?**
  _High betweenness centrality (0.044) - this node is a cross-community bridge._
- **Why does `Button()` connect `Community 3` to `Community 0`, `Community 1`, `Community 2`, `Community 4`, `Community 6`?**
  _High betweenness centrality (0.025) - this node is a cross-community bridge._
- **Why does `Capabilities` connect `Community 0` to `Community 2`, `Community 4`?**
  _High betweenness centrality (0.011) - this node is a cross-community bridge._
- **What connects `name`, `version`, `private` to the rest of the system?**
  _86 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.08792270531400966 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.11740890688259109 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.08870967741935484 - nodes in this community are weakly interconnected._