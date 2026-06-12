# workspace-it-kit

コーポレートIT担当向け **Task Worker**（4ペイン）。

## 画面 SSoT

`components/workspace/Workspace.tsx`

| ペイン | コンポーネント | 幅 |
|--------|----------------|-----|
| P1 | `TaskListPane.tsx` | 狭 w-52 |
| P2 | `TaskDetailPane.tsx` | flex 最広 — 概要・作業メモ・報告入力3欄 |
| P3 | `ExecLinksPane.tsx` | w-64 |
| P4 | `ReportPane.tsx` | w-72（折りたたみ可） |

## データ

- `data/tasks.json`
- `data/task-links.json`
- `lib/it/schema.ts` / `report.ts` / `links.ts`

## 今月スコープ

操作 + モックデータ。永続化なし（来月 localStorage）。

## やらないこと

- Jira API（その次）
- 関連チケット自動検索（関連リンクに置換済み）
