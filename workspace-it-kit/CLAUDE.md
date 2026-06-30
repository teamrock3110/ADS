# workspace-it-kit

コーポレートIT担当向け **Task Worker**（4ペイン）。

## 画面 SSoT

`components/workspace/Workspace.tsx`

| ペイン | コンポーネント | 幅 | 責務 |
|--------|----------------|-----|------|
| P1 | `TaskListPane.tsx` | w-64 | 選ぶ |
| P2 | `TaskContextPane.tsx` | flex 最広（min-w-[380px]） | 読む — 概要・作業メモ・関連リンク |
| P3 | `ReportInputPane.tsx` | w-80 | 書く — 報告入力3欄（進捗・課題・相談） |
| P4 | `ReportPane.tsx` | w-72（折りたたみ可） | 確認する — 週次報告書プレビュー＋AI生成 |

## データ

- `data/tasks.json`
- `data/task-links.json`
- `lib/it/schema.ts` / `report.ts` / `links.ts`

## 今月スコープ

操作 + モックデータ。永続化なし（来月 localStorage）。

## やらないこと

- Jira API（その次）
- 関連チケット自動検索（関連リンクに置換済み）
