# Task Worker データ設計（共有用）

コーポレートIT担当向けの **Task Worker** — タスクを見ながら作業メモ・定例報告を書く4ペインのWebツール。

---

## 設計の芯（1文）

> **タスクの骨格（外部）** と **自分の作業データ（Task Worker）** を分け、将来 JIRA 連携しても作業データをそのまま残せるようにしている。

---

## 2層モデル

```mermaid
flowchart TB
  subgraph Master["骨格 Master — タスクそのもの"]
    M1["タイトル / 期限 / 概要 / コメント"]
  end

  subgraph Overlay["作業 Overlay — Task Worker 独自"]
    O1["定例報告 3欄"]
    O2["作業メモ"]
    O3["リンク / 遅延 / 完了"]
  end

  ID["task.id（例: CIT-201）"]
  ID --> Master
  ID --> Overlay
```

| 層 | 中身 | 将来の正本 |
|----|------|------------|
| **Master** | チケット情報 | **JIRA** |
| **Overlay** | 報告・メモ・リンク等 | **Neon DB**（Phase 1 はブラウザ） |

---

## Phase 1 の保存場所

```mermaid
flowchart LR
  subgraph Files["ファイル（リポジトリ）"]
    TJ["tasks.json\n公式タスク"]
    TL["task-links.json\n初期リンク"]
  end

  subgraph Browser["ブラウザ localStorage v3"]
    LT["localTasks\n追加タスク LOCAL-001"]
    OV["Overlay\n報告・メモ・リンク・完了"]
    SEL["selectedTaskId"]
  end

  TJ --> UI["4ペイン画面"]
  LT --> UI
  TL --> UI
  OV --> UI
  SEL --> UI
```

---

## タスクは2種類だけ

```mermaid
flowchart TB
  subgraph Official["公式タスク（tasks.json）"]
    A1["ID: CIT-201"]
    A2["骨格: 表示のみ"]
    A3["削除不可 → 完了のみ"]
  end

  subgraph Added["追加タスク（+ ボタン）"]
    B1["ID: LOCAL-001"]
    B2["骨格: 編集可"]
    B3["削除可"]
  end

  subgraph Shared["共通（Overlay）"]
    C1["報告・メモ・リンク\n→ 同じ保存方式"]
  end

  Official --> Shared
  Added --> Shared
```

| | 公式タスク | 追加タスク |
|--|-----------|-----------|
| 保存 | `tasks.json` | `localStorage` |
| 追加 | ファイル編集 | P1 の **+** |
| 骨格編集 | 不可 | 可 |
| JIRA 後 | **自動同期** | **手動で紐付け** |

---

## ペイン別：何がどこに保存されるか

```mermaid
flowchart TB
  P1["P1 タスク一覧"]
  P2["P2 タスク詳細"]
  P3["P3 関連リンク"]
  P4["P4 週次報告書"]

  P1 -->|骨格・LOCAL追加| LS1["localStorage / tasks.json"]
  P1 -->|完了・選択| LS2["localStorage Overlay"]

  P2 -->|骨格 LOCALのみ| LS1
  P2 -->|メモ・報告3欄・遅延| LS2

  P3 -->|追加リンク| LS2
  P3 -->|初期リンク| JSON["task-links.json"]

  P4 -->|プレビュー| NONE["保存しない\nP2 から生成"]
```

| ペイン | 保存する | 保存しない |
|--------|----------|------------|
| **P1** | 選択タスク・完了状態・LOCAL追加 | 報告済バッジ（計算値） |
| **P2** | メモ・報告3欄・遅延・LOCAL骨格 | 折りたたみ状態 |
| **P3** | ユーザー追加リンク | プレビュー |
| **P4** | — | 報告書本文（P2から生成） |

---

## 将来：JIRA 連携後

```mermaid
flowchart LR
  JIRA["JIRA API\n骨格の正本"]
  Neon["Neon DB\nOverlay の正本"]
  App["Task Worker"]

  JIRA -->|"起動時 + 手動更新"| App
  Neon <-->|"読み書き"| App

  LS["localStorage\n（Phase 1 データ）"]
  LS -->|"初回接続時に一括移行"| Neon
```

| 操作 | 手動が必要？ |
|------|-------------|
| JIRA チケット（CIT-xxx）を表示 | **不要** — 同期で自動 |
| 作業データの引き継ぎ | **不要** — 同じ ID で紐付く |
| LOCAL → JIRA 化 | **必要** — チケット作成後に手動紐付け |

---

## なぜこうするか（3点）

1. **JIRA が来ても作業データを捨てない** — 骨格と作業を最初から分離
2. **Phase 1 は DB なしで動く** — localStorage で最速リリース
3. **LOCAL は JIRA 前の仮置き** — 本番チケットができたら昇格、それ以外は自動

---

## 用語

| 用語 | 意味 |
|------|------|
| **Master / 骨格** | タイトル・期限・概要などチケット本体 |
| **Overlay / 作業** | Task Worker で書く報告・メモなど |
| **公式タスク** | `tasks.json` 由来（将来 JIRA） |
| **追加タスク** | `LOCAL-001` 形式。アプリからたまに追加 |
