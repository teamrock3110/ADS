# スキル模範例とチェックリスト

## 目次

- description の書き方
- 汎用スキル例
- プロジェクト固有スキル例
- コード付きスキル例
- スクリプトの品質
- 評価と反復プロセス
- チェックリスト

---

## description の書き方

### 三人称ルール

descriptionはシステムプロンプトに注入される。視点の不一致はスキル発見の問題を引き起こす。

```yaml
# 良い: 三人称
description: スキルを作成・更新・改善するスキル。「スキルを作って」「このスキルを改善して」と依頼された際に使用する。

# 悪い: 一人称
description: 私がスキルの作成を手伝います。

# 悪い: 二人称
description: あなたがスキルを作成する時に使えます。
```

### トリガーフレーズ

Claudeが100+のスキルから選択する判断材料。具体的なキーワードを含める。

```yaml
# 良い: トリガーフレーズ3つ以上 + 具体的なキーワード
description: |
  Cursor Hooksを作成・設定するスキル。
  「フックを作って」「hookを追加して」「afterFileEditを設定して」と依頼された際に使用する。

# 悪い: トリガーがない
description: Hooksを処理するスキル。

# 悪い: 抽象的すぎる
description: 設定関連の作業を支援する。
```

### 命名規則

gerund形式（動詞+ing）が活動を明確に伝える。

```
良い: processing-pdfs, analyzing-data, managing-hooks
許容: pdf-processing, data-analysis（名詞句）
避ける: helper, utils, tools（曖昧）
```

---

## 汎用スキル

プロジェクト固有の実装に依存しない。公式ドキュメント・仕様に基づく。

### 例: hook-creator

```markdown
---
name: hook-creator
description: Cursor Hooksを作成・設定するスキル。「フックを作って」「hookを追加して」「afterFileEditを設定して」と依頼された際に使用する。
---

# Hook Creator

Cursor Hooksの作成・設定を支援する。

## 概要

Hooksはエージェントループの特定タイミングでカスタムスクリプトを実行する仕組み。

## クイックスタート

[最小限の例]

## フックイベント一覧

| イベント | タイミング | 出力 |
|---------|-----------|------|
| afterFileEdit | ファイル編集後 | なし |
| stop | Agent停止時 | followup_message |

**詳細スキーマ** → [references/events.md](references/events.md)
```

**ポイント**:
- 公式ドキュメントの内容のみ
- プロジェクト固有の実装パターンなし

---

## プロジェクト固有スキル

特定プロジェクトのワークフロー・データ構造に依存。依存先を明示する。

### 構造例

```markdown
---
name: project-specific-skill
description: プロジェクト固有の作業を行うスキル。「〇〇を作って」「〇〇を更新して」と依頼された際に使用する。
---

# Project Specific Skill

## 依存

- `path/to/` 配下のディレクトリ構造
- `config.json` スキーマ（references/schema.md）
- 品質チェックフロー（.cursor/hooks/validate.sh）

## ワークフロー

[プロジェクト固有のワークフロー]

## 出力形式

[プロジェクト固有のスキーマ]
```

**ポイント**:
- 依存先を「依存」セクションで明示
- 変更時の影響範囲が把握できる

---

## コード付きスキル

スクリプトで決定的処理を実行し、SKILL.md は仕組み・実行方法・出力を記載する。

### 例: hooks-toggle

```markdown
---
name: hooks-toggle
description: Cursorフックを一時的に無効化/有効化するスキル。「フックを止めて」「フックを無効にして」「フックを有効にして」「hooks off」「hooks on」と依頼された際に使用する。
---

# Hooks Toggle

Cursor hooks と SDK hooks を同時に無効化/有効化する。

## 仕組み

各 `hooks-disabled` ファイルの有無でフックが動作を判定。
- ファイルあり → フック無効
- ファイルなし → フック有効

## 実行

bash .claude/skills/hooks-toggle/scripts/toggle-hooks.sh

## 出力

| 状態 | 出力 |
|------|------|
| 有効→無効 | `Hooks disabled (Cursor + SDK)` |
| 無効→有効 | `Hooks enabled (Cursor + SDK)` |

## 依存

- `.cursor/hooks/on-quiz-edit.ts` - スキップ判定ロジック
- `drill/tools/quiz-viewer/server/hooks/index.ts` - スキップ判定ロジック
```

**ポイント**:
- `scripts/toggle-hooks.sh` で状態管理（ファイル作成/削除）を確実に実行
- SKILL.md は**仕組み・実行方法・出力**を記載（スクリプトの実装詳細は書かない）
- 依存セクションでフック判定ロジックの所在を明示

---

## スクリプトの品質

### Solve, don't punt

スクリプト内でエラーを処理する。Claudeに丸投げしない。

```python
# 良い: エラーを自力で処理
def process_file(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        print(f"File {path} not found, creating default")
        with open(path, "w") as f:
            f.write("")
        return ""

# 悪い: Claudeに丸投げ
def process_file(path):
    return open(path).read()
```

### マジックナンバー禁止

設定値には根拠を示す。

```python
# 良い: 根拠がある
REQUEST_TIMEOUT = 30  # HTTPリクエストは通常30秒以内に完了
MAX_RETRIES = 3       # 大半の間欠的エラーは2回目で解消

# 悪い: 根拠不明
TIMEOUT = 47  # なぜ47?
RETRIES = 5   # なぜ5?
```

### 検証可能な中間出力

複雑なタスクでは「計画→検証→実行」パターンでエラーを早期発見する。

```
analyze → changes.json作成 → validate_changes.py → 問題なければ実行
```

バリデーションスクリプトのエラーメッセージは具体的に:
- 良い: `Field 'signature_date' not found. Available: customer_name, order_total`
- 悪い: `Validation failed`

---

## 評価と反復プロセス

### 評価駆動開発

スキルを書く前に、まずClaudeの現状の能力を測定する。

1. **ベースライン計測**: スキルなしでClaudeにタスクを実行させる
2. **Gap特定**: 失敗箇所・不足情報を文書化
3. **評価シナリオ作成**: Gapをテストする3つ以上のシナリオを用意
4. **最小限の記述**: Gapを埋める最小限のスキル内容を書く
5. **反復**: 評価を実行し、ベースラインと比較し、改善

```json
{
  "skills": ["pdf-processing"],
  "query": "このPDFからテキストを抽出してoutput.txtに保存して",
  "files": ["test-files/document.pdf"],
  "expected_behavior": [
    "PDFライブラリを使用してファイルを正常に読み取る",
    "全ページからテキストを漏れなく抽出する",
    "output.txtに読みやすい形式で保存する"
  ]
}
```

### Claude A/B パターン

- **Claude A**（設計者）: スキルの内容を設計・改善する会話
- **Claude B**（使用者）: スキルを使って実際のタスクを実行する会話

Claude Bの挙動を観察してClaude Aに報告し、改善する:

| 観察 | 対応 |
|------|------|
| Claudeがバンドルファイルを一度も読まない | 不要か、SKILL.mdでの参照が不十分 |
| 同じファイルを繰り返し読む | そのコンテンツをSKILL.mdに昇格 |
| 参照リンクをたどらない | リンクをより目立たせる |
| 予想外の順序でファイルを読む | 構造が直感的でない可能性 |

### チーム展開時

- スキルをチームメンバーに共有し、使用状況を観察
- 「期待通りに発動するか？」「指示は明確か？」「何が足りないか？」を確認

---

## チェックリスト

### 全スキル共通

- [ ] descriptionに「何をするか」と「いつ使うか」の両方がある
- [ ] descriptionにトリガーフレーズ3つ以上
- [ ] descriptionが三人称で書かれている
- [ ] SKILL.md 500行以内
- [ ] 冗長な説明なし
- [ ] 一貫した用語を使用
- [ ] 時間依存情報なし
- [ ] 具体的な例がある
- [ ] ワークフローに明確なステップがある
- [ ] **SSoT 監査を通過済み**（[ssot-audit.md](ssot-audit.md) の全ステップを実行し、違反なしを確認）
- [ ] **ハードコード・不整合レビューを通過済み**（[ssot-audit.md](ssot-audit.md) のレビュー全項目を確認）
- [ ] 参照は1階層まで（深いネスト禁止）
- [ ] 100行超の参照ファイルに目次がある

### 汎用スキル

- [ ] 公式ドキュメント・仕様に基づいている
- [ ] プロジェクト固有のパターン・実装がない
- [ ] 他プロジェクトでも使える

### プロジェクト固有スキル

- [ ] 「依存」セクションがある
- [ ] 依存するファイル・ワークフローが明示されている
- [ ] 依存先が変更されたときの影響範囲が分かる

### コード付きスキル

- [ ] 実行方法が SKILL.md に記載されている
- [ ] 決定的処理がスクリプトで実装されている
- [ ] スクリプトがエラーを自力で処理する
- [ ] 設定値に根拠がある（マジックナンバーなし）
- [ ] 必要なパッケージが明記されている

### テスト

- [ ] 実際のタスクでテスト済み
- [ ] 3つ以上の評価シナリオがある
- [ ] 使用予定の全モデルでテスト済み（Haiku/Sonnet/Opus）
