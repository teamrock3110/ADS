---
name: creating-skills
description: スキルを作成・更新・改善するスキル。「スキルを作って」「このスキルを改善して」「スキルを更新して」など依頼された際やスキルを更新する際に使用する。
---

# Skill Creator

**品質方針**: スキル作成は時間より品質を優先する。手順のスキップや品質チェックの省略は禁止。全ステップを確実に実行し、品質チェックを通過してから完了とする。

## 必読リファレンス（省略禁止）

**作業開始前に必ず全て読むこと。時間短縮のためにスキップしない:**

1. [references/principles.md](references/principles.md) — 核心原則・構造・判断基準
2. [references/ssot-audit.md](references/ssot-audit.md) — SSoT 監査・ハードコード不整合レビュー（ゲートとして必ず実行）
3. [references/exemplar.md](references/exemplar.md) — 模範例・品質チェックリスト
4. [references/patterns.md](references/patterns.md) — 設計パターン・サイズ目安

## 作成プロセス

### Step 0: リファレンスを読む

上記4つのリファレンスを全て読む。省略禁止。

### Step 1: 種類を判断

汎用スキルかプロジェクト固有スキルかを判断する。

→ [principles.md](references/principles.md)（スキルの種類）

### Step 2: 情報を分離

SKILL.md に置く情報と references/ に置く情報を分離する。

→ [patterns.md](references/patterns.md)（ディレクトリパターン、3段階ローディング）

### Step 3: 洗練

核心原則に基づいてスキルの内容を精査する。

→ [principles.md](references/principles.md)（洗練、簡潔性）

### Step 4: SSoT 監査（ゲート）

**SSoT 監査を通過するまで次のステップに進めない。**

[ssot-audit.md](references/ssot-audit.md) の全ステップを実行し、違反がないことを確認する。違反が見つかったら修正してから再監査。

### Step 5: 品質チェック

[exemplar.md](references/exemplar.md) のチェックリストを全項目確認する。未通過の項目があれば修正。

### Step 6: ハードコード・不整合レビュー（ゲート）

**このレビューを通過するまで完了としない。**

作成したスキルに以下の問題がないか最終確認する:

1. **ハードコードされた詳細情報がないか** — 参照先を読めばわかる具体的な値・構造・手順がスキル内にベタ書きされていないか
2. **参照先変更時の不整合リスクがないか** — 参照先が更新されたとき、スキル内の記述が古くなる箇所がないか

→ [ssot-audit.md](references/ssot-audit.md)（ハードコード・不整合レビュー）

### Step 7: 評価と反復

スキルを書いて終わりにしない。実際の使用を観察して改善する。

→ [exemplar.md](references/exemplar.md)（評価と反復プロセス）
