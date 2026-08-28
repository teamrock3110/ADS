# Fortinet PSIRT Watcher 実装設計書（Claude Code 引き継ぎ用）

**作成日**: 2026-08-11
**現行バージョン**: v5（動作確認済み）
**実行環境**: Google Apps Script + スプレッドシート + Gemini API + Slack
**上位文書**: 『設計書v2：脆弱性 影響判定・通知ツール』（別ファイル。目的・業務背景・対応基準はそちらが正）

このファイルは、対話で積み上げた実装judgmentをClaude Codeが引き継ぐためのもの。
上位文書と矛盾する場合、業務要件は上位文書、実装の現状はこのファイルが正。

---

## 1. 現在地

### 1.1 動いているもの（v5・全経路検証済み）

```
毎朝9時トリガー
  → 未判定行を削除（再取得対象に戻す）
  → Fortinet PSIRT RSS 取得（50件程度）
  → 台帳の FG-IR 列と突合し新着のみ抽出（上限30件/回）
  → 各アドバイザリの CSAF(JSON) 取得
  → 自社該当バージョンをコードで絞り込み
  → Gemini で判定（10件ずつ分割、503/429は5秒→10秒でリトライ）
  → 台帳（24列）に記録
  → 非該当以外を Slack 通知
```

### 1.2 検証済みの事実（再検証不要）

| 事実 | 詳細 |
|---|---|
| RSS URL | `https://filestore.fortinet.com/fortiguard/rss/ir.xml` が実取得可能。`www.fortiguard.com/rss/ir.xml` は公式記載だが今回の検証では filestore のみ200確認 |
| CSAF取得経路 | アドバイザリHTML内の `csaf_url=(https://...json)` を正規表現で抽出→取得。HTML依存はこの1箇所のみ |
| CSAFに全部入っている | 影響機能(notes[summary])・緩和策(notes[Workarounds])・影響(threats[impact])・CWE・CVSSベクター・影響バージョン(product_status.known_affected)・修正版(remediations[vendor_fix])・公開日(tracking.initial_release_date)。**HTMLパース不要。NVD API 不要**（上位文書3.2からの変更） |
| 公開サイクル | High以下は毎月第2火曜、Criticalは随時臨時公開。分母確定に使える |
| Gemini無料枠 | 請求先アカウント未紐付けなら課金されない。上限超過は429エラーであり請求ではない。無料枠は入力がGoogleの製品改善に使用される（本番資産データを流す前に有料化を検討） |
| GAS制限 | UrlFetch 20,000回/日(個人)、トリガー90分/日、1実行6分。本ツールは1日数十回で余裕 |
| JPCERT RSS | `https://www.jpcert.or.jp/rss/jpcert.rdf`(RDF形式=RSS1.0、パースはFortinetのRSS2.0と別実装が必要)。**CVE番号はタイトルに無いことが多い**（実測21件中2件のみ）。製品名キーワードで拾う |

### 1.3 ユーザーとの合意事項（変更する場合は要相談）

1. **AIプロバイダ切替**: `AI_PROVIDER = 'gemini' | 'claude'` の1行で切替。プロンプトは共通関数 `buildJudgePrompt_` に一元化
2. **KEVを使う**: ただし「KEV掲載＋機能使用中のとき対応」の基準を先に承認させてから。KEV掲載を単独で報告に出さない（機能使用状況とセットで書く）
3. **JPCERT/CCを使う**: 判定には混ぜない。製品名(Fortinet/FortiOS/FortiGate/FortiClient)で拾い、別シート記録＋月次の参考リンクのみ
4. **CSAFには毎回補足を付ける**: ユーザー向け説明では「CSAF（Fortinetが脆弱性情報を機械可読なJSONで公開しているファイル）」のように書く
5. **理由の義務付け**: 判定には必ず「【理由】」で始まる根拠を付ける。事実のみ、感想・一般論禁止
6. **非該当に優先度を付けない**: プロンプト指示＋コードで強制上書きの二重防御
7. **判定ラベル**: 現在は「該当/非該当/要確認」＋優先度4段階。設計書v2の4分類(`act_now`/`act_scheduled`/`no_action`/`needs_review`)への移行は**機能台帳の実装時にまとめて行う**（対応基準6.2が室長未承認のため境界は暫定になる）

### 1.4 設計原則（上位文書の付録より。実装で厳守）

- **決定的な処理はコード、自然言語処理のみLLM**
  - コード担当: バージョン絞り込み(`filterAffectedForAssets_`)、無認証リモート判定(`isUnauthRemote_`: AV:N∧PR:N∧UI:N)、非該当時の優先度クリア、既読管理
  - LLM担当: 機能名の抽出、日本語平易化、バージョン範囲の該非判断
- **公式記載の範囲のみ出力**: 「何が起きるか」はCSAF記載の範囲で書く。被害の推測禁止。用語の言い換え（captive portal→ネットワーク接続時の認証機能）は許容
- **安全側に倒す**: 判定不能は「要確認」として正直に出す。見逃しゼロ必須、過検知は許容

---

## 2. 現行実装（v5）の仕様

### 2.1 ファイル構成

単一GASファイル `fortinet_psirt_watcher_v5.gs`（コード全文は別添。以下は構造）。

```
設定定数     AI_PROVIDER / GEMINI_MODEL('gemini-3.6-flash') / CLAUDE_MODEL('claude-sonnet-5')
             RSS_URL / MAX_ITEMS_PER_RUN=30 / AI_CHUNK_SIZE=10
             UNJUDGED_VALUES=['','未判定','取得失敗']
エントリ     setup() / migrateLedgerHeaders() / createDailyTrigger() / main()
取得         fetchRssItems_() / parsePubDate_() / fetchCsaf_()
前処理       getKnownIrNumbers_() / purgeUnjudgedRows_() / filterAffectedForAssets_()
判定         judgeWithAI_() / buildJudgePrompt_() / callGemini_() / callClaude_()
             isUnauthRemote_()
出力         writeLedger_() / notifySlack_()
テスト       testProps() / testRss() / testCsaf() / testFilter() / testAi()
```

### 2.2 スプレッドシート

**「資産」シート**: `製品 / バージョン / 台数 / インターネット公開 / 備考`
現在はサンプル値。実データ投入は無料枠の学習利用の件をユーザーが判断してから。

**「台帳」シート**（24列・判断に使う順）:
```
取得日時 | 公開日 | FG-IR | タイトル | 判定 | 優先度 | 理由 | 影響機能名
| 何が起きるか(日本語) | 対応方針 | 修正バージョン | 自社該当バージョン
| CVSS | 深刻度 | 無認証リモート | 緩和策 | CVE | CWE
| CVSSベクター | 影響機能 | 何が起きるか | 影響バージョン | URL | 判定AI
```
- 公開日は Date 型、`yyyy/mm/dd` 書式を setNumberFormat で適用
- FG-IR が主キー（既読判定）。行削除＝再取得対象化
- 新着は末尾追記。並びは保証しない（公開日でソートする前提）

### 2.3 スクリプトプロパティ

`GEMINI_API_KEY` / `ANTHROPIC_API_KEY` / `SLACK_WEBHOOK_URL`
コードへのベタ書き禁止。SLACK_WEBHOOK_URL 未設定時は通知スキップ（エラーにしない）。

### 2.4 AI判定の入出力

入力（アドバイザリごと）: ir / title / 影響機能の記述 / 影響の種類 / 脆弱性の種類 / cvss / severity / 無認証リモート / 対象製品の全影響バージョン / 自社該当バージョン / 修正バージョン / 緩和策
＋ 資産シート全行

出力スキーマ（JSON配列のみ、コードフェンス禁止を指示）:
```json
[{"ir":"FG-IR-...","判定":"該当","優先度":"高","理由":"【理由】...",
  "影響機能名":"captive portal","何が起きるか":"...","対応方針":"...","修正バージョン":"..."}]
```

パース: 応答から `[` 〜 `]` を切り出して JSON.parse（前後のノイズ耐性）。
Gemini は `responseMimeType:'application/json'`, `maxOutputTokens:32768`, `finishReason!=='STOP'` を警告ログ。

### 2.5 既知の障害と対処（実装済み）

| 障害 | 対処 |
|---|---|
| 20件一括でJSON切れ | AI_CHUNK_SIZE=10 に分割。チャンク単位で失敗を隔離 |
| Gemini 503 (高負荷) | 5秒→10秒の指数リトライ最大3回。429も同様 |
| 失敗チャンクの取りこぼし | 未判定行を main() 冒頭で purge → 次回自動再取得 |
| 非該当なのに優先度「緊急」 | 非該当時は優先度をコードで空文字に強制 |

---

## 3. 未実装（優先順）

### 3.1 影響機能名の正規化【次にやる】

**実測の問題**（50件の台帳より）:
- 「不明」14件（約3割）— summaryから機能名を特定できず
- 表記ゆれ: `CLI / CLI command / CLI commands` `API endpoint / API endpoints / API handlers` `GUI / GUI features / administrative interface` `capwap daemon / capwap protocol`

**方針**: AI抽出時に統制語彙（正規化済み機能キーのリスト）から選ばせる。語彙は台帳50件の実データから起こす。語彙にないものは新語として報告させ、人が語彙に追加する運用。
これは次の機能台帳の前提整備。

### 3.2 機能台帳（設計書v2の4.2）【本丸】

判定軸を「バージョン該当」から「該当機能を使っているか」へ。
- シート列: `product_id / feature_key / feature_names(別名リスト) / in_use(yes|no|unknown) / verified_by / verified_at`
- 突合はコード（正規化済み機能名 × feature_names）。**LLMに使用有無を判断させない**
- 初期投入: 台帳の影響機能名50件分を棚卸し → CLIで確認して埋める（ユーザー作業）
- in_use=unknown は「要確認」に落ちる。初期は要確認が大量に出るため、暫定運用ルールが必要（上位文書11.2の未決事項）
- **このタイミングで判定4分類への移行も実施**（1.3-7）

### 3.3 KEV連携

- `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` を取得し CVE 番号で照合
- 台帳に `KEV掲載` 列追加
- 通知・月次では必ず機能使用状況とセットで表示（合意事項2）

### 3.4 JPCERT/CC 別シート記録

- RDF(RSS1.0) パーサを別実装（`<item>` が channel 直下でなくルート直下）
- タイトルに Fortinet/FortiOS/FortiGate/FortiClient を含む記事のみ「JPCERT注意喚起」シートへ
- 判定に混ぜない。月次の参考情報のみ

### 3.5 月次サマリ（Googleドキュメント）

上位文書7.2の形式。**機能台帳・対応基準承認後に着手**（中身が揃うまで器だけ作らない、とユーザー合意済み）。
DocumentApp で定例アジェンダに草案追記。

### 3.6 設計フェーズ送り（ユーザーが別途設計すると明言）

- 緊急度判定ロジックの条件式化（BOD 26-04 の4条件、「技術的影響が大きい」の閾値定義）
- Windows/macOS の扱い（KEVのみ通知でよいか。Jamf/Intune の実適用率確認が前提）
- 判定4分類の期限表（室長承認が必要。上位文書6.2）

---

## 4. 運用手順（現状）

### 4.1 セットアップ済み環境

- スプレッドシート＋GAS（v5貼付済み）
- Gemini APIキー: 個人アカウント・新規プロジェクト・請求先なし（無料枠）
- Slack: 個人検証用ワークスペースにアプリ「Notify-me」、Webhook先はSlackbot（本人のみ閲覧）
- 日次トリガー: main() 毎朝9時台

### 4.2 テスト実行順（コード変更時は毎回）

```
testProps → (migrateLedgerHeaders) → testRss → testCsaf → testFilter → testAi → main
```
- testCsaf は FG-IR-26-154 固定。期待値: features="Buffer over-read in captive portal", unauthRemote="いいえ"(PR:Lのため), workarounds="なし"
- testAi は該当/非該当の2ダミー。非該当側で理由が「対象製品名＋自社資産にない」形式になることを確認
- 列構成変更時: migrateLedgerHeaders → データ行全削除 → main×2回（50件÷30件上限）

### 4.3 本番移行時のTODO

- [ ] 資産シートに実データ投入（→同時に Gemini 有料化 or 資産をAIに渡さない設計へ変更。無料枠は学習利用されるため）
- [ ] Slack Webhook を TVer ワークスペースへ切替（アプリ上限・管理者承認制の可能性に注意）
- [ ] Gemini APIキーを会社アカウントで再発行（組織ポリシーでIAM権限が必要な場合あり）
- [ ] 対応基準の室長承認（上位文書11.3。**ツールより先**）

---

## 5. ユーザーコンテキスト（対話スタイル）

- GAS経験少。**1ステップずつ**進め、各ステップで実行ログを確認してから次へ
- 説明は結論ファースト、非エンジニアにも通じる言い換え付き（userPreferences 参照）
- 専門用語の初出時は毎回補足（特にCSAF。1.3-4）
- 「なぜその値/その設計か」を必ず問われる。根拠のない断定をすると指摘される。適当に置いた値は「根拠はない」と正直に言うこと
- 判定結果の品質に厳しい。「担当者が月次でアクションに移せるか」が受け入れ基準
