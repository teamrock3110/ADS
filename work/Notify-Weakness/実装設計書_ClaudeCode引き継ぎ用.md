# Fortinet PSIRT Watcher 実装設計書（Claude Code 引き継ぎ用）

**更新日**: 2026-08-12
**現行バージョン**: v6
**実行環境**: Google Apps Script + スプレッドシート + Gemini API + Slack
**上位文書**: 『設計書v3：脆弱性 影響判定・通知ツール』（目的・業務背景・判定方針はそちらが正）

このファイルは実装の現状を引き継ぐためのもの。
上位文書と矛盾する場合、業務要件は上位文書、実装の現状はこのファイルが正。

---

## 1. 現在地

### 1.1 v6 の処理経路

```
日次9時トリガー
  → 資産シート読み込み
  → RSS 取得（50件）
  → 全件の CSAF を fetchAll で並行取得（改訂検知に最終更新日が要るため）
  → 処理済みシートと突合。新規 or 最終更新日が変わったものだけ処理（上限25/回）
  → 改訂されていたら、その FG-IR の古い行を台帳・処理済みから削除
  → CSAF の vulnerabilities[] を 1要素 = 1行 に展開（50アドバイザリ → 100行）
     ※ vulnerabilities が無いアドバイザリは noVulnRow_ で1行立てる（3件）
  → 【コード】製品突合 + バージョン数値比較 → 自社影響を全行で確定
  → 【AI】対象・要確認の行のみ日本語化（5件ずつ）
  → 処理済みシートに全アドバイザリを記録（既読管理と分母）
  → 自社製品の行だけを台帳（12列）に追記 → 自社影響順に並べ替え
  → 対象・要確認を Slack 通知
```

### 1.2 v5 から変えた 6 点と、その理由

| # | 変更 | 理由（すべて実データ由来） |
|---|---|---|
| 1 | 行の単位を「アドバイザリ」→「CVE × 製品」 | CSAF の `vulnerabilities[]` がちょうどこの粒度。50アドバイザリ→97要素、1要素に複数製品が混在した例は0件。v5 は `pushUnique_` でこれを潰していた |
| 2 | 自社影響を AI からコードへ | 実測の台帳30行のうち**20行が「未判定」**。3チャンク中2チャンクが失敗し、判定ごと消えていた。判定は決定的な計算 |
| 3 | バージョンを実際に数値比較 | v5 の `filterAffectedForAssets_` は製品名の前方一致のみで、バージョンを見ていなかった。「自社該当バージョン」列は実質「自社が持つ製品の影響バージョン行」でしかなかった |
| 4 | アドバイザリ HTML を取得しない | CSAF の URL は RSS のタイトルから導出できる（実測 50/50）。通信半減、HTML 依存ゼロ、遮断されがちな `fortiguard.fortinet.com` を通常経路から外せる |
| 5 | 列を 24 → 12 に整理 | レビュー指摘＋実データ検証。根拠のない `優先度`、CVSSの関数でしかない `深刻度`、値が割れない `無認証リモート` などを削除し、`利用有無の確認方法` を追加（上位文書 5.1） |
| 6 | 未判定行の削除をやめた | v5 は判定できない行を消して再取得していた。取得済みの事実まで捨てる。v6 は行を残し AI 列だけ `backfillAiColumns_()` で埋め直す |

### 1.3 検証済みの事実（再検証不要）

| 事実 | 詳細 |
|---|---|
| RSS URL | `https://filestore.fortinet.com/fortiguard/rss/ir.xml` が実取得可能（50件） |
| **CSAF URL の導出** | `csaf_<タイトルのスラッグ>_<fg-ir小文字>.json`。スラッグは「小文字化→英数字以外をハイフン→連続ハイフンを1つに」。**RSS 50件すべてで成功** |
| **プロキシ** | `fortiguard.fortinet.com` は環境によって遮断される（検証環境で実際に遮断）。`filestore.fortinet.com` は通る |
| CSAF に全部入っている | 影響機能(notes[summary])・影響(threats[impact])・CVSS・影響バージョン(product_status.known_affected)・修正版(remediations[vendor_fix])・製品名(scores[].products)・公開日(tracking.initial_release_date)。**HTMLパース不要。NVD API 不要** |
| **Workarounds はほぼ空** | 97要素すべて `N/A`。実質的な緩和策の記載は**0件**。上位文書 §6.2 の期限設計の前提が崩れる（上位文書 1.1） |
| **`vulnerabilities[].title` は脆弱性名ではない** | `FortiOS - LOW - FG-IR-24-257` のような内部管理用文字列。脆弱性名は `document.title` |
| **製品名に空白が入る** | `FortiSOAR PaaS` / `FortiAnalyzer Cloud` / `FortiSOAR on-premise`。先頭1語を製品名とみなす実装は誤る。`scores[].products` を使う |
| バージョン表記は7種類 | 上位文書 1.5 の表。`25.1.c` のような非数値は比較不能 → `要確認` に落とす |
| CVSS | 97件すべて v3。v4 は 0 件（コードは v4 も読む） |
| Gemini 無料枠 | 請求先未紐付けなら課金されない。上限超過は429であり請求ではない。入力が Google の製品改善に使用される（本番資産を流す前に有料化を検討） |
| GAS制限 | UrlFetch 20,000回/日、1実行6分。1回の実行は **51リクエスト・264KB・2〜3秒**（上限の0.26%）。日次で回しても問題ない |
| **RSSは50件しか持たない** | 公表ペースは平均11件/月・最大18件/月。50件枠は平均4.5か月分。2〜3か月止めると溢れ、**エラーも出ずに永久に欠落する**。`warnIfFeedOverflowed_` が前回との重なりを数えて警告する |
| JPCERT RSS | `https://www.jpcert.or.jp/rss/jpcert.rdf`（RDF形式=RSS1.0、パースは別実装が必要）。CVE番号はタイトルに無いことが多い（実測21件中2件） |

### 1.4 ユーザーとの合意事項（変更する場合は要相談）

1. **AIプロバイダ切替**: `AI_PROVIDER = 'gemini' | 'claude'` の1行で切替。プロンプトは `buildEnrichPrompt_` に一元化
2. **KEVを使う**: ただし「KEV掲載＋機能使用中のとき対応」の基準を先に承認させてから。KEV掲載を単独で報告に出さない
3. **JPCERT/CCを使う**: 判定には混ぜない。製品名で拾い、別シート記録＋月次の参考リンクのみ
4. **CSAFには毎回補足を付ける**: ユーザー向け説明では「CSAF（Fortinetが脆弱性情報を機械可読なJSONで公開しているファイル）」のように書く
5. **判定根拠の義務付け**: `判定根拠` は必ず埋める。v6 はコード生成なので構造上必ず入る
6. **AI に判定させない**: 自社影響はコード。AI は日本語化のみ
7. **AI に `使用中`/`未使用` を書かせない**: 機器設定を渡していないため。プロンプトで明示的に禁止

### 1.5 設計原則（実装で厳守）

- **決定的な処理はコード、自然言語処理のみ LLM**
  - コード: バージョン比較(`matchesSpec_`)、製品突合(`normProduct_`)、自社影響(`decideNotification_`)、無認証リモート(`isUnauthRemote_`)、修正版の系列絞り込み(`narrowFixVersion_`)、既読管理
  - LLM: 影響機能名の抽出、日本語平易化、確認方法の提示
- **公式記載の範囲のみ出力**: 用語の言い換え（captive portal → ネットワーク接続時に認証を求める画面）は許容、被害の推測は禁止
- **安全側に倒す**: 要確認は正直に出す。`なし` に丸めない

---

## 2. v6 の仕様

### 2.1 ファイル構成

単一 GAS ファイル `fortinet_psirt_watcher_v6.gs`。

```
設定定数   AI_PROVIDER / GEMINI_MODEL / CLAUDE_MODEL / RSS_URL / CSAF_BASE
           MAX_ADVISORIES_PER_RUN=25 / AI_CHUNK_SIZE=5 / KEEP_OUT_OF_SCOPE_MONTHS=3
           SLACK_MAX_ITEMS=5 / NOTIFY_WHEN_NO_HITS=false
           V_TARGET='あり' / V_OUT='なし' / V_UNKNOWN='要確認'
           LEDGER_HEADERS(12列) / ASSET_HEADERS / FEATURE_VOCAB(統制語彙)
エントリ   setup() / migrateLedgerHeaders() / createDailyTrigger() / main()
取得       fetchRssItems_() / slugifyTitle_() / csafUrlFor_() / fetchCsaf_()
           fetchAllCsaf_() / csafUpdatedAt_() / ymd_() / warnIfFeedOverflowed_()
展開       extractRows_() / noVulnRow_() / guessProductFromAffected_() / noteText_()
           isUnauthRemote_()
バージョン parseVersion_() / compareVersion_() / stripProductPrefix_() / matchesSpec_()
           judgeVersions_()
判定       readAssets_() / normProduct_() / assetsForProduct_() / decideNotification_()
           pickFixVersion_() / narrowFixVersion_() / jpFix_() / countVerdicts_()
           logUnownedProducts_()
AI         enrichWithAI_() / rowKey_() / buildEnrichPrompt_() / callGemini_() / callClaude_()
出力       getKnownAdvisories_() / removeRowsFor_() / writeState_() / countByMonth()
           toRowArray_() / writeLedger_() / sortLedger_()
           formatLedger_() / backfillAiColumns_() / notifySlack_()
テスト     testProps() / testRss() / testCsafUrls() / testCsaf() / testVersion()
           testJudge() / listProductNames_() / testAi()
```

### 2.2 スプレッドシート

**「資産」シート**: `製品 / バージョン / 台数 / インターネット公開 / 備考`
**現在のスコープは FortiOS のみ**（上位文書 3.1）。FortiClient / FortiClient EMS は利用者確認により判定対象外。
`製品` は Fortinet の表記に合わせる（`listProductNames_()` で実表記を一覧できる）。突合時は空白・ハイフン・大文字小文字を無視する。

**「処理済み」シート**: `最終更新日 / 初回公表日 / FG-IR / タイトル / 台帳の行数 / 対象製品`
**既読判定のキーは `FG-IR + 最終更新日`。** FG-IR だけだと改訂を見落とす（上位文書 1.10）
**既読判定はこのシートを見る（台帳ではない）。** 台帳には自社製品の行しか無いため、台帳を根拠にすると他社製品だけのアドバイザリを毎回取り直し、分母も出せなくなる（上位文書 5.1c）。`countByMonth()` で月別の公表件数を出す。

**「台帳」シート（12列）**: 並びは一次情報（NN/g・GOV.UK・CISA KEV・IPA公式シート）で裏を取っている。詳細は上位文書 5.1。
```
[A いつ・何の件・関係あるか] 最終更新日 | CVE | 自社影響（あり/なし/要確認） | CVSS | 対象サービス／製品
[B 何の脆弱性か] 脆弱性名 → ユーザ影響 → 影響機能名   ← 総論から概論の順
[C なぜ]         判定根拠（「〜のため」の1行）
[D 何をするか]   利用有無の確認方法 | 対応
[E 出典]         Fortinetアドバイザリ
```
- **`setFrozenColumns(5)`**。右の説明列を読むあいだ「いつの・どのCVEの・何が起きる件か」を保つ
- **CVSS を左端寄りに置かない。** CISA KEV は CVSS 列を持たず、IPA は影響判定の後に置く。危険度から入る設計は公式のどこにも無い
- **CVE は判定より左。** NN/g「最初の列は人が読める識別子」、KEV も cveID が先頭、IPA も 識別 → 判定 の順。判定を識別より前に置かない
- **台帳に載せるのは自社製品の行と、製品を特定できなかった行だけ**（`isLedgerRow_`）。実測で 100 行 → 18 行
- **古い `なし` だけ 3 か月で落とす**（`KEEP_OUT_OF_SCOPE_MONTHS`）。18 行 → 13 行。
  **`あり` と `要確認` は年齢で切らない。** 一律カットを試すと、まだ影響下の対象2件（CVE-2025-31514 / CVE-2025-54821）が消える（上位文書 5.1b-2）
- **`対応` は対象と要確認にしか出さない。** 保有していない製品の修正指示を並べないことが情報量削減の最大要因（対象外1行 469→234文字）
- **バージョンは生表記で出さない。** `>=7.4.0|<=7.4.8` → `7.4.0〜7.4.8`（`jpRange_`）
- **`Migrate to a fixed release` は移行先を補う。** 同じアドバイザリの他系列にベンダーが書いた `Upgrade to X` から引く（`migrateTarget_`）。推測ではなく転記
- **12列目**は `=HYPERLINK(url, "FG-IR-26-150")`。既読判定は処理済みシートで行う
- `severity` / `unauthRemote` は行オブジェクトでは計算し続けている。対応基準が承認されたら列を戻せる（IPA公式シートが見本）
- 並びは `対象 → 要確認 → 対象外`、同順位は公開日の新しい順
- **列順を変えるときは `LEDGER_HEADERS` と `toRowArray_()` の両方を必ず同時に直す**

### 2.3 スクリプトプロパティ

`GEMINI_API_KEY` / `ANTHROPIC_API_KEY` / `SLACK_WEBHOOK_URL`
コードへのベタ書き禁止。`SLACK_WEBHOOK_URL` 未設定時は通知スキップ（エラーにしない）。

### 2.4 AI の入出力

**呼ぶ対象**: `あり` と `要確認` の行のみ（実測 100行中 19行）。`なし` には呼ばない。

入力（行ごと）: key / 自社影響 / 対象製品 / CVE / 脆弱性名 / アドバイザリの記述(summary) / 影響の種類 / CVSS / 自社利用バージョン / 脆弱性の影響バージョン / ベンダー提示の緩和策

修正版・移行の要否は AI に書かせない（`jpFix_` がコードで日本語化する）。

出力スキーマ:
```json
[{"key":"FG-IR-26-154|CVE-2025-43892|FortiOS","影響機能名":"captive portal",
  "ユーザ影響":"...","確認方法":"..."}]
```

`key` で元の行に突き合わせる。パースは `[` 〜 `]` を切り出して `JSON.parse`。
**AI が全部落ちても自社影響と根拠は台帳に残る。** 埋まらないのは `ユーザ影響` / `影響機能名` / `利用有無の確認方法` だけで、次回 `backfillAiColumns_()` が埋める。
`backfillAiColumns_()` は台帳に AI の入力を持たせていないため、該当アドバイザリの CSAF を取り直して材料を組み立て直す。

### 2.5 既知の障害と対処

| 障害 | 対処 |
|---|---|
| AI 応答の JSON 切れ | AI_CHUNK_SIZE=5。そもそも対象行が2割以下なので発生しにくい |
| Gemini 503 / 429 | 5秒→10秒の指数リトライ最大3回 |
| AI チャンクの失敗 | 判定は既にコードで確定済み。AI 列だけ空で記録し、次回 `backfillAiColumns_()` が補う |
| CSAF のスラッグ導出失敗 | HTML 経由（`csaf_url=` 正規表現）へ自動フォールバック |
| `fortiguard.fortinet.com` の遮断 | 通常経路では触らない。フォールバック時のみ |
| バージョン表記を解釈できない | `要確認` に落とす。`なし` に丸めない |
| **確認方法の列が空洞になる** | 初版プロンプトは禁止が強く逃げ道が易しかったため、AI が全行で「正確な確認手順を特定できません」と書いた。参照系コマンド（`show`/`get`/`diagnose`）を明示的に許可し、逃げ道を「影響機能名が不明・要確認の行だけ」に限定して解消（上位文書 7.3） |
| **列数を減らす移行で古い列が残る** | `migrateLedgerHeaders()` が余剰列を `deleteColumns` する。初回実行で v5 の 18〜24 列目が残った |
| **`vulnerabilities` が無いアドバイザリが消える** | 50件中3件（Linux Kernel / npm 由来）。行が作られず既読にもならないため、分母から欠落し毎回取得し直す。`noVulnRow_` で `要確認` を1行立てる（上位文書 1.8） |
| **アドバイザリの改訂を見落とす** | RSS 50件中6件が改訂もの（うち3件が FortiOS）。FG-IR も RSS の pubDate も改訂で変わらないため、CSAF の `current_release_date` を見ないと検知できない。既読キーを `FG-IR + 最終更新日` にし、改訂時は古い行を削除して入れ直す（上位文書 1.10） |
| **Slack が読み飛ばされる** | 平文で1件7行だと全要素が同じ太さで目が滑る。Block Kit で「太字＝何が起きるか／通常＝対応／灰色＝CVE・CVSS・機能」の3層にし、確認コマンドは台帳へのリンクに逃がす（上位文書 7.4） |
| **資産シートの登録漏れが静かな見逃しになる** | スコープ内の製品が未登録だと `なし` と断定され、エラーも出ない。`logUnownedProducts_` で毎回ログに出す（上位文書 1.9） |

---

## 3. テスト実行順（コード変更時は毎回）

```
testProps → setup → (migrateLedgerHeaders) → testVersion → testRss
  → testCsafUrls → testCsaf → listProductNames_ → testJudge → testAi → main → countByMonth
```
`setup()` は「処理済み」シートを作る。既存プロジェクトでも一度実行すること（無ければ既読管理が働かない）。

| テスト | 確認すること | 期待値 |
|---|---|---|
| `testVersion` | バージョン比較の単体テスト。**API もシートも使わないので最初に流す** | 17/17 件が期待どおり |
| `testRss` | RSS が取れるか、CSAF URL が組み立てられるか | 50件 |
| `testCsafUrls` | 全件でスラッグ導出が通るか（**タイトル規則が変わると最初に壊れる箇所**） | 成功 50/50 |
| `testCsaf` | FG-IR-26-154 の展開 | **3行**（CVE 2件 × 製品 FortiOS/FortiProxy）。CVE-2026-59840 が FortiOS と FortiProxy で2行に分かれること |
| `listProductNames_` | 資産シートに書くべき製品名の実表記 | `FortiOS` `FortiClientEMS` など |
| `testJudge` | 資産シートを使って自社影響だけ流す（AI・書き込みなし） | 根拠に具体的なバージョン範囲が入ること |
| `testAi` | AI 生成を1行分 | 影響機能名に製品名が入らないこと。確認方法が指定の一文で始まること |

列構成を変えたとき: `migrateLedgerHeaders` → データ行を全削除 → `main` を2回（50件 ÷ 25件上限）。

---

## 4. 運用手順

### 4.1 セットアップ済み環境

- スプレッドシート＋GAS
- Gemini APIキー: 個人アカウント・新規プロジェクト・請求先なし（無料枠）
- Slack: 個人検証用ワークスペースのアプリ「Notify-me」、Webhook 先は Slackbot（本人のみ閲覧）
- 日次トリガー: `main()` 毎朝9時台

### 4.2 移行手順（列構成を変えたときは毎回）

1. `fortinet_psirt_watcher_v6.gs` の内容を GAS に貼り替える
2. `testVersion()` を実行（API 不要。17/17 になることを確認）
3. **`setup()`** を実行 → 「処理済み」シートが作られる
4. `migrateLedgerHeaders()` を実行
5. 台帳の**2行目以降を全削除**。処理済みシートも作り直すなら 2 行目以降を削除
6. `listProductNames_()` を実行し、資産シートの `製品` 列を実表記に合わせる
7. `testJudge()` で判定結果を目視確認
8. `main()` を **3回**（RSS 50件 ÷ 25件上限。処理済みシートが既読を持つので重複しない）
9. `countByMonth()` で月別の公表件数を確認

### 4.3 本番移行時のTODO

- [ ] 資産シートに実データ投入（→同時に Gemini 有料化 or 資産をAIに渡さない設計へ変更。無料枠は学習利用されるため）
- [ ] Slack Webhook を業務ワークスペースへ切替（アプリ上限・管理者承認制の可能性に注意）
- [ ] Gemini APIキーを会社アカウントで再発行（組織ポリシーで IAM 権限が必要な場合あり）
- [ ] 対応基準の室長承認（**ツールより先**。ただし上位文書 6.3-1 のとおり、緩和策が取れない前提で期限を引き直してから諮る）

---

## 5. 次に実装するもの（優先順）

上位文書 6.3 の保留表が正。実装順としては次のとおり。

1. **影響機能名の統制語彙の実データ化** — `FEATURE_VOCAB` は暫定で手書きしている。台帳が数十行たまったら実データから起こし直す。機能台帳の前提整備
2. **KEV 連携** — `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` を CVE で照合。実装は容易だが、基準の承認が先（合意事項1.4-2）
3. **機能台帳** — 1 が前提
4. **判断記録シート** — 台帳とは別シート。人の判断を残す（上位文書 2.2）
5. **月次サマリ（Googleドキュメント）** — 2 と 3 が揃ってから
6. **JPCERT/CC 別シート** — RDF パーサを別実装。判定には混ぜない

---

## 6. ユーザーコンテキスト（対話スタイル）

- GAS経験少。**1ステップずつ**進め、各ステップで実行ログを確認してから次へ
- 説明は結論ファースト、非エンジニアにも通じる言い換え付き
- 専門用語の初出時は毎回補足（特に CSAF）
- 「なぜその値/その設計か」を必ず問われる。根拠のない断定をすると指摘される。**適当に置いた値は「根拠はない」と正直に言うこと**
- 判定結果の品質に厳しい。「担当者が月次でアクションに移せるか」が受け入れ基準
