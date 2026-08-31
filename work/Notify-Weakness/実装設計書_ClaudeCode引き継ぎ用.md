# NW機器 脆弱性ウォッチャー 実装設計書（Claude Code 引き継ぎ用）

**更新日**: 2026-08-30
**現行バージョン**: v7（`fortinet_psirt_watcher_v7.gs` / 5,185行 / 205関数）
**実行環境**: Google Apps Script + スプレッドシート + Gemini API + Slack
**上位文書**: 『設計書v3：脆弱性 影響判定・通知ツール』（目的・業務背景・判定方針はそちらが正）
**運用手順**: [GAS実行手順_v7.md](GAS実行手順_v7.md)（貼り替え・移行・テスト・トラブル対応）

このファイルは実装の現状と、そう作った理由を引き継ぐためのもの。
上位文書と矛盾する場合、業務要件は上位文書、実装の現状はこのファイルが正。

---

## 1. このツールは何をするか

日次9時台に Fortinet / Cisco の脆弱性情報を取得し、自社資産に当たる件だけ台帳へ書き、
Slack で1通通知する。**目的は「対応要否の自動決定」ではない。**
年1回の定期OS更新を待てない例外と、設定確認が要る行を切り分けることが目的。

判定はすべてコード。LLM は日本語生成にのみ使う。

### 1.1 処理経路

```
日次9時トリガー main()
  ├ runFortinet_()
  │   資産シート読み込み
  │   → RSS 取得（ir.xml・最新50件）
  │   → 50件すべての CSAF を fetchAll で並列取得（約3〜5秒）
  │   → 処理済みシートと突合（CSAF の current_release_date と版で判定）
  │   → 差分があれば、その ID の古い行を台帳・処理済みから削除
  │   → CSAF の vulnerabilities[] を 1要素 = 1行 に展開
  │   → 【コード】製品突合 + バージョン数値比較 → 自社影響を全行で確定
  │   → 【AI】あり判定の行だけ日本語化（10件ずつ）
  │   → 台帳へ書く → 処理済みに記録する（この順序が重要。§4.3）
  ├ runCisco_()
  │   csaf_20.xml から更新のあった分だけ CSAF を取得（直列・300ms間隔）
  │   以降は Fortinet と同じ
  ├ Slack 通知（該当ありの日だけ1通）／無ければ backfillAiColumns_()
  └ finally 実行履歴シートに1行記録（落ちた実行も残す）
```

### 1.2 ベンダーで取得方法が違う理由（v7 の中核）

| | Fortinet | Cisco |
|---|---|---|
| 一覧 | `ir.xml`（最新50件・**改訂順**） | `csaf_20.xml`（最新50件） |
| CSAF の取得 | **毎回50件すべて** | 前回から更新のあった分だけ |
| 根拠 | フィードの日付が CSAF の改訂を表さない | フィードが CSAF から生成されており一致する |

**実測（2026-08-30・50件全数）**

```
Fortinet: RSS の Revised on と CSAF の current_release_date が一致  41 / 49
            RSS だけ動いて CSAF が変わらない                          6 件
            CSAF だけ動いて RSS が動かない                            2 件
Cisco   : RSS の pubDate と CSAF の current_release_date が一致     50 / 50
```

Fortinet で RSS の日付を使って候補を絞ると、**CSAF だけ改訂された件を永久に見逃す**。
実例は FG-IR-26-139（2026-05-13 公表 → CSAF 2026-06-08 改訂だが RSS は動かず）と
FG-IR-26-128（RSS 5/12・CSAF 5/13）。Fortinet はページ更新と CSAF 生成が別工程で、
日付も別々に付く。

逆に RSS だけ動く6件（FG-IR-24-257 など）は CSAF の中身が変わっていないので、
取りに行っても得るものがない。

**したがって RSS は「ID とタイトルの目次」としてだけ使い、既読判定は CSAF の実データだけで行う。**
Cisco は前提が成り立つので差分取得のままでよい（全件取得にすると直列＋300ms待ちで30〜50秒かかる）。

### 1.3 検証済みの事実（再検証不要）

| 事実 | 詳細 |
|---|---|
| Fortinet RSS | `https://filestore.fortinet.com/fortiguard/rss/ir.xml`（50件）。**pubDate 順ではなく Revised on の降順** |
| CSAF URL の導出 | `csaf_<タイトルのスラッグ>_<fg-ir小文字>.json`。スラッグは「小文字化→英数字以外をハイフン→連続ハイフンを1つに」。**RSS 50件すべてで成功** |
| **Fortinet は CSAF の目次を公開していない** | `.well-known/csaf/provider-metadata.json`・ROLIE feed・`index.txt`・`changes.csv` すべて 404。ディレクトリ一覧は 403。`security.txt` に CSAF の記載なし。BSI の CSAF アグリゲータ（登録15社）にも不在。**RSS が唯一の発見手段** |
| **アドバイザリ HTML は取得できない** | `fortiguard.fortinet.com/psirt/*` は altcha のボット対策で `Just a moment — verifying connection security` の待機ページしか返さない。本文は1文字も含まれない（OpenSSL・CVE・FortiOS すべて0件）。**HTML フォールバックは v7 で削除した** |
| **CSAF が存在しないアドバイザリがある** | Fortinet が CSAF を出し始めたのは 2025年3月頃。それ以前の案件には遡って作られていない（例: FG-IR-22-059＝2022年の OpenSSL）。改訂されると RSS には載り続けるが CSAF は404のまま |
| CSAF に全部入っている | 影響機能(notes[summary])・影響(threats[impact])・CVSS・影響バージョン(product_status.known_affected)・修正版(remediations[vendor_fix])・製品名(scores[].products)・公開日(tracking) |
| **Fortinet の `tracking.version` は常に "0"** | 49件すべて。既読判定で効いているのは `current_release_date` だけ。**この列は空欄と "0" の取り違えで一度全件誤検知を起こしている**（`f400edd`） |
| **Fortinet の `vulnerabilities[].title` は脆弱性名ではない** | `FortiOS - LOW - FG-IR-24-257` のような内部管理用文字列。脆弱性名は `document.title` |
| **Cisco の `vulnerabilities[].title` は脆弱性名** | 複数CVEのアドバイザリ11件中8件で CVE ごとに違う（例: ClamAV は ZIP / PDF / Mach-O と別々）。**未対応。現在は document.title を全行にコピーしている**（§6-3） |
| **Cisco の RSS `<title>` はアドバイザリID そのもの** | `csaf_20.xml` の仕様。人が読める題名は CSAF の `document.title` にある。v7 で切り替え済み |
| **Cisco の日付は UTC 16:00 系** | 日本時間に直すと翌日になる。公表ページの表記とは1日ずれるが、運用が日本時間なので日本時間で扱う（月末締めの要件が無いため） |
| CSAF ファイルの HTTP ヘッダ | `ETag` / `Last-Modified` を返す。条件付きGETは可能だが**採用していない**。ファイルの更新であってアドバイザリの改訂ではなく、一括再生成で全件が誤検知になる |
| 製品名に空白が入る | `FortiSOAR PaaS` / `FortiAnalyzer Cloud` / `FortiSOAR on-premise`。先頭1語を製品名とみなす実装は誤る |
| バージョン表記は7種類 | 上位文書 1.5 の表。`25.1.c` のような非数値は比較不能 → `不明` に落とす |
| **RSSは50件しか持たない** | 公表ペースは平均11件/月。ただし **Fortinet は改訂順**なので、古い件が改訂されるたび先頭に戻り末尾が押し出される。公表だけを数えた「4.5か月分」の見積もりより実際は早く溢れる。`warnIfFeedOverflowed_` が前回との重なりを数えて警告する |
| CISA KEV | 1,685件・1.6MB。`CacheService` に CVE 集合だけ6時間キャッシュ（約36KB／上限100KB）。あと3,000件増えるまで余裕あり |
| GAS制限 | UrlFetch 20,000回/日、1実行6分。差分ゼロの実行は約10秒。**50件の全再処理は6分制限に到達した実績がある** |
| Gemini 無料枠 | 1日20回程度。HTTP 429 かつ本文に `PerDay` なら日次上限で、別モデルへ退避する。**HTTP 503 は過負荷であり別物**（退避しない） |

### 1.4 ユーザーとの合意事項（変更する場合は要相談）

1. **AIプロバイダ切替**: `AI_PROVIDER = 'gemini' | 'claude'` の1行で切替。Claude 側は Haiku
2. **KEVを使う**: 「KEV掲載＋機能使用中のとき対応」の基準を承認させてから。KEV掲載を単独で報告に出さない
3. **JPCERT/CCを使う**: 判定には混ぜない
4. **CSAFには毎回補足を付ける**: ユーザー向け説明では「CSAF（機械可読な脆弱性情報のファイル）」のように書く
5. **判定根拠の義務付け**: `判定根拠` は必ず埋める
6. **AI に判定させない**: 自社影響はコード。AI は日本語化のみ
7. **AI に `使用中`/`未使用` を書かせない**: 機器設定を渡していないため

### 1.5 設計原則（実装で厳守）

- **決定的な処理はコード、自然言語処理のみ LLM**
  - コード: バージョン比較(`matchesSpec_`)、製品突合(`normProduct_`)、自社影響(`decideNotification_`)、無認証リモート(`isUnauthRemote_`)、修正版の系列絞り込み(`narrowFixVersion_`)、既読管理
  - LLM: 影響機能名の抽出、日本語平易化、確認方法の提示
- **公式記載の範囲のみ出力**: 用語の言い換えは許容、被害の推測は禁止
- **安全側に倒す**: 判定できないものは正直に出す。`なし` に丸めない
- **静かに失敗させない**: 取りこぼしが起きうる経路には、必ず人へ届く出口を用意する

---

## 2. スプレッドシート（4シート）

### 2.1 台帳（13列・左6列固定）— 対応要否を判断する作業リスト

```
最終更新日 | 自社影響 | 製品 | CVE | CVSS | KEV | 脆弱性名 | ユーザ影響 | 影響機能 | 判定根拠 | 確認方法 | 公式推奨対応 | アドバイザリ
└──── 固定表示 ────┘
```

列は確認者の読み順。「いつ検知した何か → どれくらい危ないか → どんな影響か →
なぜその判定か → 何を確認しどう直すか → 公式で裏を取る」。

- **最終更新日が先頭**。毎日動いて新着が積まれる表なので、「その行が自分にとって新しいか」を
  判断する一次情報として扱う
- **KEV は CVSS の隣**。悪用実績は CVSS より強い信号
- 並びは `自社影響` 順（あり（対応検討）→ あり（影響調査）→ なし）、第2キーが最終更新日の降順。
  作業リストなので、未処理の重い行が新しい「なし」の下に沈まないようにしている
- 台帳に載せるのは自社製品の行と、製品を特定できなかった行だけ（`isLedgerRow_`）
- **古い `なし` だけ3か月で落とす**（`KEEP_OUT_OF_SCOPE_MONTHS`）。`あり` は年齢で切らない
- 最終列は `=HYPERLINK(url, "FG-IR-26-150")`
- **列順を変えるときは `LEDGER_HEADERS` と `toRowArray_()` の両方を必ず同時に直す。**
  列幅は列名で引くようにしたので幅だけずれることはない

### 2.2 処理済み（10列）— 公表全件の記録。分母であり、除外の根拠

```
最終更新日 | 初回公表日 | ベンダー | CVE | タイトル | 自社判定 | 判定根拠 | 対象製品 | アドバイザリID | CSAF版
```

「今月10件公表されたが対象は5件。残り5件はなぜ対象外だったのか」に答えるシート。
**台帳に載らなかった行は、載せなかった根拠がここにしか残らない。**

| 自社判定 | 判定根拠の例 |
|---|---|
| `対象` | `FortiOS 7.4.11｜影響範囲内` |
| `対象外-OS影響外` | `FortiOS 7.4.11｜7.4 系の影響は 7.4.8 まで` |
| `対象外-未保有` | `資産に該当する製品が無い` |
| `対象外-情報通知` | `脆弱性ではなく公開一覧のお知らせ` |
| `判定不能` | `CSAF を取得できず判定できない` |

- 値の先頭を `対象` / `対象外` / `判定不能` で揃え、列を眺めるだけで可否が読めるようにする
- **日付を2つ並べる**のは、同じ日なら初出・違えば改訂と判別するため
- **既読判定のキーはアドバイザリID。**`アドバイザリID` は `=HYPERLINK()` だが
  セルの値は ID のままなので判定は壊れない
- **既読判定はこのシートを見る（台帳ではない）。** 台帳には自社製品の行しか無いため
- `CSAF版` は Fortinet では常に `0`。CSAF を読めなかった行だけ `未取得`
- 最終更新日の降順に自動で並べ替える（`sortState_`）
- **追記型で既存行を書き換えない。**列を増やしたら `reprocessFortinet()` / `reprocessCisco()` が要る

`countByMonth()` / `countByMonthVendor()` は**情報通知を除いて**数える。Cisco の
Advance Notification は同じ内容を個別アドバイザリで出し直す重複なので、公表件数に入れると水増しになる。

### 2.3 実行履歴（11列）— 1実行1行。動いた事実そのもの

```
実行日時 | 結果 | 確認件数 | 差分なし | 更新あり | 対象 | 対象以外 | 失敗 | 所要秒 | AI呼び出し | 備考
```

**なぜ要るか**: Slack は該当ありの日だけ鳴る（`NOTIFY_WHEN_NO_HITS = false`）。
つまり「該当なしだった日」「取得に失敗した日」「トリガーが消えて実行されなかった日」が
すべて同じ静けさに見える。実行ログの保持期間も短く後から遡れない。
**行が途切れていれば実行されていない日**と読めるようにするためのシート。

- 数字は左から右へ一直線。`確認件数 = 差分なし + 更新あり`、`更新あり = 対象 + 対象以外`
- **単位はアドバイザリ件数**。台帳の行数ではない（1 アドバイザリが CVE × 製品で複数行に開き、
  さらに古い「なし」を `isLedgerRow_` が落とすので、どう数えても一致しない）。
  この列が答えるのは「自社の資産に当たる公表がいくつあったか」であって、台帳が何行増えたかではない
- `対象以外` は残差。`対象外-未保有` / `対象外-OS影響外` / `対象外-情報通知` に加えて
  **`判定不能`（CSAF が取れず判定できなかった件）も入る**。だから「対象外」とは呼ばない。
  判定できなかった件を対象外と名乗らせると、分からなかった事実が消える。内訳は `備考` の `判定[…]`
- 取得件数（何本ダウンロードしたか）は列に出さない。ベンダーで意味が違い、
  合計すると「確認100なのに取得50、残り50はどこへ？」という誤読を生む
- `備考` は更新・失敗・エラーがあった日だけ書く。平常日は空欄。
  **何か書いてある行が見るべき行**
- `main()` が落ちても `finally` で記録する。エラー内容も備考に入る
- `AI呼び出し` は実際に投げた HTTP リクエスト数。リトライとフォールバックも1回ずつ数える
  （枠を減らすのはプロンプト数ではなくリクエスト数のため）
- `reprocess*()` など `main()` 以外からの実行では行を作らない

### 2.4 資産（9列）

```
ベンダー | 種別 | 製品 | 機種 | バージョン | 台数 | ツール対象 | 備考 | 更新日
```

- `更新日` は棚卸しした日を人が手で入れる欄。ツールは書き込まない。
  判定はバージョンの突き合わせで行うため、この表がいつ時点のものか分からないと
  判定の根拠も定まらない
- `migrateAssetHeaders()` は**入力済みの資産を消さない**。台帳や処理済みと違い、
  資産シートは人が手で維持している唯一の入力で、消すと復元できない

---

## 3. 失敗したときどうなるか

**このツールで一番避けたいのは、取りこぼしが静かに起きること。**
v7 では失敗の扱いを両ベンダーで揃えた。

```
CSAF が取れない
  → RSS にある CVSS と説明文でフォールバック行を作る       ← 両ベンダー
  → 台帳に出す（あり（影響調査））・Slack で知らせる         ← 両ベンダー
  → 処理済みに「未取得」の印を付けて記録する                 ← 両ベンダー
       ↑ 版を空欄にすると「版が空なら再取得」に毎回引っかかり、
         取得できない件を永久に取り続ける
  → Fortinet は毎回全件取りに行くので、CSAF が公開された日に
     版の不一致（未取得 ≠ 0）で自動的に拾われる
     Cisco は改訂で RSS 日付が動いた日に拾われる
```

**一度も処理できていない件の取得失敗だけメールする**（`notifyFetchFailures_`）。
記録済みの件が一時的に取れなかっただけなら送らない。

`main()` が例外で止まった場合は別途メールする（`notifyMainFailure_`）。
メールは保持期間が長く、台帳と Slack は流れるので、durable な記録として残している。

---

## 4. 実装で注意する点

### 4.1 空欄に意味を持たせない

`CSAF版` を空欄のままにすると「入力漏れ」と区別が付かず、人が埋めたり移行で正規化されたりすると
判定が壊れる。この列は `"0"` と空欄の取り違えで**一度全件を誤検知している**（`f400edd`）。
取得できていない行には `未取得` と明示的に書く。

### 4.2 削除してから書く

台帳への書き込み前に、これから書く分を**記録の有無に関わらず**削除する（`removeRowsFor_`）。
前回の実行が台帳を書いた直後に落ちていると記録が付いておらず、
消さずに追記すると同じ行が二重に並ぶ。

### 4.3 台帳を先に、処理済みを後に

```
削除 → AI 生成 → 台帳へ書く → 処理済みに記録する
                  ↑ 6分制限に当たるならここ
```

逆順だと、時間切れのときに「処理済みには記録されたが台帳には無い」状態が残り、
翌日以降は既知として扱われて改訂まで台帳に載らない（静かな取りこぼし）。
この順なら記録が付かないので次の実行でやり直せる。

`fillLedgerDisplay_` は `reasonPhrase` を通知要否の理由で上書きするため、
処理済みの判定根拠に使う値は `snapshotJudgeRows_` で**AI 生成前に控えておく**。

### 4.4 判定根拠は2種類ある

| 列 | 答える問い | 例 |
|---|---|---|
| 台帳の `判定根拠` | なぜ緊急ではないのか（通知要否） | `悪用に管理者権限が必要なため` |
| 処理済みの `判定根拠` | なぜ対象と判定したのか（自社該当） | `FortiOS 7.4.11｜影響範囲内` |

`decideNotification_` は版が影響範囲内の行に社内ルールを当てて `reasonPhrase` を
前者で上書きするので、**処理済み側で `reasonPhrase` を使ってはいけない**。

### 4.5 ベンダー差は「根拠のある非対称」だけ許す

v7 で意図的に残している非対称と、その根拠。

| 箇所 | Fortinet | Cisco | 根拠 |
|---|---|---|---|
| CSAF の取得 | 全件 | 差分のみ | フィードの日付が CSAF を反映するか（§1.2） |
| 取得の並列度 | `fetchAll` 並列 | 直列＋300ms | Cisco は API 側の作法に合わせている |
| 失敗時の CSAF 取得 | `lastSeenDate_` | `it.pubDate` | Cisco は `revisedOn` を持たないので結果が同じ。**設計ではなく成り行き。次に取得層を触るとき揃える** |

根拠を書けない非対称は残さない。

### 4.6 Slack の宛先はテーブルに置き、呼び出し側に持たせない

宛先は `SLACK_TARGETS`（`personal` / `team`）の 1 箇所だけで定義する。
`notifySlack_(rows, targetKey)` の第2引数を省くと運用宛先（`SLACK_TARGET` プロパティ、
未設定なら `personal`）になるので、**`main()` / `reprocessFortinet()` / `reprocessCisco()` の
3 箇所は宛先を知らない**。3 つ目の宛先が要るときもテーブルに 1 行足すだけで、関数は触らない。

| 関数 | 役割 |
|---|---|
| `slackWebhookUrl_(key)` | キー → Webhook URL。未設定・未知は理由をログに残して `null` |
| `operationalSlackTarget_()` | `SLACK_TARGET` → キー。**未知の値でも止めず既定へ落とす** |
| `postSlack_(url, payload)` | 送信のみ。HTTP コードを見てログに残す |

判断が 2 つある。

- **`SLACK_WEBHOOK_URL` を `..._PERSONAL` に改名しない。** 命名は揃わないが、改名した .gs を
  貼った瞬間、プロパティを直すまで日次通知が黙って止まる。それは「該当が無くて静かな日」と
  見分けが付かない（§4.1 と同じ理由）
- **`SLACK_TARGET` が未知の値でも既定へ送る。** 設定ミスを隠す妥協だが、
  誤った宛先へ 1 通出る害より、通知が消えて誰も気づかない害の方が大きい。警告はログに残す

`postSlack_` で応答コードを見るのはこの変更で足した。宛先が 1 つのうちは「届かない ＝ すぐ気づく」
だったが、宛先が複数になると片方の Webhook だけ失効しても残りが届き、欠測に気づけない。

メニューからのテスト送信（`sendSlackTest_`）はサンプル行を使い、先頭に「テスト送信」の印を足す。
印は `buildSlackPayload_` ではなく送信側で `unshift` する。**本番の見た目を作るコードは変えない。**

### 4.7 フォールバック行の製品はベンダーで絞る

`primaryAssetProduct_(assets, vendor, fallback)` は必ずベンダーを渡す。
絞らないと資産シートの先頭行（`Fortinet / FortiOS`）がどのベンダーにも返り、
Cisco のフォールバック行が「ベンダー Cisco・製品 FortiOS」になる。
Slack の機器名は `vendor` から引くので、台帳と Slack で違う製品が出ることにもなる。

`ツール対象=いいえ` の資産も外す。判定に使わないと決めた機器の製品名を判定行に
載せると、その行が何を指しているのか説明できない。

ベンダー名の表記が資産シート側で揺れている場合（`cisco` など）は一致せず
fallback（`IOS-XE` / `FortiOS`）へ落ちるが、それは元々そのベンダーの主力製品なので害はない。

**これは「どの製品か」を当てる仕組みではない。**CSAF が無い以上、自社が持っていない
製品のアドバイザリでもここで製品が付く。その解決は §6-1。

### 4.8 通知で隠す件数は、隠れる行が何かで決める

Slack に出るのは `あり（対応検討）` と `あり（影響調査）` だけで、`なし` は台帳止まり。
つまり **表示上限で隠れる行は、すべて人が見る必要のある行**になる。
上限は「読みやすさ」ではなく「隠してよいか」で決める。

`SLACK_MAX_ITEMS = 15`。数えているのは台帳の行数（CVE × 製品）なので、
Cisco の複数 CVE アドバイザリが 1 本あるだけで旧値の 5 を超えていた（ClamAV は 1 本で 7 行）。
15 の根拠は Slack 側の制約: 1 メッセージ 50 ブロック、カード 1 枚が divider + section の
2 ブロック、ヘッダ・サマリ・末尾で 4 ブロック。15 枚で 34 ブロック。
計算上 23 枚まで入るがそこまで上げないのは、読む側の限界が手前にあるため。

2 行目のサマリは `buildSlackPayload_(shown, sheetUrl, all)` の第 3 引数で**全件を渡して数える**。
`shown` で数えると内訳とカード枚数が一致してしまい、切られた事実がどこにも出ない。
読む人は 2 行目を「今日の該当件数」として読むので、そこが表示件数だと末尾の数字と繋がらない。

---

## 5. ファイル構成

単一 GAS ファイル `fortinet_psirt_watcher_v7.gs`（5,387行・212関数）。

```
設定定数   AI_PROVIDER / GEMINI_MODEL(+FALLBACKS) / CLAUDE_MODEL(Haiku)
           RSS_URL / CSAF_BASE / CISCO_CSAF_RSS_URL / KEV_FEED_URL
           MAX_ADVISORIES_PER_RUN=50 / AI_CHUNK_SIZE=10 / KEEP_OUT_OF_SCOPE_MONTHS=3
           SLACK_MAX_ITEMS=15 / NOTIFY_WHEN_NO_HITS=false
           SLACK_TARGETS{personal,team} / SLACK_TARGET_DEFAULT='personal'
           LEDGER_HEADERS(13) / STATE_HEADERS(10) / RUNLOG_HEADERS(11) / ASSET_HEADERS(9)
           STATE_VERSION_UNAVAILABLE='未取得' / aiRequestCount_ / runStats_
エントリ   setup() / migrateLedgerHeaders() / migrateAssetHeaders() / clearRunData()
           createDailyTrigger() / main() / reprocessFortinet() / reprocessCisco()
           countByMonth() / countByMonthVendor()
取得       fetchRssItems_() / slugifyTitle_() / csafUrlFor_() / fetchCsaf_() / fetchAllCsaf_()
           fetchCiscoCsafRssItems_() / fetchCiscoCsafBatch_() / fetchCiscoHumanRssIndex_()
           selectRssCsafCandidates_()【Cisco専用】/ csafDate_() / csafUpdatedAt_()
           lastSeenDate_() / warnIfFeedOverflowed_() / ymd_()
展開       extractRows_() / extractCiscoRowsFromCsaf_() / noVulnRow_()
           extractFortinetRowFallback_() / extractCiscoRowFallback_() / errorRow_()
           ciscoCsafProductNames_() / csafCveList_()
バージョン parseVersion_() / compareVersion_() / matchesSpec_() / judgeVersions_()
           judgeCiscoVersions_() / narrowFixVersion_()
判定       readAssets_() / normProduct_() / assetsForProduct_() / primaryAssetProduct_()
           decideNotification_() / judgeOsApplicability_() / ruleGate_() / finalizeVerdict_()
           needsAdvisoryProcessing_() / ownershipJudgement_() / judgeReasonText_()
           isKevListed_() / fetchKevCatalog_()
AI         enrichWithAI_() / buildEnrichPrompt_() / callGemini_() / callGeminiModel_()
           callClaude_() / countAiRequest_() / backfillAiColumns_() / fillLedgerDisplay_()
出力       getKnownState_() / removeRowsFor_() / writeState_() / sortState_()
           snapshotJudgeRows_() / advisoryIdCell_() / advisoryUrlFor_()
           toRowArray_() / writeLedger_() / sortLedger_() / formatLedger_()
           writeRunLog_() / startRunStats_() / addVendorStats_() / notifySlack_()
           slackWebhookUrl_() / operationalSlackTarget_() / postSlack_()
           sendOpsMail_() / notifyMainFailure_() / notifyFetchFailures_()
テスト     testVersion() / testRuleGate() / testJudge() / testCheckSteps() / testRss()
           testCsafUrls() / testCsaf() / testCiscoRss() / testAi() ほか（約540行）
           sampleSlackRows_() / testSlackBlocks() / sendSlackTest_()
```

テスト関数は本体と同居している。**別ファイルへの分離は未着手**（§6-2）。

---

## 6. 次にやること（優先順）

1. **フォールバック行が自社非保有の製品まで台帳に載せる** — ベンダー絞り込みは入れたが
   （§4.7）、CSAF が読めない以上「どの製品か」は分からないままで、
   `primaryAssetProduct_` はそのベンダーの主力製品を機械的に充てている。
   RoomOS や BroadWorks のアドバイザリも `IOS-XE` として「あり（影響調査）」で載る。
   CSAF が取れたときは `ciscoAdvisoryTargetsAssets_` が弾いているのに、取れないと素通りする。

   使える情報がベンダーで違う（2026-09-01 実測）。Cisco の人向け RSS のタイトルには
   製品名が入る（`Cisco RoomOS Stack Overflow Vulnerability`）が、Fortinet の RSS には
   無い（`UI DoS attack` / `Vulnerability in OpenSSL library`）。
   Cisco だけタイトルで絞ると、`ClamAV Vulnerabilities Affecting Cisco Products` のように
   製品名を書かない題名を見逃す。

   正しくは「分からない」を書けるようにすること。ただし `isLedgerRow_` が
   製品なし・非保有の行を落とすので、判定の中核に例外を足すことになる。単独で時間を取る
2. **テスト約540行を別ファイルへ分離** — GAS は複数ファイル可でグローバルスコープを共有する。
   取得層を次に触るときに、§4.5 の非対称の解消と一緒にやる
3. **KEV 連携の基準承認** — 実装済みだが「KEV掲載＋機能使用中のとき対応」の
   基準は未承認（合意事項 1.4-2）
4. **判断記録シート** — 人の判断を残す（上位文書 2.2）
5. **JPCERT/CC 別シート** — RDF パーサを別実装。判定には混ぜない

### 追わないと決めたもの

- **RSS の `Revised on` を判定に使う** — CSAF の改訂と 41/49 でしか一致せず、
  見逃しと空振りの両方を生む。**表示（CSAF が取れない件の最終更新日）にだけ使う**
- **アドバイザリ HTML の取得** — ボット対策により不可能（§1.3）
- **条件付きGET（ETag / Last-Modified）** — ファイルの更新であってアドバイザリの改訂ではない
- **Cisco を Fortinet と同じ全件取得にする** — フィードが 50/50 で一致するので不要。
  直列取得のため30〜50秒かかる
- **clasp（ローカルから GAS へ push）** — 2026-09-01 に見送りと決定。
  デプロイは今後も `.gs` を GAS エディタへ手貼り＋保存で行う。
  技術的には `npx @google/clasp@3` で動くことを確認済みだが、有効化・ログイン・
  スクリプトID の共有というユーザー側の作業が要る。**再提案しないこと。**
  手貼りである以上、実装した内容が GAS に入っているとは限らない。
  作業の区切りで「貼ったか」を確認する側で担保する
- **Slack のカードをアドバイザリ単位にまとめる** — 一見きれいだが、`影響` は
  `fallbackImpactJa_` が CVE のベクターから引き、`推奨対応` の修正版は
  `ciscoFixedVersions_(vuln, …)` が CVE ごとの `product_status` から引き、
  自社影響そのものも `ruleGate_(row)` が CVE のベクターを見て決めている。
  同じアドバイザリでも CVE ごとに割れるので、1 枚にまとめると代表値を選ぶことになり、
  選んだ瞬間に他の CVE については誤りになる。とくに修正版を低い方に丸めると
  「更新したのに直っていない」を生む。**やるなら集約規則の設計から**

---

## 7. ユーザーコンテキスト（対話スタイル）

- GAS経験少。**1ステップずつ**進め、各ステップで実行ログを確認してから次へ
- 説明は結論ファースト。手順の羅列や過度な言い換えは不要
- 専門用語の初出時は補足（特に CSAF）
- **「なぜその値・その設計か」を必ず問われる。**根拠のない断定をすると指摘される。
  適当に置いた値は「根拠はない」と正直に言うこと
- **「パッチワークになっていないか」「ベストプラクティスと言えるか」を繰り返し問われる。**
  当てはまらない場合は正直にそう答え、何が構造的で何が対症療法かを分けて示すこと
- 判定結果の品質に厳しい。「担当者が月次でアクションに移せるか」が受け入れ基準
- 実装前に設計を詰めたがる。選択肢を出し、推奨と理由を添えること
- コミット・push は依頼があるまでしない
