# macOS対応 設計確定書

**作成 2026-09-08。** `引き継ぎ_macOS対応.md`（既存側の視点）と
`macOS_GAS_統合引き継ぎ.md`（モジュール側の指示書）を読んだうえで、
**実装前レビューで16件の是正を入れた確定版**。実装者はこれを最初に読むこと。

**状態: 実装済み・実 GAS 未検証（2026-09-08 04:5x JST）。**

| | |
|---|---|
| 設計 | 確定・承認済み |
| 実装 | 完了。`macos_release_monitor.gs`（1,512行）＋ 既存 3 ファイルへの接続 |
| ローカル検証 | **67 件パス**（実データ 49 件 ＋ 既存回帰 18 件） |
| 実 GAS E2E | **完了（2026-09-10 06:23）。**下記 §4.6 参照 |
| コミット / push | していない |

承認内容は「この設計確定書のとおり実装する」。段階分け（既存側に触らない案）は採らない。
既存 `fortinet_psirt_watcher_v7.gs` への変更は §3 に挙げた3か所のみ。判定ロジックには触らない。
コミット・push は別途依頼があるまでしない。

---

## 0. 結論

**v3.2 の ZIP を移植するのではなく、判定ロジックだけを引き継いで書き直す。**

理由は §2。v3.2 の Phase 1（情報源の統合とリリース識別）は、
**2026-09-08 時点の Apple 公式データに対して機能しない**ことを実測で確認した。
Phase 2/3 の判定ロジックそのものは正しいので、そこは残す。

| | 扱い |
|---|---|
| 配布判断の順序（5分類・Decision_Reason_Code） | **そのまま残す** |
| Apple Security 詳細の解析・実悪用記載の検知 | **そのまま残す** |
| CISA KEV 照合（`matchKev_` / `parseCveList_`） | **そのまま残す** |
| AI出力の検証（URL・CVE・判断語の拒否、source_id検証） | **そのまま残す** |
| メジャーOS判定（`isMajorUpgradeRelease_`） | **そのまま残す** |
| 情報源マージ・リリース識別・初回バックフィル | **書き直す**（§2.1〜2.3） |
| 台帳 I/O | **書き直す**（§2.4〜2.6） |
| Slack 送信 | **書き直す**（§2.7〜2.8） |
| Gemini 呼び出し | **既存に相乗り＋responseSchema追加**（§2.9） |
| KEV 取得 | **既存と共通化**（§2.10） |

---

## 1. 利用者と合意済みの4点（2026-09-08）

1. **AI基盤**: 既存の Gemini 経路（`callGemini_`）に相乗り。Vertex AI は使わない
   - 理由: `cloud-platform` / `script.scriptapp` の2スコープ新規追加＝**既存GASの再認可**が発生する。
     プレ運用中の本番スクリプトを承認画面に戻すのは避ける
2. **Slack**: macOS は既存の日次1通とは別に、独立した2通目として送る
   - 理由: 既存カードと混ぜると「NW判定を通った行」と誤読される。README §4.8 で JPCERT を別枠にしたのと同じ理由
3. **通知量**: 確定リリースは1リリース1通にまとめる（速報と配布判断を統合）
   - v3.2 のままだと1リリース2〜3通。Apple が 26/15/14 系を同日に出すと6〜9通になる
   - **RSS単独候補の不一致警告だけは独立した経路として残す**（理由は §2.11）
4. **トリガー**: macOS 専用の2本目トリガーを作る。既存 `main()` には手を入れない
   - 理由: 6分制限を共有しない。貼り替え時の回帰リスクが既存側に及ばない

---

## 2. レビューで潰した是正16件

### 2.1 【最重要】GDMF の `PostingDate` はリリース日ではない

**実測（2026-09-08 取得）**。GDMF `PublicAssetSets.macOS` は6件で、
**全件が `PostingDate: 2026-08-24`**。その中には 2024年7月公開の macOS 12.7.6 も含まれる。
フィード側の更新時刻を各エントリにコピーしているだけ。

`macOS_GAS_統合引き継ぎ.md` §5.1.A はこれを公開日として扱い、
§5.3 は Release ID `macOS|Version|Build|PostingDate` の一部にしている。**どちらも誤り。**

| Version | GDMF PostingDate | Security Index の実際の公開日 |
|---|---|---|
| 26.6.2 | 2026-08-24 | 2026-08-17 |
| 14.8.9 | 2026-08-24 | 2026-08-06 |
| 15.7.9 | 2026-08-24 | 2026-08-06 |
| 13.7.8 | 2026-08-24 | 2025-08-20 |
| 12.7.6 | 2026-08-24 | 2024-07-29 |
| 11.7.11 | 2026-08-24 | 該当なし |

**是正**: リリース識別子は `macOS|Version|Build`。**PostingDate を鍵から外す。**
Build は Apple が再利用しないので単独で一意。公開日は属性として持ち、Security Index の値を正とする。

外さないと、GDMF がフィードを更新するたびに Release ID が変わり、
`upsertRelease_` が既存行を見つけられず**同じリリースの速報が繰り返し再送**される。

### 2.2 Security Index の結合を Version 単位にする

`mergeReleaseSources_` は Security Index を `version|postingDate` の**完全一致**でしか結合しない。
§2.1 の日付ずれにより、実データで**GDMF由来6行すべてが Security URL を得られない**。

結果 `Security_Status = PENDING_INDEX` → `Distribution_Decision = PENDING` が固定化し、
**このモジュールの目的（今すぐ当てるか次回定例かを一目で決める）が100%達成されない。**

さらに同一バージョンが2行に割れる（`25G83/2026-08-24` と `UNKNOWN/2026-08-17` など5バージョン）。
CVE 解析は片方の行にしか付かない。

**是正**: 日付一致をやめ、**Version で結合**する。Apple は1バージョンにつき1つのセキュリティページしか出さない。

### 2.3 初回バックフィル87行を追跡対象にしない

`parseSecurityReleaseIndexMacOS_` に**日付の下限フィルタが無い**。
実測で `support.apple.com/en-us/100100` から **81行・最古 2024-01-22** を拾う。
GDMF 6件と合わせて**初回に台帳へ87行**入る。

`ledgerRow_` は確定行の `Followup_Slack` を `'PENDING'` で初期化し、
`Phase2.gs` は `Followup_Slack === 'PENDING'` を初回送信条件にしている。
→ 初回実行の**翌日に87通**。6分制限で途中死し、`PENDING` が残るので**翌日また最初から**。永久に収束しない。

`macOS_GAS_統合引き継ぎ.md` §5.4 は「初回は現在存在するリリースを登録」と書いているが、**コードはそうなっていない。**

**是正**: 初回実行で台帳に入った行は記録として残すが、**追跡対象から外す**（Slack送信対象にしない）。
監視開始日より後に出現したリリースだけを追う。

### 2.4 台帳の列参照を「見出し文字列」から「列インデックス」へ

`rowObject_(headers, row)` と `headerIndex_(headers)` は
**シート見出し行の文字列そのものをJSのキーにしている**。
`record.Version` は「見出しが literally `Version`」であることに依存する。

参照箇所は プロパティアクセス27種 / `setLedgerField_('文字列')` 24種 / `idx.X` 9種 /
`preserveNames` の文字列配列25個。

当初「見出しを日本語にする」と決めていたが、**それをやると全部壊れる**。
とくに `preserveNames` の `idx[name]` が全て `undefined` になり、
**Phase 2/3 が積み上げた CVE_List / KEV_List / Distribution_Decision / AI要約が毎日の upsert で全消去される**（無音で）。

**是正**: `MACOS_LEDGER_COLS = [{key:'Version', label:'バージョン'}, ...]` を定義し、
**列インデックスでキーする**方式に書き換える。これにより日本語見出しを安全に使える。
チームは git を見られずシートを読むので、見出しの日本語化自体は維持する価値がある。

### 2.5 `ledgerRow_` の位置依存を捨てる

42要素の名前なし配列（`Ledger.gs:82-129`）。旧互換3列を削るときに位置がずれると、
`Initial_Slack` に `''` が入って**毎日速報が出る**、`Deployment_Status` に `''` が入って
`markReleaseApplied` が効かなくなる、などが**すべて無音で**起きる。

**是正**: §2.4 の列マップと同時に、キー名付きオブジェクト→ヘッダ順展開に書き換える。

### 2.6 スプレッドシートの型強制に備える

`appendRow` / `setValues` は文字列を数値・真偽値へ変換する。

- `'TRUE'` / `'FALSE'` → **真偽値**になる。`Phase2.gs` と `SecurityAnalysis.gs` の
  `record.Managed_OS === 'FALSE'` が `false === 'FALSE'` で成立せず、
  **管理対象外と明示した OS も毎日 Apple 詳細取得と KEV 照合を走らせる**
  （`RiskJudge` は `String().toUpperCase()` なので判定結果は偶然正しいまま）
- `'15.10'` のような版は `15.1` に潰れ、読み戻すと不一致 → 毎日重複行 → 毎日速報

**是正**: Version / Posting_Date / Detected_At 列は `setNumberFormat('@')` で文字列固定。
真偽値比較は `String(x).toUpperCase() === 'FALSE'` に統一。

### 2.7 Slack 送信は自前で throw するラッパを噛ませる

既存 `postSlack_(url, payload)` は**例外を投げない**。非200でも `Logger.log` して `return code` するだけ
（`fortinet_psirt_watcher_v7.gs:4367-4379`）。
一方 macOS 側の3か所は「throw されたら FAILED」前提で書かれている（`Slack.gs:12-20, 38-46, 112-120`）。

そのまま再利用すると、Webhook失効(404)やBlock Kit不正(400)でも
`setLedgerField_(row, 'Initial_Slack', 'SUCCESS')` が実行される。
**送れなかった通知が「送れた」として残り、再送条件に永久に該当しない。**
README §4.15「静かに失敗させない」の真逆で、
しかも `macOS_GAS_統合引き継ぎ.md` §22.5 が直せと言っている既知バグを別経路で作り直すことになる。

**是正**: 戻り値のコードを見て自前で throw する薄いラッパを噛ませる。
`postSlack_` 本体は NW の判定経路と直結しているので触らない。
プロパティ名 `SLACK_WEBHOOK_URL`（定数 `SLACK_WEBHOOK_PROP`）は**改名しない**（README §4.6）。

### 2.8 Block Kit の3,000字上限に備える

`Slack.gs:87` は `cves.join(', ')` を無制限に1行へ出す。
macOS のセキュリティ更新は公開CVEが数十件規模になる（1件約18文字 → 80件で約1,400字）。
そこに AI要約・実悪用文言・注意書きが同じ section に入る。

上限超過で 400 → §2.7 未対応なら SUCCESS として記録され再送されない。
**最も重要な配布判断通知が、CVEが多い＝最も重要なリリースで優先的に落ちる。**

**是正**: CVE の表示件数を切って「他N件」。section を分割する。

### 2.9 `callGeminiModel_` に `responseSchema` の任意引数を足す

- macOS 側は `responseMimeType` **と** `responseSchema` の両方を渡してJSON形を保証している
- 既存 `callGeminiModel_` は `responseMimeType` だけ（`:3600`）
- macOS の `buildAiPrompt_` は `summary` / `notable_changes` / `source_ids` には言及するが、
  **`text` と入れ子構造を書いていない**（スキーマ任せの設計）

そのまま差し替えると `validateAiSummaryOutput_` が必ず `AI_OUTPUT_INVALID: summary` で落ちる。
さらに `existingOk` が `AI_Status === 'SUCCESS'` を要求するので**キャッシュが効かず毎日リトライして毎日枠を食う**。
`callGemini_` は PerDay で複数モデルを順に試すため、枠が尽きた日は1リリースで最大5リクエスト消費する。

**是正**: `callGeminiModel_` に `responseSchema` の任意引数を追加（省略時の挙動は変えないので既存呼び出しは安全）。

### 2.10 KEV は共通化する。ただしキャッシュキーを必ず変える

**衝突している。** `fetchKevCatalog_` は両方に存在し、戻り値の形が違う。

- NW版: `{ "CVE-2026-1234": "Fortinet" }`。`isKevListed_` が `set[cve]` で読む
- macOS版: `{ byCve, count, source, catalogVersion, warning }`

同一プロジェクトでは関数宣言が後勝ちし、`isKevListed_` が**全件 false**を返す。
`isKevListed_` は例外も握りつぶす（`:2696-2704`）ので**ログにも残らない**。
KEV は社内ルール §5 で承認済みの判定材料なので、これは判定が黙って緩む事故。

なお `LEDGER_HEADERS` は両方 `const` なので衝突すると `SyntaxError` でプロジェクトごと起動不能になる（＝派手に壊れるので気づける）。
NW は `LEDGER_HEADERS.forEach` を**トップレベル文**で実行して `COL` を組んでいる（`:3681-3682`）。

**衝突する識別子は4つ**: `LEDGER_HEADERS` / `postSlack_` / `fetchKevCatalog_` / `uniqueStrings_`
（`uniqueStrings_` は両実装が意味的に同一なので実害なし）。

**是正**:
- macOS 側は全面的に `MACOS_` / `macos` プレフィックスへ
- KEV は共通関数1本に統合し、`{map, ok, source, fetchedAt}` を返す。
  `isKevListed_` / `kevVendor_` / `kevLabel_` の外形は維持する
- **CacheService のキーを `kev_catalog` から変える。**変えないと貼り替え直後の最大6時間、
  旧形のキャッシュが返って全件 false になる。NW 自身のコメントが同じ事故を記録している（`:2708-2711`）
- GitHub ミラーを判定入力に入れるなら**どちらから取ったかを記録する**（README §1.5「判断の根拠を残す」）。
  実測では両者 catalogVersion 2026.09.04 / 1,695件で完全一致
- **`fetchKevCatalog_` は NW の判定入力である。**`引き継ぎ_macOS対応.md` §3 の
  「判定ロジックは実データでシミュレーションして差分を見せ、承認を得てから触る」に該当する。
  貼る前に既存台帳の KEV 列で差分ゼロを確認すること

### 2.11 RSS単独候補の警告は独立経路として残す

`CANDIDATE_RSS_ONLY` 行は定義上 `isConfirmed_` を通らないので、
`getConfirmedLedgerRows_()` でフィルタされる Phase 2 に**一切到達しない**。

「1リリース1通に畳む」を素直に実装すると、CANDIDATE 行には配布判断が無いので**何も通知されない**。
Apple 側の公開情報が食い違っている状態が、誰にも届かないまま消える。

**是正**: 「1リリース1通」は**確定リリースについてのみ**。CANDIDATE 警告は独立経路で残す（頻度が低いので通知量の懸念なし）。

### 2.12 Gemini 無料枠の消費を両モジュールで数える

- 無料枠は1日20回程度・**モデル別**（`:52,56`）。NW は `AI_CHUNK_SIZE = 10` で
  「回数課金なので通知対象はできるだけ1回にまとめる」と明記して設計されている
- 消費カウンタ `aiRequestCount_` は**モジュールスコープの `let`**（`:74`）。
  **別トリガー＝別実行なので、macOS の消費は実行履歴の `AI呼び出し` 列に一切載らない**

実行履歴の `AI呼び出し` 列は README §2.3 で無料枠の消費を追うために置かれている。
macOS 分が数えられなくなると**実際より少ない数字を出す**（壊れているのに壊れて見えない）。
枠を先に食った側が勝つので、**プレ運用で観測対象になっている NW 台帳の AI 3列が落ちる日が出る。**

**是正**: 日付キーの Script Property で当日消費数を両モジュール共有にする。
上限到達時は macOS 側が AI をスキップし「AI要約なし」で送る（`Slack.gs:64` に既に分岐がある）。

### 2.13 `LockService` は残す

**LockService は OAuth スコープを一切必要としない。**
Vertex を避けた理由（スコープ追加による再認可）は Lock には当てはまらない。
`macOS_GAS_統合引き継ぎ.md` §18.2 は「Lock を外せ」と言っているが、
その根拠（親処理との二重取得）は**既存NWに Lock が1か所も無い**ので成立しない。

`upsertRelease_` は「全件読む→無ければ appendRow」の read-modify-write なので、
2実行が重なると同一リリースが2行入る。**コストゼロなので残す。**

### 2.14 トリガー消滅に気づける経路を作る

NW が「トリガーが消えた日」を検知できるのは、実行履歴に**行が無い**ことで分かるから（README §2.3）。
macOS の Slack は Apple がリリースしない限り**数週間鳴らないのが正常**なので、
専用シートを作っても誰かが毎日開かない限りトリガー消滅は数週間気づかれない。**NW より条件が悪い。**

**是正**: macOS 側は最終実行日時を Script Property に書き、
NW の `writeRunLog_` の `備考` に「macOS最終実行から N 日」を出す。**見る場所を1か所に保つ。**
`fortinet_psirt_watcher_v7_readme.gs` の「同じ関数のトリガーを二重に作らないこと」に macOS 用トリガーを追記する。

### 2.15 管理OS未設定の空振りを検出する

`seedManagedOsConfig_` は Managed 列を**意図的に空で**播く。
空 → `UNKNOWN` → 全件 `PENDING` / `MANAGED_UNKNOWN`。
これを本番前に強制的に埋めさせていた唯一の門番が `validateProductionReadiness_`（`Setup.gs:186-205`）。

`System_Status` / `Test_Results` シートを作らない設計にすると、この門番ごと落ちる。
誰もシートを埋めないまま運用開始 → macOS の配布判断が**未来永劫すべて ⚪判断保留**。
Slack は毎回届くので「動いている」ように見える。

**是正**: readiness チェックは残す（シートは不要、戻り値とログで足りる）。
最低限「管理OSが1つもTRUEでない」を検出して macOS 実行履歴の `結果` を `要確認` にし、備考に理由を書く。

### 2.16 `markReleaseApplied(releaseId)` は消してよい

引数必須だが、**GAS エディタの実行ドロップダウンは引数を渡せない**。
デプロイは手貼り運用（clasp は 2026-09-01 に見送り決定済み・再提案禁止）なので、
担当者はコードを書き換えないと APPLIED にできない。

誰も APPLIED にしない → `isDeploymentOpen_` が常に true →
一度 EMERGENCY になったリリースが `EMERGENCY_STICKY` で永久に残り、毎日 Apple 取得と KEV 照合を続ける。

**是正**: `Deployment_Status` は `preserveNames` に入っているので、
**担当者がセルに直接 `APPLIED` と手入力すれば動く。**
これを GAS 側の `readme.gs` に書けば済む（NW の「人はシートに書く」＝判断記録シートと同じやり方）。
`markReleaseApplied` / `reopenRelease` は消す。

---

## 3. 確定した構成

### ファイル

`macos_release_monitor.gs` を1枚追加。v3.2 の16ファイルは1枚に畳む。
分割の理由が「貼り替え回数を減らすこと」（README §5）なので、macOS 側も1枚。

既存 `fortinet_psirt_watcher_v7.gs` への変更は**最小限の3か所だけ**:
1. `fetchKevCatalog_` の共通化（キャッシュキー変更・戻り値拡張・外形維持）
2. `callGeminiModel_` に `responseSchema` の任意引数追加
3. `writeRunLog_` の `備考` に macOS 最終実行からの日数を出す

**判定ロジック（`decideNotification_` / `ruleGate_` / `impactSeverity_` / `matchesSpec_` /
`normProduct_` / `isUnauthRemote_` / `narrowFixVersion_` / `finalizeVerdict_` / `featureExposure_`）には触らない。**

### シート3枚

| シート | 中身 |
|---|---|
| `macOS台帳` | リリース1行。見出しは日本語（§2.4 の列マップ方式で安全に）。約30列 |
| `macOS管理OS` | メジャー系統の TRUE/FALSE。未設定は UNKNOWN。**サンプル値を自動でTRUEにしない** |
| `macOS実行履歴` | 1実行1行。**行が無い＝未実行**（README §2.3 と同じ思想） |

`System_Status`（key-value・最終実行しか残らない）と `Test_Results` は作らない。
`INITIALIZED` は Script Property `MACOS_INITIALIZED` へ。

**列の整理**: `Risk` / `Previous_Risk` / `Review_Until` は削除（旧互換・`macOS_GAS_統合引き継ぎ.md` §23.3）。
書きっぱなしで一度も読まれない列（`AI_Input_Fingerprint` / `KEV_CVE_Fingerprint` /
`AI_Prompt_Version` / `AI_Model` / `AI_Source_IDs` など）は**JSON 1列に集約**する。
README §1.5「入力が揃っていない判定は列にしない」・§4.1「空欄に意味を持たせない」に沿わせるため。

### 定数

確認用ファイルから参照するものは **`var`** で宣言する（README §5 の実測罠）。
`testSharedConstants()` の一覧にも足すこと。

---

## 4. 残っている懸念・未確認

- **プレ運用中である**（2026-09-06 開始、3日目）。README §6-1 は「しばらくコードを足さないこと」。
  macOS は別シート・別トリガーなので判定と台帳の観測は汚れないが、
  **Slack の通知量の観測は条件が変わる**。利用者は承知のうえで進める判断
  - 貼る日を記録し、**貼る直前の台帳・実行履歴のスナップショットを取る**こと。無いと前後比較ができない
  - 段階分けの選択肢: KEV共通化(§2.10)と AI相乗り(§2.12)だけ観測期間終了まで見送り、
    macOS 側で KEV を独立取得・AI無効で先に動かす。UrlFetch は2万回/日なので2回取っても問題ない
- **統合先スプレッドシートのタイムゾーンが未確認。** リポジトリに `appsscript.json` が無く確認できない。
  Asia/Tokyo でない場合、`cellDate_` の Asia/Tokyo 整形と日付が1日ずれる可能性がある。**貼る前に確認すること**
- **実GAS E2Eテストは未実施。** `macOS_GAS_統合引き継ぎ.md` §26 が明記している。PASS 済みとして扱わない
- Gemini 無料枠のデータ利用（README §6-2）は NW 側で未解決のまま。macOS を相乗りさせると対象が増える

---

## 4.5 実装の記録（2026-09-08）

### 作ったもの

| ファイル | 変更 |
|---|---|
| `macos_release_monitor.gs` | **新規 1,504 行 / 71 関数。**モジュール本体 |
| `fortinet_psirt_watcher_v7.gs` | 4,614 → 4,721 行。**接続点 4 か所のみ**（下記） |
| `fortinet_psirt_watcher_v7_readme.gs` | 218 → 303 行。macOS の運用手順（§6 を追加） |

判定ロジック 9 関数（`decideNotification_` / `ruleGate_` / `impactSeverity_` / `matchesSpec_` /
`normProduct_` / `isUnauthRemote_` / `narrowFixVersion_` / `finalizeVerdict_` / `featureExposure_`）は触っていない。

### v7.gs の接続点（設計時は 3 か所としていたが 4 か所になった）

1. `kevCatalogWithStatus_()` を新設。`fetchKevCatalog_()` はその薄いラッパにして**外形を維持**
   （素のマップを返し、取れなければ投げる）。キャッシュキーは `kev_catalog_v2`。GitHub ミラーへの退避を追加
2. `callGemini_(prompt, responseSchema)` / `callGeminiModel_(model, prompt, responseSchema)`。
   **省略時の挙動は不変**なので既存呼び出し（`enrichWithAI_`）は変わらない
3. `countAiRequest_()` が日付キーのプロパティにも積む（`sharedAiCountToday_()` で読む）。
   **設計時に想定していなかった 4 か所目。**§2.12 の「両モジュールで消費を数える」には
   NW 側の計数点に触る必要があった
4. `writeRunLog_` の備考に「KEV照合不可 / KEV出典」と「macOS監視：最終実行から N 日」を追加

### 設計から変えた点

- **トリガーをコードから作らない。**`ScriptApp.newTrigger` には `script.scriptapp` スコープが要り、
  既存 GAS の再認可が発生する。Vertex を避けたのと同じ理由で、NW と同様に画面から手で張る。
  **結果として、新規に必要な OAuth スコープはゼロ**（既存の spreadsheets ＋ external_request のみ）
- **実行時刻を 8 時台ではなく 10 時台にした。**Gemini の無料枠は先に走ったほうが取る。
  プレ運用で観測しているのは NW 台帳の AI 3 列なので、NW（9 時台）に先を譲る
- **列は 29 列**（設計では約 30 列）。書きっぱなしの内部項目は `内部データ` の JSON 1 列に集約
- **Apple の修正項目（Fact）を台帳に持たない。**毎日取り直すので持つ必要がなく、
  数十件あるとセルの 5 万字上限に当たる。AI の再実行防止は指紋だけで足りる
- `markReleaseApplied` / `reopenRelease` は作らない。**人が「追跡状態」列に `適用済` と手入力する**（§2.16）

### 実測で確認したこと

- Security Index 81 行 ＋ GDMF 6 件 → **マージ後 82 行**（v3.2 は 87 行で 5 版が重複していた）
- macOS 26.6.2 に Security URL が付き、公開日は Security Index 側の 2026-08-17、ビルドは GDMF 側の 25G83
- 初回取込 82 行の通知対象は **0 件**（v3.2 は翌日 87 通）
- GDMF の PostingDate を動かしても新規行は **0 件**（v3.2 は毎回新規になり速報が再送された）
- Apple 詳細ページ（26.6.2）から **CVE 28 件・修正項目 20 件**を抽出。別バージョンのページは拒否
- 既存 NW の KEV 経路 18 件が回帰なし。CISA 障害時は GitHub ミラーへ退避し、
  全経路失敗なら従来どおり `isKevListed_` が false を返す（挙動不変）

### 実 GAS で判明したこと：GDMF は使えない。**2 情報源構成に変更**（2026-09-08）

**症状**: Apps Script から `https://gdmf.apple.com/v2/pmv` が `SSL Error`。恒久的で、再試行しても直らない。

**原因**（実測）:

```
gdmf.apple.com     → Apple Server Authentication CA → Apple Root CA（Apple 独自のプライベート root）
support.apple.com  → Apple Public EV Server RSA CA 1 - G1（公的 CA）
developer.apple.com→ Apple Public EV Server ECC CA 1 - G1（公的 CA）
```

GDMF だけ Apple 独自ルートで公的 CA に繋がっていない。macOS のキーチェーンは Apple Root CA を
信頼しているのでローカルの curl は通るが、Google の信頼ストアには無いため Apps Script からは必ず失敗する。
openssl でも `verify error:num=19 self signed certificate in certificate chain`。
TLS は 1.2 のみ・クライアント証明書要求なしなので、詰まっているのはルート CA の一点。

**試して駄目だったこと**: `UrlFetchApp` の `validateHttpsCertificates: false`。
公式ドキュメントには「無効な証明書を無視する」とあるが、**未信頼ルートは救われなかった**（実機で確認）。
**再挑戦しないこと。**

**対処**: **GDMF を情報源から外し、Developer RSS ＋ Apple Security Index の 2 情報源にした**（利用者判断、2026-09-08）。
利用者の要件は「最新の OS を追えれば十分」。

**失うもの**（実測で確認）:

| | Developer RSS | Security Index | 結果 |
|---|---|---|---|
| macOS 26.6.2（最新） | ビルド 25G83 が取れる | 取れる | **完全に検知** |
| macOS 15.7.9 / 14.8.9 | 窓から外れている | 取れる | 検知できるが**ビルドは UNKNOWN** |

Developer RSS は直近しか持たない短い窓（macOS 系 4 件、うち 3 件は beta）。
**失うのは旧メジャー系統のビルド番号表示だけで、検知・配布判断・CVE・KEV はすべて動く。**

**確認状態の意味が変わった**:

| Confirmation_Status | 条件 | 正式版扱い |
|---|---|---|
| `CONFIRMED_SECURITY_RSS` | Security Index ＋ Developer RSS | YES |
| `CONFIRMED_SECURITY_ONLY` | Security Index のみ | YES |
| `CANDIDATE_RSS_ONLY` | Developer RSS のみ | NO（不一致警告を出す） |

`CONFIRMED_GDMF` は消えた。**正式版と認めるには Security Index が要る。**
RSS が先に出て Security Index が遅れた場合は候補どまりになり、配布判断へ進めない（原則 2 のとおり）。

**検討したが採らなかった代替**: SOFA（`sofafeed.macadmins.io`、Mac Admins コミュニティの Apple 更新フィード）。
公的 CA で検証が通り、26.6.2 のビルド・公開日・CVE 28 件・実悪用フラグまで揃っていて、
Apple 公式ページから直接抽出した数と完全一致していた。ビルド番号を全系統で取り戻せるが、
**第三者フィードへの依存とフィード陳腐化に気づけないリスク**が残るため見送った。
旧メジャーのビルド番号がどうしても要るときは再検討の余地がある。

### 貼る前にやること

1. **統合先スプレッドシートのタイムゾーンが Asia/Tokyo か確認**（§4。未確認のまま）
2. **台帳・処理済み・実行履歴のスナップショットを取る**（プレ運用の観測の前後比較用）
3. 貼る順番は `fortinet_psirt_watcher_v7.gs` → `macos_release_monitor.gs` → `readme.gs`。
   **逆にすると `macosSelfTest()` の「v7 の ... が見える」が落ちる**
4. 貼ったら `macosSelfTest()` → `macosSetup()` → 管理OS を設定 → `macosRunReadinessCheck()` →
   トリガーを手で張る

---

## 4.6 実 GAS で潰したバグ（2026-09-08 〜 09-10）

ローカル 50 件のテストでは 1 つも出ず、**実機のシートを見て初めて分かった**ものばかり。
いずれも「実行は成功したように見えるのに結果が壊れる」型。

| # | 症状 | 原因 | 対処 |
|---:|---|---|---|
| 1 | GDMF が SSL Error | Apple 独自ルート CA。`validateHttpsCertificates:false` も効かない | GDMF を外し 2 情報源に（§4.5 の節を参照） |
| 2 | AI が 503 のとき枠を空振りで消費し 6 分制限に接近 | `callGeminiModel_` は再試行ごとに計数する。1 リリース最大 3 回 × リリース数 | **1 件目が失敗したらその実行では以降 AI を呼ばない。**経過 3 分でも打ち切る |
| 3 | 台帳が空のまま、実行は完了 | `macosSaveLedger_` が書く前にシートの行数を確認していなかった。人が「行を削除」で消すとシートの行数自体が減り `getRange` が例外 | 書く前に `insertRowsAfter` で広げる |
| 4 | 81 版なのに 163 行 | 書いた行より**下**に残った古い行を消していなかった。次の読み込みでそれも読み、固定化する | 読み込み時に空行と重複を畳み、書き込み後に下を `clearContent` |
| 5 | 台帳を空にすると 81 通飛ぶ | `MACOS_INITIALIZED` が TRUE のまま台帳が空だと、全件が「追跡中・通知 PENDING」で入り直す | **台帳が空なら初回取込としてやり直す** |

### 追加した運用・診断関数

| 関数 | 用途 |
|---|---|
| `macosDiagnose()` | シートの行数・列数、台帳の有効版数／空行／重複、追跡対象の行、情報源の取得件数。**書き込みはしない** |
| `macosSlackTest()` | Slack へ 1 通テスト送信。台帳に依存しないので Slack 単体を切り分けられる |
| `macosNotifyLatest()` | 台帳の最新正式版で**本番と同じ経路の通知を 1 通**送る。送信後に追跡状態を元に戻す |
| `macosReinitialize()` | 初回取込をやり直す |
| `macosSelfTest()` | ファイル分離・判定順序・AI 検証の 23 項目。ネットにもシートにも触らない |

### E2E 検証の記録（2026-09-10 06:23）

```
対象: macOS 26.6.2（ビルド 25G83 / 公開日 2026-08-17）
Security 状態: FOUND / 公開CVE 28 件
配布判断: 推奨：次回定例アップデートで可（NO_EMERGENCY_EVIDENCE）
HTTP 503 (gemini-3.8-flash) のため 5秒待って再試行します（1回目）
OK: Slack へ送信しました。
```

ビルド `25G83` と公開日 `2026-08-17` が入っていることが、
**Developer RSS と Security Index を版で結合できている証拠**（v3.2 が壊れていた箇所）。
CVE 28 件はローカルで Apple 公式ページから直接抽出した数と一致する。

---

## 4.7 情報源を Apple Security Releases 1 本にした（2026-09-10）

Developer Releases RSS を外した。**理由は要件に対して足していたものが小さく、ノイズが大きかったこと。**

実測（2026-09-10）:

```
Developer RSS: 全 53 件 / 期間 2025-10-06 〜 2026-08-31（約 11 か月）
  macOS 26.6.2  ある
  macOS 15.7.9  ない   ← 2026-08-06 公開のセキュリティ更新
  macOS 14.8.9  ない   ← 同上
```

**11 か月で 53 件しかない疎なフィードで、旧メジャーのセキュリティ更新を載せていない。**
RSS が実質的に足していたのはビルド番号だけで、それも 8 件中 1 件。
利用者に確認したところ、ビルド番号を見て何かをすることは無い。

一方 Apple Security Releases は、macOS の全リリースを網羅し、
**セキュリティ詳細ページの URL を持つ唯一の情報源**。CVE も実悪用記載もそこから取る。
これが無いと 🔴 / 🟢 の判定そのものが成立しない。

連鎖して消えたもの:

| 消したもの | 理由 |
|---|---|
| `ビルド` 列 | Security Index からは取れないので、常に「未取得」になる列だった |
| `確認状態` 列 | 情報源が 1 本なら全行が同じ値 |
| `検知ソース` 列 | 同上 |
| `不一致警告` 列と候補通知 | RSS にだけ出た状態が存在しなくなった |
| ビルド差し替えの再通知 | ビルドが取れないので判定できない |

**25 列 → 21 列、1,952 行 → 1,772 行。**

引き継ぎ資料 §29 の原則 5「1 情報源に依存しない」には反する。
ただしその原則は GDMF がある前提で書かれたもので、GDMF が使えない時点で
実質的な冗長性はすでに失われていた。**冗長性があるように見える状態を維持するより、
1 本だと明示するほうが誠実**という判断。取得に失敗した日は実行履歴に失敗として残り、
配布判断は保留に倒れる。

---

## 5. 受入テスト

`macOS_GAS_統合引き継ぎ.md` §25 の25項目に加えて、**本レビューで見つけた分**を必ず通すこと。

| No | ケース | 期待結果 |
|---:|---|---|
| 26 | GDMF の PostingDate が変わる | 同じリリースとして扱い、速報を再送しない（§2.1） |
| 27 | GDMF と Security Index で日付が違う | Version で結合し、1行になる（§2.2） |
| 28 | 初回実行 | 87行が台帳に入るが、翌日に通知が飛ばない（§2.3） |
| 29 | 台帳の見出しが日本語 | 全列が正しく読み書きできる（§2.4） |
| 30 | Managed に TRUE/FALSE を入れる | 真偽値化されても比較が成立する（§2.6） |
| 31 | Slack が 400 / 404 を返す | FAILED として記録され、翌日再送される（§2.7） |
| 32 | CVE が80件のリリース | 3,000字を超えず送信できる（§2.8） |
| 33 | 貼り替え直後6時間以内 | KEV が全件「なし」にならない（§2.10） |
| 34 | CANDIDATE_RSS_ONLY 行 | 不一致警告が届く（§2.11） |
| 35 | 既存台帳の KEV 列 | 共通化の前後で差分ゼロ（§2.10） |

---

## 6. 守るべき原則（`macOS_GAS_統合引き継ぎ.md` §29 より）

1. AI に配布タイミングを決めさせない
2. 情報取得に失敗したら緑にしない（分からない → PENDING）
3. EMERGENCY は人が APPLIED にするまで自動解除しない
4. NEXT_CYCLE は「安全」ではない（現時点で緊急根拠がないという意味）
5. macOS 正式版検知は1情報源に依存しない
6. 既存 NW GAS へ統合する際は、トリガー・Lock・設定・名前空間を二重化しない

既存 README §1.5 の設計原則もそのまま適用される。とくに
**「安全側に倒す」「静かに失敗させない」「判断ではなく判断の根拠を残す」**は、
本レビューで潰した16件のほとんどがこの3つに紐づいている。
