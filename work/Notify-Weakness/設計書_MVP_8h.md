# 設計書 MVP（8h）：NW機器 脆弱性ウォッチャー

**更新日**: 2026-08-23（自社影響3値の刷新・社内ルール反映）  
**上位文書**: [脆弱性影響判定通知ツール_設計書v3.md](脆弱性影響判定通知ツール_設計書v3.md)  
**判定ルール**: [社内ルール案_OS更新基準.md](社内ルール案_OS更新基準.md)  
**現行実装**: [fortinet_psirt_watcher_v7.gs](fortinet_psirt_watcher_v7.gs)（v6 + Cisco RSS）

この文書は **発表まで約8時間** で「最低限動く」状態を作るための設計。  
詳細設計（機能台帳・KEV・月次サマリ等）は v3 §6.3 のまま**後回し**。

## 移行手順（v6 → v7）

1. GAS に `fortinet_psirt_watcher_v7.gs` の内容を貼り替え
2. `migrateLedgerHeaders()` を実行（台帳 **13 列** / 処理済み **7 列**）
3. `migrateAssetHeaders()` を実行（資産 8 列 + 社内機器9行）
4. `clearRunData()` を実行（確認ダイアログで台帳・処理済みの 2 行目以降を削除）
   - 自社影響の語彙が変わるため、旧データは残さない
5. `testVersion()` → `testRuleGate()` → `testFeatureExposure()` → `testJudge()` → `testCheckSteps()` → `main()`
   - Cisco openVuln の資格情報は不要（GAS では使えない。§6）

---

## 1. ゴール（8h）

| やる | やらない |
|---|---|
| 社内 NW 機器の脆弱性を**取りこぼさない** | クライアント（FortiClient EMS 等） |
| Fortinet は **版比較まで自動判定** | Cisco の版比較（次フェーズ） |
| Cisco は **RSS 取得 → 台帳に要確認** | Netgear / Soliton（別フィード） |
| 資産台帳に**全機種を記録**（ツール対象外も含む） | 機能使用有無の自動判定 |
| 発表で Forti 判定デモ + Cisco 拡張の骨格を見せる | 発表資料の肉付け（別ファイル） |

---

## 2. 社内資産（確定）

| 種別 | ベンダー | 機種 | OS/版 | ツール対象 | 備考 |
|---|---|---|---|---|---|
| UTM | Fortinet | FortiGate 120G | **FortiOS 7.4.11** | **○ コード判定** | 資産シート `FortiOS` |
| Switch | Cisco | C9200-24PXG-E | **IOS-XE 17.15.5** | △ RSS→要確認 | Catalyst 9200 |
| Switch | Cisco | C9200L-24PXG-4X | **IOS-XE 17.15.5** | △ RSS→要確認 | 同上系列 |
| Switch | Netgear | MS510TXM | （未把握） | × 対象外 | 別ベンダー・別フィード |
| Switch | Netgear | GS108Tv3 | （未把握） | × 対象外 | 同上 |
| WLC | Cisco | Catalyst 9800-L | **IOS-XE 17.15.5**（想定） | △ RSS→要確認 | 版は実機確認推奨 |
| AP | Cisco | CW9166I-Q | （WLC 管理下） | △ RSS→要確認 | AP 単体版は WLC 経由のことが多い |
| RADIUS | Soliton | NetAttest EPS-edge SX06 | — | × 対象外 | 日本製・別情報源 |

**除外（ユーザー合意）**

- FortiClient EMS … クライアント。v3 §3.1 と同じ
- Netgear / Soliton … 8h では取得経路が別のためスコープ外。資産シートには**行だけ残す**

---

## 3. 資産シート設計（v7）

v6 の `資産` シートに列を追加する。

| 列 | 例 | 用途 |
|---|---|---|
| ベンダー | `Fortinet` / `Cisco` / `Netgear` / `Soliton` | フィルタ・表示 |
| 種別 | `UTM` / `Switch` / `WLC` / `AP` / `RADIUS` | 人間向け |
| 製品 | `FortiOS` / `IOS-XE` / `—` | **突合キー**（ベンダー公式表記） |
| 機種 | `FortiGate 120G` / `C9200-24PXG-E` | 備考・ログ用 |
| バージョン | `7.4.11` / `17.15.5` | Fortinet 判定に使用 |
| 台数 | `2` | 任意 |
| ツール対象 | `はい` / `いいえ` | `いいえ` は台帳に出さない |
| 備考 | `SSL-VPN 有効` / `WLC 管理下` | 任意 |

**初期データ例**

```
ベンダー   種別    製品     機種              バージョン  台数  ツール対象  備考
Fortinet   UTM     FortiOS  FortiGate 120G    7.4.11      1     はい
Cisco      Switch  IOS-XE   C9200-24PXG-E     17.15.5     1     はい
Cisco      Switch  IOS-XE   C9200L-24PXG-4X   17.15.5     1     はい
Cisco      WLC     IOS-XE   Catalyst 9800-L   17.15.5     1     はい        版要確認
Cisco      AP      —        CW9166I-Q         —           —     はい        WLC管理下・版はWLC経由
Netgear    Switch  —        MS510TXM          —           1     いいえ
Netgear    Switch  —        GS108Tv3          —           1     いいえ
Soliton    RADIUS  —        NetAttest SX06    —           1     いいえ
```

---

## 4. 処理フロー（v7・判定刷新後）

ベンダーで判定を分けない。差は「影響機能の語彙」だけに閉じ込める。

```
日次トリガー main()
  │
  ├─ decideNotification_()  ← AI を呼ばずに結論が出る分をここで確定
  │     製品不明     → あり（影響調査）＋ AI表示列
  │     非保有       → なし（台帳に載せない）
  │     版が範囲外   → なし（台帳に載せない）
  │     版が不明     → あり（影響調査）＋ AI表示列
  │     ruleGate_()  → 落ちたら なし。★AI を呼ばない（KEV掲載なら影響調査）
  │     ゲート通過   → 判定は保留（needsVerdict）
  │
  ├─ fillLedgerDisplay_()
  │     needsVerdict/needsDisplayAi → enrichWithAI_() で埋める
  │     needsCodeDisplay            → コードのフォールバックだけで埋める
  │
  └─ finalizeVerdict_()     ← 社内ルールを適用して3値を確定
        KEV掲載            → 条件を満たせば対応検討、それ以外は影響調査
        featureExposure_() → disabled=なし / config=影響調査 / unknown=影響調査
        always かつ 掌握or業務停止 → あり（対応検討）
        always かつ 軽微           → なし
```

**ゲートを AI の前に置く理由**: `PR:H` の行の影響機能を分類しても結論は変わらない。
到達性と前提条件はベクターだけで決まるので、AI を呼ぶ前に落として API を使わない。
落とした行の表示列は空にせず、コードのフォールバックで埋める
（空欄だと「AI が失敗した行」と区別できなくなる）。

`finalizeVerdict_()` も同じ `ruleGate_()` を呼ぶ。判定の入口が2つあると片方だけ直して
食い違うため、この関数単体で社内ルール全体を表現しておく。

**main() 失敗時**: `notifyMainFailure_()` が実行アカウントへメールする
（日次トリガーはログを見ないと気づかないため）。

**自社影響（3値）** — 定義と根拠は [社内ルール案_OS更新基準.md](社内ルール案_OS更新基準.md)

| 値 | 意味 | 次の行動 |
|---|---|---|
| あり（対応検討） | 臨時更新の条件を満たした | 対応時期を検討する |
| あり（影響調査） | 設定次第で影響が変わる | 確認方法を実行して振り分ける |
| なし | 定期更新まで待てる根拠がある | 記録のみ |

判定に**深刻度スコアは使わない**。使うのは到達性（`AV`）・前提権限（`PR`）・
利用者操作（`UI`）と、影響機能が設定依存かどうかの4点。

**CISA KEV**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

日次キャッシュ（`fetchKevCatalog_()` / `isKevListed_()`）。台帳表記は **あり / なし**。
KEV は判定の主軸ではなく、**最低ラインを「影響調査」に固定する例外**として使う。

**Slack**: 「あり」2値のみ。「なし」は件数だけフッターに出し、台帳には残す。

---

## 4b. 処理フロー（旧・参考）

```
日次トリガー
  │
  ├─ [Fortinet] 既存 v6 経路（変更最小）
  │     RSS → CSAF → 版比較(7.4.11) → あり/なし/要確認 → 台帳・Slack
  │
  └─ [Cisco] 資産シート基準（決め打ち）
        RSS (最大50件)
          → 処理済みと突合し、新規・改訂候補だけ CSAF 取得
          → 資産シートの製品・版と CSAF を突合
               条件1: product_tree に IOS-XE 等が含まれる
               条件2: known_affected の版が資産版と完全一致
          → 一致したアドバイザリのみ CVE 行を生成
          → 17.15.5 等と版比較 → 要対応 / 対応不要 / 要調査
          → 台帳・Slack
```

**Cisco RSS URL（公開・認証不要）**

```
主経路（CSAF RSS）:
https://sec.cloudapps.cisco.com/security/center/csaf_20.xml

補助（通常 RSS・失敗時のタイトル/概要/人向けURL）:
https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml
```

CSAF RSS の `guid`/`link` に CSAF JSON の URL が直接入る。
ID 抽出 → URL 組み立ては主経路では行わない（組み立て保険は `CISCO_CSAF_BASE` に残す）。

**Cisco 行の台帳フォーマット**

- Fortinet 行と同じ 13 列構造
- 公式推奨対応: CSAF の回避策コマンドがあればそれ。無ければ「更新先はアドバイザリで確認」（人向けページへのリンク）

---

## 5. FortiOS 7.4.11 の扱い（既存 v6）

資産シートに `FortiOS` / `7.4.11` を登録すれば、v6 の `decideNotification_()` がそのまま動く。

- `>=7.4.0|<=7.4.8` 等の範囲 → 版該当。3値の判定へ進む
- 範囲外 → **なし**（判定根拠に系列範囲を1行）
- 解釈不能 → **あり（影響調査）**

発表デモ前に `testJudge()` で 7.4.11 の判定結果をログ確認すること。

---

## 6. Cisco IOS-XE 17.15.5 の扱い

**新着検知は CSAF RSS を主経路にする。** 通常 RSS は補助。

```
CSAF RSS（csaf_20.xml）
  → guid/link の CSAF JSON URL を直接取得
  → known_affected の版番号と資産 17.15.5 を突合
  → AI 列（影響機能・確認方法・ユーザ影響）
  → finalizeVerdict_() で3値確定（Fortinet と同じ経路）
  → 公式推奨対応: Workarounds コマンド or Fixed Software 参照

失敗時:
  通常 RSS（psirtrss20）からタイトル・概要・人向けURLを補完
  → extractCiscoRowFallback_()
```

### 修正版バージョン（openVuln API）— GAS では使わない

CSAF には First Fixed が入らない。openVuln API で取れることは手元の `curl` で確認済みだが、
**GAS の `UrlFetchApp` は `id.cisco.com` で Akamai Access Denied（HTTP 403）になる**ため呼べない。

| 項目 | 内容 |
|---|---|
| 運用 | **しない**（`ciscoFirstFixedMap_` は常に空） |
| 理由 | Key/Secret は有効。GAS の出口 IP / User-Agent が Cisco 側で拒否される |
| 更新先の出し方 | CSAF Workarounds のコマンドがあれば併記。版番号は担当者が Fixed Software / Software Checker で確認 |
| スクリプトプロパティ | `CISCO_API_CLIENT_*` は不要 |
| 将来案 | 中継サーバー（Cloud Run 等）経由なら復活可能。8h スコープ外 |

### 回避策（`ciscoWorkaround_()`）

Workarounds note を役割で分ける。

| 部分 | 扱い |
|---|---|
| コマンド行（`no ip http server` 等） | コードで抽出し、原文のまま台帳へ（訳す必要がない） |
| 説明文 | `row.workaround` に入れ、AI が日本語40字以内に要約（`回避策` フィールド） |
| 免責文（`While this mitigation...` 以降） | 落とす。運用上の注意で、何をするかの情報がない |
| `There are no workarounds` | `workaroundNone` を立て、`回避策なし。修正版へ更新が必要` と出す |

出力例: `更新できない場合の回避策: snmp-server view NO_BAD_SNMP snmpUsmMIB excluded（該当OIDをSNMPビューから除外）`

### 確認方法の情報源

Cisco の `Vulnerable Products` / `Determine` 節には正確な確認コマンドと、
悪用不可になる除外条件（`ip http active-session-modules none` など）まで書かれている。
これを `ciscoConfigHints_()` で AI に渡し、プロンプトで「note のコマンドを優先」と指示する。
手書きの `CHECK_STEPS_CISCO` は**フォールバック専用**（AI 失敗時のみ使用）。

**未対応**

- プラットフォーム別（C9200 / 9800-L）の細分化
- AP（WLC 管理下）の版判定単位

---

## 7. 台帳・Slack の変更点（v6 → v7 → 実用性改善）

### 台帳 13 列（2026-08 確定）

固定6列: `自社影響 | 製品 | CVE | 脆弱性名 | CVSS | 最終更新日`  
判定表示: `公式推奨対応 | KEV | 影響機能 | 判定根拠`  
人の確認: `確認方法 | ユーザ影響`  
参照: `アドバイザリ`

| 項目 | 内容 |
|---|---|
| 自社影響 | **あり（対応検討）/ あり（影響調査）/ なし** |
| 脆弱性名 | CSAF / RSS の文書タイトル（表示は最大60字）。CVE 単位の短い日本語名は出さない |
| 公式推奨対応 | 日本語のみ。Cisco は回避策コマンド、無ければ「更新先はアドバイザリで確認」 |
| KEV | **あり / なし** |
| 判定根拠 | **2行**。1行目 `OS=対象 \| KEV=なし`、2行目 `Webフィルタ の利用有無が設定次第のため「あり（影響調査）」` |
| 確認方法 | 版該否済み前提。設定次第なら設定確認、常時有効なら次アクション。**ラベルは表示時に除去** |
| ユーザ影響 | 悪用時の最悪ケースを50字以内（CVSS の C/I/A と矛盾させない） |
| 非保有・OS対象外 | **台帳に載せない**（処理済みのみ） |
| 「なし」行 | **台帳に残す**（臨時更新しない判断の記録）。Slack には出さない |
| 古い「なし」行 | `KEEP_OUT_OF_SCOPE_MONTHS`（3か月）を過ぎたら台帳から落とす。「あり」2値は年齢で切らない |

**判定根拠を2行にした理由**: 同じ `|` 区切りで値と文章を並べると、
文章もフィールドとして読まれて頭に入らない。構造値と散文を行で分ける。

**確認方法のラベルを表示時に外す理由**: `確認ポイント：`／`コマンド：`／`判断：` は
AI 出力の検証に必要なので生成側では残すが、セルに並べると全行の同じ位置に
同じ4文字が3回ずつ出て、読みたい中身より先に目に入る。3行の位置そのものが
役割を示すので、表示では中身だけ残す（`stripCheckLabels_()`）。

| 項目 | v6 | v7（現行） |
|---|---|---|
| 台帳列数 | 12 | **13**（CVE 右に脆弱性名を追加。OS該当は判定根拠に統合のまま） |
| 処理済み列数 | 8 | **7**（`台帳の行数` を廃止。実行タイミングで値が変わり集計の意味が定まらない） |
| Slack | Fortinet 対象・要確認 | **「あり」2値のみ**（なしは件数のみ） |
| 処理済み | FG-IR 単位 | ベンダー + アドバイザリ ID |
| 判定の分岐 | Fortinet と Cisco で別関数 | `finalizeVerdict_()` に統合 |

---

## 8. 8h 作業の分割案

| 順 | 作業 | 見積 | 成果 |
|---|---|---|---|
| 1 | 資産シート列追加 + 上記8行投入 | 30m | setup 更新 |
| 2 | FortiOS 7.4.11 で testJudge / main 確認 | 30m | デモデータ |
| 3 | Cisco RSS 取得・パース関数 | 2h | fetchCiscoRss_() |
| 4 | Cisco 行を台帳形式に変換（要確認固定） | 1.5h | extractCiscoRows_() |
| 5 | main() 統合・処理済み・既読 | 1.5h | v7 main |
| 6 | Slack 通知のベンダー表示 | 1h | notifySlack_ 更新 |
| 7 | 通しテスト・発表デモ確認 | 1h | — |

**合計 約8h**

---

## 9. 発表での言い方（設計と整合）

- **面倒23個**は現行業務の話（変更なし）
- **ツール**は「FortiGate は判定まで動く。Cisco は取りこぼし防止の第一歩」
- Netgear / Soliton は「資産には載せるが、別ベンダーは別フェーズ」と正直に言う
- 時間削減ではなく **網羅性 + 根拠の保存**（v3 と同じ）

---

## 10. 未決（8h 後）

- WLC 9800-L の IOS-XE 版がスイッチと同一 17.15.5 か（`show version` で確認）
- CW9166I-Q の AP ファーム版（WLC 管理下なら WLC 版で足りるか）
- Netgear の脆弱性情報源
- Soliton のセキュリティ情報の取得方法
- Cisco の更新先版番号はアドバイザリの Fixed Software / Software Checker で人が確認する
  （openVuln は GAS からは呼べないことが確認済み。中継が要る）
