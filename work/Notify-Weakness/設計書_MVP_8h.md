# 設計書 MVP（8h）：NW機器 脆弱性ウォッチャー

**更新日**: 2026-08-23（台帳12列・実用性改善反映）  
**上位文書**: [脆弱性影響判定通知ツール_設計書v3.md](脆弱性影響判定通知ツール_設計書v3.md)  
**現行実装**: [fortinet_psirt_watcher_v7.gs](fortinet_psirt_watcher_v7.gs)（v6 + Cisco RSS）

この文書は **発表まで約8時間** で「最低限動く」状態を作るための設計。  
詳細設計（機能台帳・KEV・月次サマリ等）は v3 §6.3 のまま**後回し**。

## 移行手順（v6 → v7）

1. GAS に `fortinet_psirt_watcher_v7.gs` の内容を貼り替え
2. `migrateLedgerHeaders()` を実行（台帳 **12 列**）
3. `migrateAssetHeaders()` を実行（資産 8 列 + 社内機器9行）
4. `clearRunData()` を実行（確認ダイアログで台帳・処理済みの 2 行目以降を削除）
5. `testVersion()` → `testJudge()` → `testCiscoKevJudge()` → `main()`

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

```
日次トリガー main()
  │
  ├─ [Fortinet]
  │     RSS → CSAF → 第0段階 OS版該当（コード）
  │       対象外 → 処理済みのみ（台帳に載せない）
  │       不明 → 要調査 + AI表示列
  │       該当 → KEV最優先 → AI（機能分類+確認方法+ユーザ影響）→ コード判定表 → 台帳
  │
  └─ [Cisco]
        RSS → CSAF → OS版該当
          対象外 → 処理済みのみ（台帳に載せない）
          不明 → 要調査 + AI表示列（判定は据え置き）
          該当 → KEVあり→対応推奨 / なし→次回定期 + AI表示列
```

**自社影響（3値）**

| 値 | 意味 |
|---|---|
| 対応推奨 | 次回定期更新を待てない例外 |
| 次回定期 | 年1回の定期FWで解消見込み（版該当かつ非KEV等） |
| 要調査 | 版不明・AI分類不能など情報不足 |

**CISA KEV**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

日次キャッシュ（`fetchKevCatalog_()` / `isKevListed_()`）。台帳表記は **あり / なし**。

**Slack**: 対応推奨 + 要調査のみ。次回定期は台帳のみ。

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
https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml
```

**Cisco 行の台帳フォーマット**

- `ベンダー` 列を台帳に追加（または製品列に `Cisco IOS-XE` と明示）
- Fortinet 行と同じ 12 列構造を維持し、Cisco は AI 列を空 or 最小にしてもよい（8h）

---

## 5. FortiOS 7.4.11 の扱い（既存 v6）

資産シートに `FortiOS` / `7.4.11` を登録すれば、v6 の `decideNotification_()` がそのまま動く。

- `>=7.4.0|<=7.4.8` 等の範囲 → **あり** になりうる（要実データ確認）
- 範囲外 → **なし**（根拠列に系列範囲を1行）
- 解釈不能 → **要確認**

発表デモ前に `testJudge()` で 7.4.11 の判定結果をログ確認すること。

---

## 6. Cisco IOS-XE 17.15.5 の扱い

**Cisco CSAF（公開 JSON）で版比較する。** openVuln API キーは不要。

```
RSS → cisco-sa-* を特定 → CSAF JSON 取得
  → known_affected の版番号と資産 17.15.5 を突合
  → 要対応 / 対応不要 / 要調査
  → AI 列（影響機能・確認方法・ユーザ影響）
```

推奨対応は CSAF に具体版が無い場合 `修正版はアドバイザリの Fixed Software を参照` と出す。

**Cisco 判定（AI なし）**: KEV 掲載 → 対応推奨、それ以外 → 次回定期。

**未対応**

- プラットフォーム別（C9200 / 9800-L）の細分化
- AP（WLC 管理下）の版判定単位

---

## 7. 台帳・Slack の変更点（v6 → v7 → 実用性改善）

### 台帳 12 列（2026-08 確定）

固定5列: `自社影響 | 製品 | CVE | CVSS | 最終更新日`  
判定表示: `公式推奨対応 | KEV | 影響機能 | 判定根拠`  
人の確認: `確認方法 | ユーザ影響`  
参照: `アドバイザリ`

| 項目 | 内容 |
|---|---|
| 自社影響 | **対応推奨 / 次回定期 / 要調査** |
| 公式推奨対応 | 日本語のみ（Cisco は修正版抽出 or 定型日本語） |
| KEV | **あり / なし** |
| 判定根拠 | 例: `OS=対象 \| KEV=なし \| 影響機能が外部から到達しないため「次回定期」`（`パス=` なし。OS該当は列に出さない） |
| 確認方法 | 3行: 確認ポイント／コマンド／判断。不合格時は機能別手順テーブルで差し替え |
| ユーザ影響 | 悪用時の最悪ケースを50字以内 |
| OS対象外 | **台帳に載せない**（処理済みのみ） |
| Cisco 判定 | KEV固定。影響機能は短い名称に正規化 |
| Fortinet 判定 | 版該当 → AI機能分類 → 外面×掌握×停止のコード表（内部。列には出さない） |

| 項目 | v6 | v7（現行） |
|---|---|---|
| 列数 | 12 | **12**（OS該当列を廃止し判定根拠に統合） |
| Slack | Fortinet 対象・要確認 | **対応推奨 + 要調査**（次回定期は台帳のみ） |
| 処理済み | FG-IR 単位 | ベンダー + アドバイザリ ID |

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
- Cisco openVuln API トークンの有無
