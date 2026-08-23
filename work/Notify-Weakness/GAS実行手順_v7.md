# GAS 実行手順 v7

**対象ファイル**: [fortinet_psirt_watcher_v7.gs](fortinet_psirt_watcher_v7.gs)

## 事前確認（ローカルで実施済み）

| 項目 | 結果 |
|---|---|
| Fortinet RSS | HTTP 200 |
| Cisco RSS | HTTP 200、全50件取得後に資産シート基準で CSAF 突合 |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |

`testCiscoRss()` では「直近 N か月」と「資産対象アドバイザリ ○ 件」が出れば正常です。

---

## 1. GAS にコードを貼る

1. スプレッドシートを開く → **拡張機能 → Apps Script**
2. 既存コードを **v7 の全文で置き換え**
3. **保存**（Ctrl+S）

## 2. スクリプト プロパティ（未設定なら）

**プロジェクトの設定 → スクリプト プロパティ**

| キー | 用途 |
|---|---|
| `GEMINI_API_KEY` | 影響機能・確認方法・ユーザ影響（Fortinet 判定用の機能分類も含む） |
| `SLACK_WEBHOOK_URL` | Slack 通知（任意） |

## 3. 移行（列構成が変わった場合）

```
① migrateLedgerHeaders()   ← 13列に更新（余分な列を削除）
② migrateAssetHeaders()    ← 初回のみ
③ clearRunData()           ← メニュー「脆弱性ウォッチャー → データ削除」
④ main()
```

`clearRunData()` は **資産シートは触りません**。列がずれた台帳は必ずデータ行を消してから再取得してください。

## 4. テスト（API キー不要のものから）

| 順 | 関数 | 期待するログ |
|---|---|---|
| 1 | `testVersion()` | `17 / 17 件が期待どおり` |
| 2 | `testJudge()` | Fortinet 判定表 `7 / 7 件が期待どおり` |
| 3 | `testCiscoKevJudge()` | `Cisco 固定ルール: OK`（KEV=あり/なし） |
| 4 | `testExternalSurface_()` | 外面判定が期待どおり |
| 5 | `testCiscoRss()` | `Cisco RSS 件数: 50` |

## 5. 本番取得

```
main()
```

### 期待される結果

**台帳（13列・左5列固定）**

`自社影響 | 製品 | CVE | CVSS | 最終更新日 | 公式推奨対応 | OS該当 | KEV | 影響機能 | 判定根拠 | 確認方法 | ユーザ影響 | アドバイザリ`

| 識別 | 自社影響 | 内容 |
|---|---|---|
| FG-IR-* | 対応推奨 / 次回定期 / 要調査 | OS該当 → AI機能分類 → コード判定表。影響機能・確認方法・ユーザ影響が入る |
| cisco-sa-* | 対応推奨 / 次回定期 / 要調査 | **OS=対象**のみ台帳（対象外は載せない）。KEVあり→対応推奨、なし→次回定期。表示列は AI |

**KEV**: `あり` / `なし`  
**公式推奨対応**: 次回定期でも空にしない  
**Slack**: 対応推奨 + 要調査のみ。次回定期は台帳のみ

## 6. うまくいかないとき

| 症状 | 対処 |
|---|---|
| 台帳の列がずれる | `migrateLedgerHeaders()` → `clearRunData()` → `main()` |
| 影響機能が空 | `GEMINI_API_KEY` 確認。未設定時は title/impact のフォールバックが入るはず |
| Cisco が多すぎる | OS対象外は台帳から除外済みか確認。`clearRunData()` 後に再実行 |
| KEV 照合失敗 | ログの `KEV 照合失敗` → ネットワーク確認 |

## 7. 発表デモ用の最短確認

1. Fortinet 行 → `判定根拠` が `OS=対象 | KEV=なし | 機能=… → …` 形式
2. Cisco 行 → OS=対象のみ。公式推奨対応・影響機能・確認方法が入っている
3. `countByMonthVendor()` → 月別・ベンダー別

---

実行ログを貼ってもらえれば、次の修正に進みます。
