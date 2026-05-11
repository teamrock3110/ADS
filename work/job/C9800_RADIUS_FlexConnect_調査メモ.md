# C9800 FlexConnect RADIUS認証 フェイルオーバー 調査メモ

作成日：2026-03-13  
最終更新：2026-03-13  
担当：  

---

## 1. 構成概要

### RADIUSサーバ（ONE GATE）

| 役割 | ホスト名 | IPアドレス |
|------|----------|------------|
| プライマリ | EDGETVR-01 | 192.168.151.219 |
| セカンダリ | EDGETVR-02 | 192.168.151.218 |

### ネットワーク機器

- **WLC：** Cisco Catalyst 9800（C9800）
- **AP動作モード：** FlexConnect（Local Auth使用）

### 対象SSID

| SSID名 | 認証方式 | 備考 |
|--------|----------|------|
| `v_access01-r` | EAP-TLS（端末証明書） | RADIUS認証対象 |
| `v_access01-r_6G` | EAP-TLS（端末証明書） | RADIUS認証対象（6GHz帯） |
| その他SSID | WPA認証 | RADIUS認証対象外 |

### RADIUSグループ定義

- グループ名：`GRP_EDGETVR`
- メンバー：EDGETVR-01（プライマリ）、EDGETVR-02（セカンダリ）

---

## 2. 設計方針

- **通常時：** EDGETVR-01で認証
- **障害時：** EDGETVR-02へ自動フェイルオーバー
- **切り替わり目標時間：** 10秒以内
- **ユーザ影響：** フェイルオーバー中も認証可能な状態を維持

---

## 3. 現在の課題

### 事象

EDGETVR-01をオフライン（シャットダウン等）にしても、EDGETVR-02へ認証先が切り替わらない。

### 症状の確認（実機）

EDGETVR-01をオフラインにした状態で `show aaa servers` を実行すると、  
**status が UP のまま DOWN に変わらない。**

---

## 4. 原因分析（調査済み）

### 4-1. 根本原因：`show aaa servers` が UP のままになる理由

**WLC は一度も EDGETVR-01 にリクエストを送っていないため、失敗を検知できない。**

#### WLC の Dead 判定の仕組み

```
WLC が RADIUS サーバを DOWN と判定する条件：

  WLC 自身が送ったリクエスト
      ↓
  応答がない × dead-criteria の回数
      ↓
  DOWN と判定

= リクエストを送っていなければ、失敗も検知できない
```

#### FlexConnect Local Auth だと WLC がリクエストを送らない

```
【Central Auth（WLCが仲介）】
[端末] → [AP] → [WLC] → [RADIUSサーバ]
                  ↑
          WLCが送信・受信するため失敗を検知できる

【FlexConnect Local Auth（今回の構成）】
[端末] → [AP] ─────────────→ [RADIUSサーバ]
                               ↑
          APが直接通信するため WLC はこのやり取りを一切知らない
          WLC の送信記録：0件 → 失敗記録：0件 → show aaa servers：UP のまま
```

#### 結論

| 状態 | WLCのリクエスト送信 | show aaa servers |
|------|------------------|-----------------|
| FlexConnect Local Auth（automate-testerなし） | **ゼロ** | **UP のまま（誤認）** |
| automate-tester idle-time あり | WLCが自分でprobe送信 | **DOWN に変わる ✓** |

> **これはバグではなく、WLC が何も送っていないことによる当然の結果。**

---

### 4-2. なぜフェイルオーバーしないか

```
EDGETVR-01がダウン
  ↓
APがEDGETVR-01へ認証リクエスト送信 → タイムアウト
  ↓
WLCはこのやり取りを知らない
  ↓
WLC上でEDGETVR-01はまだ "UP" のまま
  ↓
APはWLCから「EDGETVR-02を使え」と通知されない
  ↓
切り替わらない
```

### 4-3. automate-tester（idle-time）を入れると解決する理由

```
WLC自身がidle-time間隔でEDGETVR-01へprobeを送信
  ↓
EDGETVR-01がダウン → WLCがタイムアウトを検知
  ↓
WLCの失敗カウントが積み上がる → dead-criteriaを満たす
  ↓
show aaa servers → DOWN に変わる
  ↓
WLCがFlexConnect APに「EDGETVR-01はDown」を通知
  ↓
APがEDGETVR-02へ切り替え → フェイルオーバー成功 ✓
```

**→ FlexConnect Local Auth環境でフェイルオーバーを実現するには、WLCが自らRADIUSサーバを死活監視する `automate-tester` が必須。**

### 4-2. automate-testerの各オプションの動作（Ciscoコミュニティ・Ciscoエンジニア確認済み）

#### `idle-time N`（probe-onなし）

```
automate-tester username probe-user idle-time 5
```

- サーバが **Alive の状態でも** idle-time間隔（5分）ごとにprobeを送信
- ONE GATEに定期的にRADIUSリクエストのログが残る
- サーバ障害を能動的に検知できる

#### `probe-on`（idle-timeなし）

```
automate-tester username probe-user probe-on
```

- **設定を投入した瞬間にサーバをDeadに強制する**（重要な副作用）
- Deadになったあと、deadtime経過ごとにprobeを送信
- DeadのままAliveに戻れなければ、deadtimeごとにしかprobeしない
- 設定投入時に一時的に認証不能になるリスクあり

#### `idle-time` と `probe-on` の**併用は不可**（IOS-XE 17.9.4aでも確認済み）

```
automate-tester username probe-user idle-time 5 probe-on
→ % Invalid input detected  ← エラーになる
```

どちらか一方しか選択できない。

| 設定 | Alive時のprobe | Dead時のprobe | ログ影響 | リスク |
|------|--------------|--------------|---------|-------|
| `idle-time N` | N分ごとに送信 | 継続 | 常にあり | ログが多い |
| `probe-on` | なし | deadtimeごとに送信 | Dead時のみ | 設定投入時に即Dead |
| なし（passive） | なし | なし | なし | 初回ユーザが待たされる＋WLCが検知できない |

---

## 5. 推奨設定

### 5-1. RADIUSサーバ定義（automate-tester必須）

```
radius server EDGETVR-01
 address ipv4 192.168.151.219 auth-port 1812 acct-port 1813
 automate-tester username probe-user idle-time 5
 timeout 3
 retransmit 2
 key <shared-secret>

radius server EDGETVR-02
 address ipv4 192.168.151.218 auth-port 1812 acct-port 1813
 automate-tester username probe-user idle-time 5
 timeout 3
 retransmit 2
 key <shared-secret>
```

> `idle-time 5`：5分間RADIUSトラフィックがなければprobeを送信。  
> ログの影響を最小限にしつつ、アイドル時の障害も検知できる。  
> ONE GATE側で `probe-user` のログをフィルタリングすることでログの影響をさらに低減可能。

### 5-2. Dead Criteria設定

```
aaa server radius dead-criteria time 5 tries 2
```

| パラメータ | 値 | 意味 |
|-----------|-----|------|
| `time` | 5 | 5秒以内に応答がない |
| `tries` | 2 | 2回連続未応答でDeadと判定 |

### 5-3. AAA サーバグループ

```
aaa group server radius GRP_EDGETVR
 server name EDGETVR-01
 server name EDGETVR-02
 deadtime 5
```

- サーバの記載順が優先順位（EDGETVR-01がプライマリ）
- `deadtime 5`：Dead判定後5分間は再試行しない

### 5-4. AAA 認証・認可設定

```
aaa authentication dot1x default group GRP_EDGETVR
aaa authorization network default group GRP_EDGETVR
```

### 5-5. FlexConnect Profile へのRADIUS紐付け

**GUIの場合：**

```
Configuration > Tags & Profiles > Flex
→ 対象Flex Profile を選択
→ [RADIUS] タブ
→ RADIUS Server Group: GRP_EDGETVR を設定
```

**CLIの場合：**

```
wireless profile flex <FlexProfile名>
 radius server group GRP_EDGETVR
```

> **重要：** FlexConnect ProfileのRADIUS設定はWLCのグローバルAAA設定とは独立。  
> Flex Profile側に**明示的に**設定しないとフェイルオーバーが機能しない。

### 5-6. WLAN（SSID）設定 ※EAP-TLS対象SSIDのみ

```
wlan v_access01-r 1 v_access01-r
 security dot1x authentication-list default
 security wpa wpa2
 security wpa wpa2 ciphers aes
 no security wpa wpa2 ciphers tkip
 no shutdown
```

`v_access01-r_6G` についても同様に設定する。

---

## 6. ログ対策（ONE GATE側）

automate-testerを使う場合、ONE GATE側で以下の対応を検討する。

| 対応 | 内容 |
|------|------|
| **probe専用ユーザを作成** | `probe-user` をONE GATEに正規ユーザとして登録。Access-Acceptを返すことでログ上でテスト認証と識別可能にする |
| **ログフィルタリング** | ONE GATEのログ管理で `probe-user` のエントリを除外またはレベルを下げる |
| **idle-timeを長くする** | 監視の要件に応じて `idle-time` を長くすることでログ頻度を下げる（5分→10分など） |

---

## 7. 確認コマンド（実機確認時）

```bash
# WLC上でのRADIUSサーバ死活状態確認（automate-testerが効いているか）
show aaa servers

# RADIUS Dead検知設定の確認
show aaa dead-criteria radius 192.168.151.219

# FlexConnect APのRADIUS設定・状態確認
show ap name <AP名> flex

# 接続中のクライアント状態確認
show wireless client summary

# RADIUS認証デバッグ（本番環境では注意）
debug radius authentication

# WLCのログでRADIUS Dead/Alive通知を確認
show logging | include RADIUS
show logging | include dead
```

---

## 8. 未確認事項（要確認）

- [ ] 現在、FlexConnect Profile/GroupにRADIUSグループが**明示的に設定されているか**
- [ ] `automate-tester` が現在設定されているか（`show run | section radius server`）
- [ ] C9800のIOS-XEバージョン（`show version` で確認）
- [ ] ONE GATE側でprobe専用ユーザのログフィルタリングが可能か
- [ ] EDGETVR-01オフライン時にWLCのsyslogに `Dead` の記録が出ているか

---

## 9. 調査で判明した誤解・訂正事項

| 当初の理解 | 調査後の正しい理解 |
|-----------|----------------|
| passive検知（automate-testerなし）でもtimeout/retransmitを短くすれば切り替わる | FlexConnect Local AuthではWLCが認証に関与しないため、passive検知だけでは**WLCがサーバダウンを知れず切り替わらない** |
| `probe-on` は「Aliveサーバを常時監視する」機能 | **設定投入時にサーバをDeadに強制し**、deadtimeごとに復旧確認する機能 |
| `idle-time` と `probe-on` は併用できる | **IOS-XE全バージョンで併用不可**（排他オプション） |

---

## 10. 変更履歴

| 日付 | 内容 | 担当 |
|------|------|------|
| 2026-03-13 | 初版作成・現状調査まとめ | |
| 2026-03-13 | 原因分析を全面更新。automate-testerが必須である根拠を追記。probe-on/idle-timeの動作を公式コミュニティ情報で訂正 | |
