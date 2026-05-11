# 成功パターン集

このファイルは「うまくいった図解」の構造パターンを記録する。
ヒアリングシートの事例（Wi-Fi証明書認証・フェイルオーバー）を参考例として使用。

---

## 「ざっくり一言」の成功例

| トピック | ざっくり一言（30字以内） |
|---------|----------------------|
| WPA2 vs WPA3 | WPA3は"パスワード盗み見攻撃"に強い認証方式に刷新した規格 |
| RADIUSフェイルオーバー | RADIUSはAPと認証サーバの仲介役で、主系障害時に自動で副系へ切り替わる |
| SAMLの仕組み | SAMLはパスワードを渡さずに「本人確認済み」を別サービスに証明する仕組み |
| OktaのSCIM連携 | SCIMはOktaのユーザー情報を各SaaSに自動で同期・削除する規格 |

---

## パターン1: 冗長化・フェイルオーバーの図解

「正常時と障害時で何が変わるか」を比較で見せる。

### 全体構成

```
1. ヘッダー
   └─ タイトル: 「RADIUS認証のフェイルオーバー仕組み」
   └─ バッジ: 「ネットワーク / 認証」
   └─ 一言の答え: 「Primaryが応答しなくなると、設定した時間後に自動でSecondaryへ切り替わる」

2. この図解でわかること（冒頭サマリー）
   └─ 読み終わると「どの設定値を変えれば切り替わりタイムを短縮できるか」が判断できる

3. 一枚絵サマリー【ASCIIアート】
   └─ クライアント → 無線コントローラ → Primary/Secondaryサーバの全体フロー
   └─ 正常時と障害時の両方を1枚に収める

4. まず理解する3つの構造
   └─ RADIUSのリクエスト/レスポンスの仕組み
   └─ タイムアウトと再試行の仕組み
   └─ フェイルオーバーの判定ロジック

5. 各セクション
   └─ 通常時のフロー図
   └─ 障害時のフロー図
   └─ dead-time等の設定値と動作の対応表

6. まとめ
   └─ 「この理解で dead-time の設定変更を根拠を持って提案できる」
```

### 一枚絵ASCIIアートの例（RADIUSフェイルオーバー）

```html
<div class="bg-ads-surface rounded-2xl p-6 md:p-8 mb-6" id="overview">
  <div class="flex items-center gap-3 mb-4">
    <div class="w-10 h-10 rounded-xl bg-ads-text flex items-center justify-center flex-shrink-0">
      <i data-lucide="layout-template" class="w-5 h-5 text-white"></i>
    </div>
    <div>
      <p class="text-xs font-semibold text-ads-accent uppercase tracking-widest mb-0.5">全体像</p>
      <h2 class="text-xl font-bold text-ads-text">全体構成</h2>
      <p class="text-sm text-ads-muted">まずこの図で登場人物と通信の流れを把握する</p>
    </div>
  </div>

  <div class="bg-slate-900 rounded-xl p-5 md:p-8 overflow-x-auto">
    <pre class="font-mono text-sm leading-relaxed whitespace-pre"><span class="text-slate-400">【RADIUSフェイルオーバー: 全体フロー】</span>

<span class="text-blue-300">  [デバイス (PC / スマホ)]
         │
         │ ① 接続要求 (802.1X/EAP)
         ▼
  ┌─────────────────────────┐
  │  無線コントローラ (WLC)  │  ← フェイルオーバー設定はここに書く
  │  timeout=5s  retries=3  │
  └─────────────────────────┘
         │
         │ ② RADIUS Access-Request (UDP:1812)
         │
         ├──────────────────────────────────▶ [Primary RADIUS]
         │                                        │ ③ 応答あり → Accept/Reject
         │                                        ▼
         │  Primaryダウン時:             [デバイス接続 OK/NG]
         │  ② タイムアウト(5s) × 再送(3回) = 最大20s 待機
         │
         └──── dead-time経過まではスキップ ──▶ [Secondary RADIUS]
                                                   │ ④ 応答 → Accept/Reject
                                                   ▼
                                           [デバイス接続 OK/NG]</span>
    </pre>
  </div>

  <div class="mt-3 flex flex-wrap gap-4 text-xs text-ads-dim">
    <span>timeout = Primaryの応答待ち時間</span>
    <span>retries = タイムアウト後の再送回数</span>
    <span>dead-time = 障害判定後にPrimaryをスキップする時間</span>
  </div>
</div>
```

### 「まず理解する3つ」の書き方（例）

```html
<div class="bg-ads-surface rounded-2xl p-6 md:p-8 mb-6">
  <div class="flex items-center gap-3 mb-6">
    <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-blue-700 rounded-xl flex items-center justify-center">
      <i data-lucide="layers" class="w-5 h-5 text-white"></i>
    </div>
    <div>
      <p class="text-xs font-semibold text-ads-accent uppercase tracking-widest mb-0.5">まず理解する</p>
      <h2 class="text-xl font-bold text-ads-text">3つの構造</h2>
      <p class="text-sm text-ads-muted">この順に理解すると全体像がつながる</p>
    </div>
  </div>

  <div class="grid gap-4">
    <!-- 1つ目：骨格 -->
    <div class="flex items-start gap-4 p-4 bg-gradient-to-r from-blue-50 to-blue-100 rounded-xl border-l-4 border-blue-500">
      <div class="w-10 h-10 bg-blue-500 text-white rounded-full flex items-center justify-center font-bold text-lg flex-shrink-0">1</div>
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold text-ads-text">RADIUSの通信の仕組み</span>
          <span class="text-xs bg-blue-500 text-white px-2 py-0.5 rounded-full font-semibold">骨格</span>
        </div>
        <p class="text-sm text-ads-muted leading-relaxed">クライアントが直接認証サーバと通信するのではなく、<strong class="text-ads-text">無線コントローラが中継する</strong>。この中継者の存在が、フェイルオーバー設定の場所を決める。</p>
      </div>
    </div>

    <!-- 2つ目：補足 -->
    <div class="flex items-start gap-4 p-4 bg-gradient-to-r from-cyan-50 to-cyan-100 rounded-xl border-l-4 border-cyan-500">
      <div class="w-10 h-10 bg-cyan-500 text-white rounded-full flex items-center justify-center font-bold text-lg flex-shrink-0">2</div>
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold text-ads-text">タイムアウトと再試行</span>
          <span class="text-xs bg-cyan-500 text-white px-2 py-0.5 rounded-full font-semibold">補足</span>
        </div>
        <p class="text-sm text-ads-muted leading-relaxed">RADIUSはUDPベースのため、<strong class="text-ads-text">応答がなければ一定時間後に再送</strong>する。この再送回数とタイムアウト時間の積が「切り替わりまでの遅延」になる。</p>
      </div>
    </div>

    <!-- 3つ目：応用 -->
    <div class="flex items-start gap-4 p-4 bg-gradient-to-r from-gray-50 to-gray-100 rounded-xl border-l-4 border-gray-400">
      <div class="w-10 h-10 bg-gray-400 text-white rounded-full flex items-center justify-center font-bold text-lg flex-shrink-0">3</div>
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold text-ads-text">dead-time による保護</span>
          <span class="text-xs bg-gray-400 text-white px-2 py-0.5 rounded-full font-semibold">応用</span>
        </div>
        <p class="text-sm text-ads-muted leading-relaxed">一度障害と判定されたサーバへの問い合わせを、一定時間スキップする仕組み。この設定がないと、障害中も毎回Primaryに問い合わせて遅延が続く。</p>
      </div>
    </div>
  </div>
</div>
```

---

## パターン2: SaaS製品の仕組み図解

「このSaaSが何者で、どう機能しているか」を整理する。

### 全体構成

```
1. ヘッダー
   └─ 「〇〇（SaaS名）の仕組み」
   └─ バッジ: 「SaaS / 認証 / IDaaS」 など

2. この製品が解決する問題
   └─ ビフォー/アフター形式で「この製品がなかった時代の課題」を先に見せる

3. 一枚絵サマリー【ASCIIアート】
   └─ 製品の主要コンポーネントと外部連携先の全体図

4. 主要コンポーネントと役割
   └─ 各機能ブロックをアーキテクチャ図で配置

5. 他製品との連携フロー
   └─ どのプロトコルでどう連携するか（SAML / SCIM / OAuth等）

6. 設定と動作の対応
   └─ 設定パラメータ → 実際の動作の表

7. まとめ
   └─ 「この製品の導入提案に必要な理解ができた」
```

### 一枚絵ASCIIアートの例（IdPの連携構成）

```
  ┌──────── Okta Org ──────────────────────────────────────┐
  │                                                        │
  │  [Universal Directory]     [Application Integration]  │
  │   Users / Groups / OU  ──▶  Slack   (SAML/OIDC)      │
  │           │              ──▶  Google WS (SAML)         │
  │           │              ──▶  Box     (SCIM)           │
  │           │                                            │
  │      SCIM Provisioning                                 │
  └──────────────────────────────────────────────────────┘
              │ AD Agent / LDAP
              ▼
  ┌──── オンプレ Active Directory ───────────────────────┐
  │   DC01.corp.internal  (ユーザー情報の正本)           │
  └────────────────────────────────────────────────────┘
```

---

## パターン3: 認証フロー・プロトコルの図解

「通信が何回往復して、誰が何を確認するか」をシーケンスで見せる。
一枚絵はASCIIアートのシーケンス図で表現する。

### 一枚絵ASCIIアートの例（SAMLフロー）

```
ユーザー         SP（Slack等）          IdP（Okta等）
   │                  │                      │
   │ ① URL アクセス   │                      │
   │─────────────────▶│                      │
   │                  │ ② SAMLリクエスト発行  │
   │                  │─────────────────────▶│
   │◀────────────────────────────────────────│ ③ ログイン画面
   │ ④ ID/PW 入力     │                      │
   │─────────────────────────────────────────▶│
   │                  │◀───────────────────── │ ⑤ SAMLアサーション
   │ ⑥ アクセス許可   │                      │
   │◀─────────────────│                      │
```

### シーケンス図の書き方（例: SAMLフロー）

```html
<div class="bg-ads-surface rounded-2xl p-6 md:p-8 mb-6" id="saml-flow">
  <div class="flex items-center gap-3 mb-6">
    <div class="w-10 h-10 rounded-xl bg-ads-accent flex items-center justify-center flex-shrink-0">
      <i data-lucide="key-round" class="w-5 h-5 text-white"></i>
    </div>
    <div>
      <p class="text-xs font-semibold text-ads-accent uppercase tracking-widest mb-0.5">認証フロー</p>
      <h2 class="text-xl font-bold text-ads-text">SAMLの認証フロー</h2>
    </div>
  </div>

  <!-- シーケンスの参加者（上部に横並び） -->
  <div class="flex justify-around mb-4 px-4">
    <div class="text-center">
      <div class="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-1">
        <i data-lucide="user" class="w-5 h-5 text-blue-600"></i>
      </div>
      <p class="text-xs font-bold text-ads-muted">ユーザー</p>
    </div>
    <div class="text-center">
      <div class="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-1">
        <i data-lucide="globe" class="w-5 h-5 text-green-600"></i>
      </div>
      <p class="text-xs font-bold text-ads-muted">SP（サービス）</p>
    </div>
    <div class="text-center">
      <div class="w-10 h-10 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-1">
        <i data-lucide="key-round" class="w-5 h-5 text-purple-600"></i>
      </div>
      <p class="text-xs font-bold text-ads-muted">IdP（認証基盤）</p>
    </div>
  </div>

  <!-- フローのステップ -->
  <div class="space-y-3">
    <!-- ステップ1 -->
    <div class="flex items-center gap-3 bg-blue-50 rounded-xl p-3 border border-blue-100">
      <span class="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">1</span>
      <div class="flex-1">
        <div class="flex items-center gap-2">
          <span class="text-xs font-bold text-blue-700">ユーザー → SP</span>
          <i data-lucide="arrow-right" class="w-3 h-3 text-blue-500"></i>
        </div>
        <p class="text-sm text-ads-muted">サービスのURLにアクセス</p>
      </div>
    </div>

    <!-- ステップ2 -->
    <div class="flex items-center gap-3 bg-green-50 rounded-xl p-3 border border-green-100">
      <span class="w-6 h-6 bg-green-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">2</span>
      <div class="flex-1">
        <div class="flex items-center gap-2">
          <span class="text-xs font-bold text-green-700">SP → ユーザー → IdP</span>
          <i data-lucide="arrow-right" class="w-3 h-3 text-green-500"></i>
        </div>
        <p class="text-sm text-ads-muted">SAMLリクエストをIdPにリダイレクト</p>
      </div>
    </div>

    <!-- ステップ3 -->
    <div class="flex items-center gap-3 bg-purple-50 rounded-xl p-3 border border-purple-100">
      <span class="w-6 h-6 bg-purple-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">3</span>
      <div class="flex-1">
        <div class="flex items-center gap-2">
          <span class="text-xs font-bold text-purple-700">IdP → ユーザー</span>
          <i data-lucide="arrow-right" class="w-3 h-3 text-purple-500"></i>
        </div>
        <p class="text-sm text-ads-muted">ログイン画面を表示・認証</p>
      </div>
    </div>
  </div>
</div>
```

---

## ページ冒頭の設計ルール

### インライン目次は置かない

このタイプの図解（一度じっくり読む学習用ドキュメント）にインライン目次は不要。

**理由:**
- コンテンツは原理原則から順に積み上げる設計のため、飛ばし読みを促すシグナルを出すべきでない
- デスクトップでは右側固定目次がナビゲーションを担っている
- インライン目次を置くと見出しとの一致を常に維持しなければならない（負債になる）

**代わりに置くもの — 「読む前の問い」カード:**

```html
<div class="bg-ads-accent rounded-xl px-6 py-5 mb-8 text-white">
  <p class="text-sm text-blue-200 mb-1 font-medium">この図解が答える問い</p>
  <p class="text-lg font-bold leading-snug">〇〇はどう動くのか。△△・□□・◇◇の関係を原理から把握する。</p>
</div>
```

「この図解は〇〇という問いに答えるものだ」と読者が意図を掴んでから本文に入れる。

---

## ダーク背景ブロックの配色ルール

`bg-slate-900` を使う全てのブロック（ASCIIアート・まとめ・ダーク強調ボックス）で統一する。

| 用途 | クラス | 役割 |
|------|--------|------|
| フロー本文・矢印・記号 | `text-blue-300` | メインコンテンツ（最も目立つ） |
| セクション見出し・注記 | `text-slate-400` | 補助情報（一段落とす） |
| 区切り線 | `text-slate-600` | 最も目立たない構造線 |
| ラベル・アイコン強調 | `text-blue-300` | 見出しラベル・チェックアイコン |

**禁止:** `text-emerald-400` をダーク背景上のメインカラーとして使わない。
- エメラルドグリーンはページの `ads-positive`（成功・肯定）の意味を持つ色であり、ダーク背景上の汎用カラーとして使うと意味が混濁する。
- 「ターミナル = 緑」というクリシェに見え、2020年代のモダンデザインとして古くなる。
- ページのアクセントカラー（blue系）と色相がズレ、ページ内で浮く。

**例: ASCIIアートの `<pre>` タグ**

```html
<!-- NG -->
<pre class="font-mono text-sm leading-relaxed text-emerald-400 whitespace-pre">...</pre>

<!-- OK -->
<pre class="font-mono text-sm leading-relaxed whitespace-pre">
<span class="text-slate-400">【セクション見出し】</span>

<span class="text-blue-300">フロー本文
  [クライアント] ──── [サーバ]
</span>

<span class="text-slate-400">  ※ 補足注記</span>
<span class="text-slate-600">━━━━━━━━━━━━━━</span>
</pre>
```

---

## ページ冒頭の設計ルール（変更なし・再掲）

インライン目次は置かない。代わりに「読む前の問い」カードを配置する。
詳細は `exemplar.md` の「ページ冒頭の設計ルール」セクションを参照。

---

## 品質チェックリスト（コーポレートエンジニア版）

作成後、以下を確認：

### 内容の確認
- [ ] 一枚絵サマリーがASCIIアートで作られている（HTML図で代替していない）
- [ ] ASCIIアートが崩れていない（幅・フォントが適切）
- [ ] 「なぜそうなっているか」（原理原則）が説明されている
- [ ] コンポーネント間の関係・依存が図で示されている
- [ ] 正常時と異常時（フェイルオーバー等）の動作の違いが示されている
- [ ] 設定パラメータとその動作への影響が対応している
- [ ] 推測による説明は「※推測」とラベリングされている
- [ ] まとめに「この理解で〇〇の提案ができる」がある

### 根拠の確認
- [ ] 主要な説明に公式ドキュメントのリンクが添えられている
- [ ] 参照した一次情報のリストがページ末尾にある
- [ ] RFCや公式仕様書の引用がある場合は明示されている

### デザインの確認
- [ ] ADS配色のTailwindクラスを使用（`bg-ads-surface`・`text-ads-text`・`text-ads-muted` 等）
- [ ] Lucide Iconsを適切に使用している（絵文字禁止）
- [ ] スマホでも読みやすいレスポンシブ対応
- [ ] フロー図か構成図が使われている
- [ ] 対応表が読みやすい形式になっている
- [ ] ダーク背景（`bg-slate-900`）上のASCIIアートは `text-emerald-400` を使わず、`text-blue-300`（本文）+ `text-slate-400`（見出し・注記）+ `text-slate-600`（区切り線）で色分けしている
