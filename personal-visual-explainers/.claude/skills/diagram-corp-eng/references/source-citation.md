# 一次情報の引用・表示ルール

「上長に自信を持って説明できる」状態を作るための出典表示の原則。

---

## 大原則: 「読者が疑う箇所にだけ URL を置く」

URL を貼ることそのものが目的ではない。
**「この主張、本当に正しいの？」と読者が疑ったとき、すぐ確認できる状態を作る**ことが目的。

URL を全ての主張に貼ると視覚的ノイズになり、かえって「どれが本当に重要な根拠か」が埋もれる。

---

## URL を置く閾値

### URL が必要（読者が疑う可能性が高い）

| 条件 | 例 |
|------|----|
| 具体的な数値・仕様値を断言している | 「有料プランのコンテキストウィンドウは 200K トークン」 |
| 読者にとって意外な事実 | 「Cowork は隔離された仮想マシン上で動作する」 |
| 判断・設定変更に直接影響する重要な制約 | 「Privacy Mode OFF はコードが学習に使われる可能性がある」 |
| 公式が明確に否定・制限している事項 | 「ローカルファイルへのアクセスは Cowork 除く」 |

### URL 不要（一般的な知識として受け入れられる）

| 条件 | 例 |
|------|----|
| 製品カテゴリの一般説明 | 「Cursor は VS Code ベースのコードエディタ」 |
| 業界で広く知られた事実 | 「RADIUS は認証プロトコルである」 |
| すでに URL を載せた主張の補足・言い換え | 同じ出典で説明した内容を別の言葉で補足する場合 |
| 上記の URL 付き主張から自明に導ける内容 | A と B の違いを既に根拠付きで示したあとの「したがって C」 |

**目安: 1 つのカード・ステップにつき 0〜2 個程度が適切。**  
貼りたくなったら「この URL がなければ読者は判断できないか？」を自問する。

---

## 一次情報の優先順位

### Tier 1（最も信頼性が高い）
- ベンダー公式ドキュメント（Cisco / Microsoft / Okta / Google Workspace 等）
- IETF RFC（ネットワークプロトコルの仕様）
- 公式 API リファレンス・公式ヘルプセンター

### Tier 2（参考として使える）
- ベンダー公式ブログ（製品チームによるアップデート情報）
- ベンダー公式 Changelog・リリースノート
- 公式コミュニティフォーラムのスタッフ回答

### Tier 3（使わない）
- 個人ブログ・Qiita・Zenn
- Stack Overflow
- まとめサイト・二次情報

---

## 情報の種別ラベリング

| 情報の種別 | 表示方法 |
|-----------|---------|
| Tier 1/2 の公式ドキュメントから引用 | Tailwind `text-xs text-ads-accent hover:underline` でインラインリンク |
| 公式情報が見つからない推測 | Tailwind `text-xs text-ads-dim` で「※ 推測」と明示 |
| 公式情報が存在しない旨を明記 | インラインで「公式情報なし」と記述 |

---

## HTML での実装

### 基本: 主張の直後にインラインリンク

**置き場所は「主張の直後」。カード末尾や末尾リストに置かない。**

```html
<!-- 良い例: 数値の断言の直後にインライン出典 -->
<p class="text-sm text-ads-muted leading-relaxed">
  有料プランのコンテキストウィンドウは <strong class="text-ads-text">200K トークン</strong>。
  <a href="https://support.claude.com/en/articles/8606394" target="_blank" class="text-xs text-ads-accent hover:underline">
    ↗ Claude コンテキスト公式ヘルプ
  </a>
</p>

<!-- 良い例: 意外な制約の直後に出典 -->
<p class="text-sm text-ads-muted leading-relaxed">
  Cowork は <strong class="text-ads-text">隔離された仮想マシン</strong> 上で動作する。
  <a href="https://www.anthropic.com/product/claude-cowork" target="_blank" class="text-xs text-ads-accent hover:underline">
    ↗ Claude Cowork 公式
  </a>
</p>

<!-- 悪い例: 全ての主張にバッジを貼る（ノイズになる）-->
<p>Claude はモデルである <a ...>↗</a>。Cursor は IDE である <a ...>↗</a>。...</p>
```

### 複数リンクを載せる場合

```html
<!-- ステップ末尾に出典をまとめる（同じステップ内の複数主張に対して）-->
<div class="flex flex-col gap-1 mt-2">
  <a href="..." target="_blank" class="text-xs text-ads-accent hover:underline">↗ 出典名 A</a>
  <a href="..." target="_blank" class="text-xs text-ads-accent hover:underline">↗ 出典名 B</a>
</div>
```

### 推測ラベル

```html
<span class="text-xs text-ads-dim">※ 推測（公式情報未確認）</span>
<!-- または -->
<span class="text-xs text-ads-dim">公式情報なし</span>
```

---

## 禁止事項

- ページ末尾に「参照した一次情報」セクションを独立して作る → 禁止
- カード末尾にすべての URL をまとめてリスト化する → 禁止（1:1 対応が取れなくなる）
- 出典の有無に関係なく全行に URL を貼る → 禁止（ノイズになる）

---

## よく参照するドキュメント（コーポレートエンジニア向け）

| 技術領域 | 主要な参照先 |
|---------|-----------|
| RADIUS | [RFC 2865](https://tools.ietf.org/html/rfc2865) / [RFC 2866](https://tools.ietf.org/html/rfc2866) |
| SAML | [OASIS SAML 仕様](https://www.oasis-open.org/standards/#samlv2.0) |
| OAuth / OIDC | [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749) |
| SCIM | [RFC 7644](https://tools.ietf.org/html/rfc7644) |
| Okta | [Okta Developer Docs](https://developer.okta.com/docs/) |
| Microsoft Entra ID | [Microsoft Learn](https://learn.microsoft.com/ja-jp/entra/identity/) |
| Google Workspace | [Google Workspace 管理者ヘルプ](https://support.google.com/a/) |
| Cisco 無線 | [Cisco Wireless LAN Controller](https://www.cisco.com/c/ja_jp/products/wireless/wireless-lan-controller/index.html) |
| Slack | [Slack API Docs](https://api.slack.com/) |
| Salesforce | [Salesforce Help](https://help.salesforce.com/s/) |
