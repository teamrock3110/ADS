# 一次情報の引用・表示ルール（Markdown出力向け）

「人に説明できるレベル」の信頼性を作るための出典表示の原則。

---

## 大原則: 「読者が疑う箇所にだけ URL を置く」

URL を貼ることそのものが目的ではない。
**「この主張、本当に正しいの？」と読者が疑ったとき、すぐ確認できる状態を作る**ことが目的。

---

## URL を置く閾値

### URL が必要

| 条件 | 例 |
|------|----|
| 具体的な数値・仕様値を断言している | 「有料プランのコンテキストウィンドウは 200K トークン」 |
| 読者にとって意外な事実 | 「Cowork は隔離された仮想マシン上で動作する」 |
| 判断・設定変更に直接影響する重要な制約 | 「Privacy Mode OFF はコードが学習に使われる可能性がある」 |

### URL 不要

| 条件 | 例 |
|------|----|
| 製品カテゴリの一般説明 | 「Cursor は VS Code ベースのコードエディタ」 |
| 業界で広く知られた事実 | 「RADIUS は認証プロトコルである」 |
| 既に URL 付きで示した主張の補足 | 同じ出典で説明した内容の言い換え |

**目安: 1つの見出し・段落につき 0〜2 個程度。**

---

## 一次情報の優先順位

### Tier 1（最も信頼性が高い・主役）
- ベンダー公式ドキュメント・管理者ヘルプ
- 公式 API リファレンス・公式ヘルプセンター

### Tier 2（参考として使える）
- ベンダー公式ブログ
- 公式 Changelog・リリースノート
- 標準化団体の規格（RFC / OASIS / W3C / NIST 等）※規格自体が主題のとき、または公式で原理が掴めないときの補助

### Tier 3（最終手段・明示ラベル必須）
- 個人ブログ・Qiita・Zenn
- Stack Overflow
- Wikipedia
- まとめサイト・二次情報

**原則は使わない。** ただし一次情報がどうしても見つからないマイナー・新しい事例に限り、補助的に使ってよい。
使う場合は次を守る:
- 一次情報を十分探した上での最終手段とする
- 該当箇所に `※二次情報（個人ブログ等）に基づく・一次情報未確認` と明示する
- 可能なら複数の二次情報で裏を取る
- 回答冒頭に `⚠ このトピックは一次情報が乏しく、一部を二次情報で補っています` と1行添える

---

## Markdown でのインライン出典

### 基本形式

主張の直後に改行して、短いリンクテキストでさりげなく置く:

```markdown
有料プランのコンテキストウィンドウは **200K トークン**。
[Claude コンテキスト公式ヘルプ](https://support.claude.com/en/articles/8606394)
```

### リンクテキストのルール

- URLそのままは使わない
- サービス名・ドキュメント名など、ページ内容がわかる短い名前にする（「出典:」プレフィックスは不要）
- 例: `[MDN Web Docs](https://developer.mozilla.org/ja/docs/...)`、`[Okta 管理者ヘルプ](https://...)`

### 推測・情報なしのラベル

```markdown
※ 推測（公式情報未確認）

公式情報なし
```

根拠のない技術的主張は書かず、「情報が見つかりませんでした」と明示する。

---

## フッターの参照一覧

本文末尾に、図解全体で根拠とした主要な一次情報を列挙する:

```markdown
---
### 参照した一次情報
- [MDN Web Docs — Web API の紹介](https://developer.mozilla.org/ja/docs/...)
- [Stripe API 公式ドキュメント](https://docs.stripe.com/api)
```

本文のインライン出典と併用する。フッターだけに出典をまとめ、本文に一切リンクがないのは NG。

---

## 禁止事項

- 二次情報（Qiita, Zenn, Wikipedia 等）を根拠にする
- 数値断言・意外な事実に出典なしで書く
- 出典の有無に関係なく全行に URL を貼る（ノイズになる）
- 根拠なしの技術情報を推測で書く

---

## よく参照するドキュメント（技術調査向け）

| 技術領域 | 主要な参照先 |
|---------|-----------|
| Web API全般 | [MDN Web Docs](https://developer.mozilla.org/ja/docs/Web/API) |
| OAuth / OIDC | [RFC 6749](https://tools.ietf.org/html/rfc6749) |
| SAML | [OASIS SAML 仕様](https://www.oasis-open.org/standards/#samlv2.0) |
| SCIM | [RFC 7644](https://tools.ietf.org/html/rfc7644) |
| RADIUS | [RFC 2865](https://tools.ietf.org/html/rfc2865) |
| Okta | [Okta Developer Docs](https://developer.okta.com/docs/) |
| Microsoft Entra ID | [Microsoft Learn](https://learn.microsoft.com/ja-jp/entra/identity/) |
| Google Workspace | [Google Workspace 管理者ヘルプ](https://support.google.com/a/) |
| Kubernetes | [Kubernetes 公式ドキュメント](https://kubernetes.io/docs/) |
