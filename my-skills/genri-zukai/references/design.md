# デザインとレイアウト

見た目の正本は `assets/template.html`。このファイルには、その部品をいつ使うかと、外してはいけない約束だけを書く。

## 目次

- 外してはいけない約束
- ページの寸法
- 部品の使いどころ
- 部品の並べ方
- 明暗と印刷

---

## 外してはいけない約束

- **1 ファイルで完結させる。** 外部の CSS・JS・フォント・画像を読み込まない（`<script src>` `<link rel="stylesheet">` `<img src="http…">` `@import` を書かない）。ネットがなくても同じ見た目で開けること
- **CSS は `assets/template.html` の `<style>` をそのまま使う。** 部品を足すときは同じ書き方（`rgb(var(--トークン))`）で末尾に足す。値を発明しない
- **本文の要素に色を直接書かない。** `style="color:…"` も 16 進の色も書かない。色は部品のクラスが持つ。書いた色は暗い画面で黒地に黒い字として残る
- **図（SVG）だけは 16 進で色を書く。** 図は明暗で反転しない白い紙として扱う。色は references/figures.md の表の値だけ
- **アイコンはインライン SVG。** references/icons.md から写す

---

## ページの寸法

- 本文の列は最大 768px、左右の余白 20px（`main`）。スマホ（幅 375px）でもページが横にはみ出さない
- 図は列の幅いっぱい（16:9）。幅 640px 未満では、図だけが幅 720px になり、図の枠の中で横にスクロールする（字を読める大きさに保つため。テンプレートの CSS がやる）
- 2 列・3 列の部品は、狭い画面では 1 列に落ちる（テンプレートの CSS がやる）

---

## 部品の使いどころ

| 部品 | クラス | 使うとき |
|---|---|---|
| 表紙 | `.hero` `.pill` `.title-grad` `.subtitle` `.lead` | ページの先頭に 1 つ |
| 全体像 | `.overview` `.cards3` `.card` `.down` `.goal` `.scope` | 表紙の直後に 1 つ。カードはパートの数（導入を除いて 2〜4）。4 枚のときは `class="cards3 cards4"`、2 枚のときは `class="cards3 cards2col"` |
| パート見出し | `.part` `.part-head` | 段階ごとの大見出し。右に区切り線が伸びる |
| パートの前置き | `.part-intro` | パート全体の前提を 1〜2 文で言いたいときだけ |
| セクション | `.sec` `.sec-head` `.sec-num` | 1 つの主張。番号は 01 から通し |
| 答え | `.answer` | 問いの見出しのリード 1 文目（答えの文） |
| 図 | `.fig` `.fig-frame` `figcaption` `.fig-note` | セクションに 1 枚が基本 |
| 橋渡し | `.bridge` | セクションの最後。最後のセクションには置かない |
| 定義の箱 | `.note` | 本文の流れから外して、用語や条件を 1 つ定義する |
| ○× | `.vs` `.ok` `.ng` `.mark` | できる／できない、正しい／誤解を並べる |
| 2 つの面 | `.cards2` | 同じものの 2 つの側面（画像から分かること／知識で補うこと） |
| 用語の一覧 | `.terms` | 用語が 3 つ以上まとめて出るとき。図の直後 |
| 手順 | `.steps` | 順番に意味がある 3〜5 個の手順 |
| 式 | `.calc` | 足し引きで結論が出る数字の例 |
| 要点 | `.takeaway` | 最後のセクションの締め。パートの締めに使うなら 1 パート 1 つまで |
| 断り | `.caveat` | 時期で変わる数値、単純化の断り |
| まとめ | `.closing` `.principle` | 原理の 1 文。ページに 1 つ |
| 出典 | `.sources` | 確かめた資料と確認日。ページの最後 |

各部品の HTML の形はテンプレートに 1 つずつ書いてある。テンプレートにない部品（`.vs` `.cards2` `.terms` `.steps` `.calc` `.note` `.takeaway` `.caveat` `.answer` `.part-intro`）は次の形で書く。

```html
<div class="note"><h4>同じ出発点を指定する番号が「シード」</h4><p>同じ指示・条件でシードをそろえると、同じ画像をもう一度作れる。</p></div>

<div class="vs">
  <div class="ok"><h4><span class="mark" aria-hidden="true">○</span><span>砂嵐からなら作れる</span></h4><p>学習で想定した出発点なので、学んだ方法を使える。</p></div>
  <div class="ng"><h4><span class="mark" aria-hidden="true">×</span><span>真っ白からでは作れない</span></h4><p>想定した出発点と違うため、学んだ方法を使えない。</p></div>
</div>

<div class="cards2">
  <div><svg class="icon" …>…</svg><h4>見出し</h4><p>説明。</p></div>
  <div><svg class="icon" …>…</svg><h4>見出し</h4><p>説明。</p></div>
</div>

<dl class="terms"><dt>用語</dt><dd>意味を 1 文で</dd><dt>用語</dt><dd>意味を 1 文で</dd></dl>

<ol class="steps">
  <li><span class="n">1</span><b>記録を残す</b><span>実際に行った内容を残す</span></li>
  <li><span class="n">2</span><b>整理する</b><span>記録を使いやすい形に整える</span></li>
</ol>

<div class="calc">
  <div><small>最初にかけた費用</small><b>−10万円</b></div><span class="op" aria-hidden="true">＋</span>
  <div><small>毎月の差し引き×12</small><b>0円</b></div><span class="op" aria-hidden="true">＝</span>
  <div class="result"><small>1年後の収支</small><b>−10万円</b></div>
</div>

<p class="takeaway">AI は写真から読み取った情報に、学んだ知識を加えて説明する。</p>
<p class="caveat">※ 料金は 2026 年 11 月時点の公開価格。変わることがある。</p>
<p class="answer">答えは、出発点となるノイズが違うからです。</p>
```

---

## 部品の並べ方

- **1 セクションの部品は、図を含めて 3 つまで。** 図・○×・要点を全部入れると、何が主張か見えなくなる。数えるのは図（`.fig`）・`.note`・`.vs`・`.cards2`・`.terms`・`.steps`・`.calc`・`.takeaway`。`.answer`・`figcaption`・`.fig-note`・`.caveat`・`.bridge` は数えない
- 図の直前には必ずリード（本文）を置く。図から始めない
- 同じ部品を 2 セクション続けて使わない（○× が続く、など）。型を変えて見せ方を変える
- `.bridge` と `.takeaway` を同じセクションに置かない
- 縦の余白はテンプレートの値のまま。部品の間に空の段落や `<br>` を入れて余白を作らない

---

## 明暗と印刷

- 明暗はトークンが切り替える。暗い画面でも図は白い紙のまま（元の講義の図と同じ）
- 印刷するとカード・図が途中で切れないよう、テンプレートの `@media print` が持つ。消さない
