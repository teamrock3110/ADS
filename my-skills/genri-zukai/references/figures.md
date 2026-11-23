# 図の描き方（SVG）

図は講義スライドと同じ見た目の 16:9 の「白い紙」を、インライン SVG で描く。写真やイラストは使わない（ネットなしで開ける 1 ファイルに収めるため）。

## 目次

- 図の約束
- 色
- 文字の大きさと幅
- 部品
- 型の選び方
- 型ごとの見本

---

## 図の約束

- **図は場面か物の動きで見せる。表になる図は描かない。** 「誰が・何を・どこへ渡し、その結果どうなるか」を、人・物・矢印で描く。左に項目名、右に値を並べただけの図は表なので、本文の `.vs` か `.terms` に置く。箱に字を入れて並べただけの図も、2 枚続けない
- **1 枚の図で言うことは 1 つ。** 図のタイトルがそのまま言い切りの 1 文になる（例：「画像の色は数字で表せる」）。セクション見出しと同じ文にしない。見出しが主張、図のタイトルは図が見せる事実
- **キャンバスは `viewBox="0 0 1280 720"` 固定。** 枠（白地・タイトル・下線）は `assets/template.html` の図をそのまま写す
- **中身は y=150〜680 を使い切る。** 中身の上下の中心を y=415 付近に置き、下に大きな空白を残さない。左右の余白は 48 以上
- **id は図ごとに接頭辞を付ける**（`f3-rule` `f3-head`）。1 ページに図が何枚あっても衝突させない
- **`<title>` と `<desc>` を必ず書く。** desc は「何が、どこから、どこへ」を文章で書く（読み上げと検索のため）
- **図の中の数値が説明用の仮のものなら、figcaption か `.fig-note` で「※ 図の数字は説明用の模式表現です」と断る**

---

## 色

図は明暗で反転しない紙なので、16 進で直接書く。ここ以外の色を足さない。

| 役 | 値 | 使う場所 |
|---|---|---|
| 見出し | `#1B4B68` | 図のタイトル、小さな ▶ |
| 濃紺 | `#10547C` | ラベル（ピル）、枠線、吹き出しの線、パネルの上下の線 |
| 青 | `#0C6CA4` | 主役の箱の塗り、主な矢印 |
| 赤 | `#DC1C18` | **その図で一番見てほしい 1 か所だけ**（新しく増えた分・変わった所・拡大の線） |
| 橙 | `#E46C38` | 逆向きの流れ（「戻す」「学ぶ」など、青の流れと対になる向き） |
| 面 | `#ECF4F8` | パネルの地 |
| 薄い面 | `#F4F8FC` | 枠だけの箱の地 |
| 字 | `#2C4C60` | 図の中の説明の字 |
| 灰 | `#909090` | 区切りの点線、補助の線、効かないもの（閉じた扉） |
| 淡い青 | `#A5C5D8` | 図のタイトルの下線の先、サーバーのランプ |

赤は 1 枚に 1 種類の対象まで。全部を赤くすると何も強調されない。

---

## 文字の大きさと幅

図は、本文の列（768px）では約 0.6 倍、スマホ（幅 640px 未満）では幅 720px に固定され約 0.56 倍で表示される（スマホでは図の枠の中だけ横にスクロールする。テンプレートの CSS がやる）。どちらでも 22 の字が約 12px になる。

- 図のタイトル 38、ラベル・箱の字 26〜30、説明の字 22〜24。**22 未満を使わない**
- 和文 1 字の幅は字の大きさとほぼ同じ。箱の幅は「字数 × 字の大きさ ＋ 48」以上にする
- SVG の文字は折り返さない。1 行は 14 字まで。長いときは `<tspan x=".." dy="1.3em">` で行を分けるか、言葉を削る
- 字は `text-anchor="middle"` で箱の中心に置き、縦位置は「箱の上端 ＋ 箱の高さ/2 ＋ 字の大きさ×0.35」

---

## 部品

そのまま写して座標と字を変える。

### ラベル（ピル）

```svg
<rect x="500" y="150" width="280" height="56" rx="28" fill="#10547C"/>
<text x="640" y="187" font-size="26" font-weight="700" fill="#FFFFFF" text-anchor="middle">最初に受け取る</text>
```

### 箱（塗り）と箱（枠）

```svg
<rect x="120" y="300" width="240" height="72" rx="10" fill="#0C6CA4"/>
<text x="240" y="345" font-size="26" font-weight="700" fill="#FFFFFF" text-anchor="middle">1回目の会話</text>

<rect x="440" y="300" width="240" height="72" rx="6" fill="#F4F8FC" stroke="#10547C" stroke-width="4"/>
<text x="560" y="345" font-size="28" font-weight="700" fill="#10547C" text-anchor="middle">注文数は？</text>
```

### 段の間の小さな ▶

```svg
<path d="M0 -14 L22 0 L0 14 Z" fill="#1B4B68" transform="translate(380 336)"/>
```

### 長い矢印（ラベル付き）

矢じりは `marker` で付ける。逆向きは色を橙にして `x1` と `x2` を入れ替える。

```svg
<defs>
  <marker id="f2-head" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
    <path d="M0 0 L10 5 L0 10 Z" fill="#0C6CA4"/>
  </marker>
</defs>
<line x1="260" y1="210" x2="1000" y2="210" stroke="#0C6CA4" stroke-width="8" marker-end="url(#f2-head)"/>
<rect x="520" y="164" width="220" height="48" rx="24" fill="#FFFFFF" stroke="#0C6CA4" stroke-width="4"/>
<text x="630" y="196" font-size="24" font-weight="700" fill="#0C6CA4" text-anchor="middle">ノイズを加える</text>
```

### パネル（上に見出しのピル）

比較や段階を並べる入れ物。地は面の色、上下に濃紺の線、ピルは上の線にまたがる。

```svg
<rect x="140" y="200" width="460" height="420" fill="#ECF4F8"/>
<rect x="140" y="200" width="460" height="3" fill="#10547C"/>
<rect x="140" y="617" width="460" height="3" fill="#10547C"/>
<rect x="240" y="174" width="260" height="56" rx="28" fill="#10547C"/>
<text x="370" y="211" font-size="26" font-weight="700" fill="#FFFFFF" text-anchor="middle">資料にたどり着ける</text>
```

### 吹き出し

本文に書いた結論を、図の上でも一言で言わせる。1 枚に 1 つまで。しっぽ（三角）は話し手か指す物へ向ける。

```svg
<path d="M770 150 h380 a24 24 0 0 1 24 24 v92 a24 24 0 0 1 -24 24 h-290 l-40 44 l4 -44 h-54 a24 24 0 0 1 -24 -24 v-92 a24 24 0 0 1 24 -24 z"
      fill="#FFFFFF" stroke="#10547C" stroke-width="5" stroke-linejoin="round"/>
<text x="960" y="210" font-size="30" font-weight="700" fill="#10547C" text-anchor="middle">
  <tspan x="960">会話が増えるごとに</tspan><tspan x="960" dy="1.3em">1回の費用も上がる</tspan>
</text>
```

### 拡大の線

全体のうちの 1 か所を赤い枠で示し、赤い点線で拡大図へつなぐ。

```svg
<rect x="300" y="250" width="40" height="40" fill="none" stroke="#DC1C18" stroke-width="4"/>
<line x1="340" y1="250" x2="560" y2="200" stroke="#DC1C18" stroke-width="3" stroke-dasharray="8 8"/>
<line x1="340" y1="290" x2="560" y2="560" stroke="#DC1C18" stroke-width="3" stroke-dasharray="8 8"/>
```

### 行の区切り

```svg
<line x1="60" y1="300" x2="1220" y2="300" stroke="#909090" stroke-width="2" stroke-dasharray="6 6"/>
```

### 場面の部品（人・物）

場面の図の登場人物と物。`translate(x y)` の位置が部品の中心（タイル・ブラウザは左上）。大きさは変えずに、位置だけ変えて使う。部品の下に名前を 22 の太字（濃紺）で添える。

| 部品 | 意味の目安 | 大きさ |
|---|---|---|
| 人 | あなた・利用者・担当者 | 幅 116、高さ 160 |
| ツール | ソフト・AI・アプリ（頼まれて動く側） | 幅 110、高さ 160 |
| サーバー | 預かる側・確かめる側 | 幅 124、高さ 142 |
| 鍵 | パスワード・何でも開くもの | 幅 130 |
| カード | 合言葉・許可・データ（中身を 2 行書ける） | 幅 170、高さ 92 |
| 引換券 | それだけでは使えない券・一時的なもの | 幅 170、高さ 70 |
| タイル | 触れられる対象（開いた／注目／閉じた） | 幅 116、高さ 100 |
| ブラウザ | 人目に触れる画面・途中の通り道 | 幅 320、高さ 170 |

```svg
<!-- 人 -->
<g transform="translate(200 300)"><circle cx="0" cy="-55" r="32" fill="#10547C"/><path d="M-58 70 A58 58 0 0 1 58 70 Z" fill="#10547C"/></g>
<!-- ツール -->
<g transform="translate(500 310)"><line x1="0" y1="-60" x2="0" y2="-82" stroke="#0C6CA4" stroke-width="6"/><circle cx="0" cy="-88" r="9" fill="#0C6CA4"/><rect x="-55" y="-60" width="110" height="90" rx="22" fill="#0C6CA4"/><circle cx="-22" cy="-20" r="11" fill="#FFFFFF"/><circle cx="22" cy="-20" r="11" fill="#FFFFFF"/><rect x="-24" y="6" width="48" height="8" rx="4" fill="#FFFFFF"/><rect x="-42" y="38" width="84" height="32" rx="12" fill="#10547C"/></g>
<!-- サーバー -->
<g transform="translate(800 330)"><rect x="-62" y="-70" width="124" height="42" rx="8" fill="#10547C"/><circle cx="-38" cy="-49" r="7" fill="#A5C5D8"/><rect x="-18" y="-53" width="60" height="8" rx="4" fill="#A5C5D8"/><rect x="-62" y="-20" width="124" height="42" rx="8" fill="#10547C"/><circle cx="-38" cy="1" r="7" fill="#A5C5D8"/><rect x="-18" y="-3" width="60" height="8" rx="4" fill="#A5C5D8"/><rect x="-62" y="30" width="124" height="42" rx="8" fill="#10547C"/><circle cx="-38" cy="51" r="7" fill="#A5C5D8"/><rect x="-18" y="47" width="60" height="8" rx="4" fill="#A5C5D8"/></g>
<!-- 鍵 -->
<g transform="translate(330 280)"><circle cx="-40" cy="0" r="24" fill="none" stroke="#10547C" stroke-width="10"/><rect x="-18" y="-5" width="82" height="10" fill="#10547C"/><rect x="40" y="5" width="9" height="16" fill="#10547C"/><rect x="56" y="5" width="9" height="11" fill="#10547C"/></g>
<!-- カード（目立たせるときは stroke と上の帯を赤にする） -->
<g transform="translate(640 270)"><rect x="-85" y="-46" width="170" height="92" rx="10" fill="#FFFFFF" stroke="#0C6CA4" stroke-width="4"/><rect x="-85" y="-46" width="170" height="14" rx="6" fill="#0C6CA4"/><text x="0" y="-2" font-size="22" font-weight="700" fill="#10547C" text-anchor="middle">予定を読む</text><text x="0" y="28" font-size="22" fill="#2C4C60" text-anchor="middle">1 時間まで</text></g>
<!-- 引換券 -->
<g transform="translate(640 290)"><path d="M-85 -35 H85 V-12 A12 12 0 0 0 85 12 V35 H-85 V12 A12 12 0 0 0 -85 -12 Z" fill="#FFFFFF" stroke="#10547C" stroke-width="4"/><line x1="-41" y1="-29" x2="-41" y2="29" stroke="#909090" stroke-width="2" stroke-dasharray="5 5"/><text x="20" y="9" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">引換券</text></g>
<!-- タイル：開いた／注目（赤枠は 1 つだけ）／閉じた -->
<rect x="392" y="490" width="116" height="100" rx="12" fill="#0C6CA4"/><text x="450" y="548" font-size="24" font-weight="700" fill="#FFFFFF" text-anchor="middle">写真</text>
<rect x="100" y="490" width="116" height="100" rx="12" fill="#0C6CA4" stroke="#DC1C18" stroke-width="5"/><text x="158" y="548" font-size="24" font-weight="700" fill="#FFFFFF" text-anchor="middle">予定</text>
<rect x="246" y="490" width="116" height="100" rx="12" fill="#FFFFFF" stroke="#909090" stroke-width="3" stroke-dasharray="8 6"/><text x="304" y="548" font-size="24" font-weight="700" fill="#909090" text-anchor="middle">メール</text>
<!-- ブラウザ（中に引換券やカードを置ける） -->
<rect x="480" y="190" width="320" height="170" rx="10" fill="#FFFFFF" stroke="#10547C" stroke-width="4"/><rect x="482" y="192" width="316" height="32" rx="8" fill="#ECF4F8"/><circle cx="500" cy="208" r="5" fill="#909090"/><circle cx="518" cy="208" r="5" fill="#909090"/><circle cx="536" cy="208" r="5" fill="#909090"/><rect x="556" y="199" width="224" height="18" rx="9" fill="#FFFFFF" stroke="#909090" stroke-width="1.5"/>
```

**直接の通り道（管）。** 2 者が人目に触れずに直接やり取りすることは、2 者の間をつなぐ角の丸い太い管（`rx` を高さの半分、地は面の色、線は濃紺 3）で描き、運ぶ物（カード）を管の上に重ねる。

部品にない物は、icons.md の絵記号を大きくして使う。それでも描けない物は、部品を自作せず言葉の箱にする。

### 絵記号（人・AI・書類など）

references/icons.md の 24 マスの線画を、拡大して置く。線の太さは拡大しても 2 のまま見えるよう `stroke-width` を割り戻す。

```svg
<g transform="translate(200 300) scale(3)" fill="none" stroke="#10547C" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <!-- icons.md の path をここに貼る -->
</g>
```

---

## 型の選び方

原理のどこを見せたいかで型を選ぶ。1 ページの中で同じ型ばかり続けない。**迷ったら場面にする。** 元の講義図解が伝わるのは、人や物が動く場面で見せているからである。

| 見せたいこと | 型 | 元の図の例 |
|---|---|---|
| 誰が何を渡し、その結果どうなるか | 場面 | あなたが鍵を渡すと、ツールは全部の扉を開けられる |
| 物が段階を追って変わる | 流れ | 砂嵐 → うっすら猫 → 猫 |
| 行きと帰りが対になる | 往復 | ノイズを加える／戻し方を学ぶ |
| 外から見えるものの正体 | 拡大 | 猫 → ピクセル → 赤緑青の数字 |
| 回を追うごとに増える | 積み重ね | 1 回目、2 回目、3 回目の会話 |
| 2 つのやり方で結果が変わる | 比較（2 つの場面を並べる） | パスワードを渡す／合言葉を渡す |
| 条件で道が分かれる | 分岐 | 発注は？ → 必要 → 注文数は？ |
| 同じ処理を繰り返す | 循環 | つくる → 照らす → 直す |
| 手順の段階ごとの中身 | 段階パネル | 数値に変える ▶ 近い絵を探す ▶ 解説する |
| 足し引きで結論が出る | 式 | 初期費用 ＋ 毎月の差 ＝ 1 年後 |
| 3〜4 者の間を順にやり取りする | やり取り | 利用者 → ツール → 認可サーバー → ツール（通信の手順、権限の受け渡し） |

---

## 型ごとの見本

枠（白地・タイトル・下線）は省略して中身だけを書く。そのまま貼れば形になる座標にしてある。

### 場面

1 枚に、渡す人 → 渡す物 → 受け取る者 と、その結果を描く。上半分で「渡す」、下半分で「どうなったか」を見せる。2 つのやり方を比べるときは、この形のパネルを左右に 2 枚並べる（比較の型）。

```svg
<defs><marker id="f4-head" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4" markerHeight="4" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#0C6CA4"/></marker></defs>
<rect x="350" y="160" width="580" height="510" fill="#ECF4F8"/><rect x="350" y="160" width="580" height="3" fill="#10547C"/><rect x="350" y="667" width="580" height="3" fill="#10547C"/><rect x="500.0" y="134" width="280" height="56" rx="28" fill="#10547C"/><text x="640.0" y="171" font-size="26" font-weight="700" fill="#FFFFFF" text-anchor="middle">合言葉を渡す</text>
<!-- 渡す人と受け取る物。間に矢印、矢印の上に渡す物 -->
<g transform="translate(450 300)"><circle cx="0" cy="-55" r="32" fill="#10547C"/><path d="M-58 70 A58 58 0 0 1 58 70 Z" fill="#10547C"/></g>
<text x="450" y="405" font-size="22" font-weight="700" fill="#10547C" text-anchor="middle">あなた</text>
<g transform="translate(820 310)"><line x1="0" y1="-60" x2="0" y2="-82" stroke="#0C6CA4" stroke-width="6"/><circle cx="0" cy="-88" r="9" fill="#0C6CA4"/><rect x="-55" y="-60" width="110" height="90" rx="22" fill="#0C6CA4"/><circle cx="-22" cy="-20" r="11" fill="#FFFFFF"/><circle cx="22" cy="-20" r="11" fill="#FFFFFF"/><rect x="-24" y="6" width="48" height="8" rx="4" fill="#FFFFFF"/><rect x="-42" y="38" width="84" height="32" rx="12" fill="#10547C"/></g>
<text x="820" y="405" font-size="22" font-weight="700" fill="#10547C" text-anchor="middle">ツール</text>
<line x1="525" y1="335" x2="745" y2="335" stroke="#0C6CA4" stroke-width="6" marker-end="url(#f4-head)"/>
<g transform="translate(635 270)"><rect x="-85.0" y="-46.0" width="170" height="92" rx="10" fill="#FFFFFF" stroke="#0C6CA4" stroke-width="4"/><rect x="-85.0" y="-46.0" width="170" height="14" rx="6" fill="#0C6CA4"/><text x="0" y="-2.0" font-size="22" font-weight="700" fill="#10547C" text-anchor="middle">予定を読む</text><text x="0" y="28.0" font-size="22" fill="#2C4C60" text-anchor="middle">1 時間まで</text></g>
<!-- その結果。注目の 1 つだけ赤枠、効かないものは点線 -->
<text x="640" y="470" font-size="22" fill="#2C4C60" text-anchor="middle">ツールが触れられるもの</text>
<rect x="387" y="490" width="116" height="100" rx="12" fill="#FFFFFF" stroke="#909090" stroke-width="3" stroke-dasharray="8 6"/><text x="445" y="548" font-size="24" font-weight="700" fill="#909090" text-anchor="middle">メール</text>
<rect x="517" y="490" width="116" height="100" rx="12" fill="#0C6CA4" stroke="#DC1C18" stroke-width="5"/><text x="575" y="548" font-size="24" font-weight="700" fill="#FFFFFF" text-anchor="middle">予定</text>
<rect x="647" y="490" width="116" height="100" rx="12" fill="#FFFFFF" stroke="#909090" stroke-width="3" stroke-dasharray="8 6"/><text x="705" y="548" font-size="24" font-weight="700" fill="#909090" text-anchor="middle">写真</text>
<rect x="777" y="490" width="116" height="100" rx="12" fill="#FFFFFF" stroke="#909090" stroke-width="3" stroke-dasharray="8 6"/><text x="835" y="548" font-size="24" font-weight="700" fill="#909090" text-anchor="middle">ドライブ</text>
<text x="640" y="640" font-size="22" font-weight="700" fill="#1B4B68" text-anchor="middle">予定だけ。ほかは閉じたまま</text>
```

### 流れ

```svg
<!-- 3 段。箱の幅 300、間に ▶ -->
<rect x="90"  y="300" width="300" height="200" rx="12" fill="#ECF4F8"/>
<rect x="490" y="300" width="300" height="200" rx="12" fill="#ECF4F8"/>
<rect x="890" y="300" width="300" height="200" rx="12" fill="#ECF4F8" stroke="#DC1C18" stroke-width="4"/>
<text x="240"  y="410" font-size="28" font-weight="700" fill="#10547C" text-anchor="middle">段階 1</text>
<text x="640"  y="410" font-size="28" font-weight="700" fill="#10547C" text-anchor="middle">段階 2</text>
<text x="1040" y="410" font-size="28" font-weight="700" fill="#10547C" text-anchor="middle">段階 3</text>
<path d="M0 -14 L22 0 L0 14 Z" fill="#1B4B68" transform="translate(429 400)"/>
<path d="M0 -14 L22 0 L0 14 Z" fill="#1B4B68" transform="translate(829 400)"/>
<text x="240"  y="550" font-size="22" fill="#2C4C60" text-anchor="middle">何が起きるか</text>
<text x="640"  y="550" font-size="22" fill="#2C4C60" text-anchor="middle">何が起きるか</text>
<text x="1040" y="550" font-size="22" fill="#2C4C60" text-anchor="middle">何が起きるか</text>
```

時間が流れるだけで物が変わらないとき（同じカードが期限を迎える、など）は、箱を並べず、下に時間の線（灰 4、y=600 付近）と時点の丸・名前を置き、各時点の上にその時の場面（部品と結果）を描く。

### 往復

上の段は左から右へ（青）、下の段は右から左へ（橙）。矢印のラベルが「何をする向きか」を言う。

```svg
<defs>
  <marker id="f3-blue" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="4" markerHeight="4" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#0C6CA4"/></marker>
  <marker id="f3-orange" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="4" markerHeight="4" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#E46C38"/></marker>
</defs>
<!-- 上の段（行き） -->
<line x1="260" y1="190" x2="1020" y2="190" stroke="#0C6CA4" stroke-width="8" marker-end="url(#f3-blue)"/>
<rect x="520" y="166" width="240" height="48" rx="24" fill="#FFFFFF" stroke="#0C6CA4" stroke-width="4"/>
<text x="640" y="199" font-size="24" font-weight="700" fill="#0C6CA4" text-anchor="middle">行きでやること</text>
<rect x="200" y="230" width="220" height="150" rx="10" fill="#ECF4F8"/>
<rect x="530" y="230" width="220" height="150" rx="10" fill="#ECF4F8"/>
<rect x="860" y="230" width="220" height="150" rx="10" fill="#ECF4F8"/>
<text x="310" y="314" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">状態 A</text>
<text x="640" y="314" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">状態 B</text>
<text x="970" y="314" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">状態 C</text>
<path d="M0 -14 L22 0 L0 14 Z" fill="#1B4B68" transform="translate(464 305)"/>
<path d="M0 -14 L22 0 L0 14 Z" fill="#1B4B68" transform="translate(794 305)"/>
<!-- 下の段（帰り） -->
<rect x="200" y="420" width="220" height="150" rx="10" fill="#ECF4F8"/>
<rect x="530" y="420" width="220" height="150" rx="10" fill="#ECF4F8"/>
<rect x="860" y="420" width="220" height="150" rx="10" fill="#ECF4F8"/>
<text x="310" y="504" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">状態 A</text>
<text x="640" y="504" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">状態 B</text>
<text x="970" y="504" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">状態 C</text>
<path d="M0 -14 L22 0 L0 14 Z" fill="#E46C38" transform="translate(486 495) rotate(180)"/>
<path d="M0 -14 L22 0 L0 14 Z" fill="#E46C38" transform="translate(816 495) rotate(180)"/>
<line x1="1020" y1="620" x2="260" y2="620" stroke="#E46C38" stroke-width="8" marker-end="url(#f3-orange)"/>
<rect x="520" y="596" width="240" height="48" rx="24" fill="#FFFFFF" stroke="#E46C38" stroke-width="4"/>
<text x="640" y="629" font-size="24" font-weight="700" fill="#E46C38" text-anchor="middle">帰りでやること</text>
```

### 拡大

```svg
<!-- 左：全体。中：拡大した 1 か所。右：その正体（数値など） -->
<rect x="60" y="200" width="300" height="380" rx="8" fill="#ECF4F8"/>
<text x="210" y="400" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">全体</text>
<rect x="290" y="230" width="44" height="44" fill="none" stroke="#DC1C18" stroke-width="4"/>
<circle cx="640" cy="390" r="170" fill="#F4F8FC" stroke="#2C4C60" stroke-width="5"/>
<line x1="334" y1="230" x2="560" y2="235" stroke="#DC1C18" stroke-width="3" stroke-dasharray="8 8"/>
<line x1="334" y1="274" x2="560" y2="545" stroke="#DC1C18" stroke-width="3" stroke-dasharray="8 8"/>
<text x="640" y="400" font-size="28" font-weight="700" fill="#10547C" text-anchor="middle">拡大した 1 か所</text>
<rect x="880" y="250" width="340" height="280" rx="14" fill="#ECF4F8"/>
<text x="1050" y="370" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">正体</text>
<text x="1050" y="420" font-size="40" font-weight="700" fill="#2C4C60" text-anchor="middle">210 · 167 · 155</text>
<line x1="810" y1="390" x2="880" y2="390" stroke="#DC1C18" stroke-width="3" stroke-dasharray="8 8"/>
```

### 積み重ね

```svg
<!-- 行ごとに 1 つずつ増える。前の回の分は青、その回に増えた分だけ赤 -->
<line x1="60" y1="230" x2="1220" y2="230" stroke="#909090" stroke-width="2" stroke-dasharray="6 6"/>
<text x="70" y="290" font-size="24" font-weight="700" fill="#2C4C60">1回目</text>
<rect x="170" y="254" width="210" height="64" rx="10" fill="#DC1C18"/>
<text x="275" y="295" font-size="24" font-weight="700" fill="#FFFFFF" text-anchor="middle">1回目の会話</text>
<line x1="60" y1="345" x2="1220" y2="345" stroke="#909090" stroke-width="2" stroke-dasharray="6 6"/>
<text x="70" y="405" font-size="24" font-weight="700" fill="#2C4C60">2回目</text>
<rect x="170" y="369" width="210" height="64" rx="10" fill="#0C6CA4"/>
<text x="275" y="410" font-size="24" font-weight="700" fill="#FFFFFF" text-anchor="middle">1回目の会話</text>
<text x="410" y="412" font-size="36" font-weight="700" fill="#DC1C18" text-anchor="middle">＋</text>
<rect x="440" y="369" width="210" height="64" rx="10" fill="#DC1C18"/>
<text x="545" y="410" font-size="24" font-weight="700" fill="#FFFFFF" text-anchor="middle">2回目の会話</text>
<line x1="60" y1="460" x2="1220" y2="460" stroke="#909090" stroke-width="2" stroke-dasharray="6 6"/>
<!-- 3 回目も同じ要領。最後に右上へ吹き出しで結論 -->
```

### 比較

```svg
<!-- 左右 2 枚のパネル。違いはパネルの中の絵記号と短い説明で見せる -->
<rect x="110" y="210" width="480" height="400" fill="#ECF4F8"/>
<rect x="110" y="210" width="480" height="3" fill="#10547C"/>
<rect x="110" y="607" width="480" height="3" fill="#10547C"/>
<rect x="220" y="184" width="260" height="56" rx="28" fill="#10547C"/>
<text x="350" y="221" font-size="26" font-weight="700" fill="#FFFFFF" text-anchor="middle">方法 A</text>

<rect x="690" y="210" width="480" height="400" fill="#ECF4F8"/>
<rect x="690" y="210" width="480" height="3" fill="#10547C"/>
<rect x="690" y="607" width="480" height="3" fill="#10547C"/>
<rect x="800" y="184" width="260" height="56" rx="28" fill="#10547C"/>
<text x="930" y="221" font-size="26" font-weight="700" fill="#FFFFFF" text-anchor="middle">方法 B</text>
<!-- 各パネルの中：絵記号（icons.md）を scale(4) で中央に、下に 22〜24 の説明を 2 行まで -->
```

○と×で比べるときは、× のパネルの見出しのピルを灰（`#909090`）にする。図より本文の `.vs`（○×カード）の方が向くことも多い。

パネルの中は、場面の型と同じく人・物・矢印と、その結果で描く。左右で同じ人・同じ位置にし、違う所（渡す物・結果）だけが目に入るようにする。項目名と値を行に並べただけの比較は表なので、図にせず本文の `.vs` か `.terms` に置く。

### 分岐

```svg
<defs>
  <marker id="f5-head" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="4" markerHeight="4" orient="auto">
    <path d="M0 0 L10 5 L0 10 Z" fill="#10547C"/>
  </marker>
</defs>
<!-- 1 段目 y=200、2 段目 y=420。もう 1 段分けるときは 2 段目の箱から同じ形で下へ伸ばす（y=600 まで） -->
<rect x="510" y="200" width="260" height="84" rx="4" fill="#F4F8FC" stroke="#10547C" stroke-width="4"/>
<text x="640" y="253" font-size="32" font-weight="700" fill="#10547C" text-anchor="middle">条件は？</text>
<path d="M640 284 V340 H320 V404" fill="none" stroke="#10547C" stroke-width="4" marker-end="url(#f5-head)"/>
<path d="M640 340 H960 V404" fill="none" stroke="#10547C" stroke-width="4" marker-end="url(#f5-head)"/>
<rect x="430" y="322" width="96" height="36" fill="#FFFFFF"/>
<text x="478" y="350" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">いいえ</text>
<rect x="770" y="322" width="72" height="36" fill="#FFFFFF"/>
<text x="806" y="350" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">はい</text>
<rect x="190" y="420" width="260" height="84" rx="4" fill="#F4F8FC" stroke="#10547C" stroke-width="4"/>
<text x="320" y="473" font-size="30" font-weight="700" fill="#10547C" text-anchor="middle">結果 A</text>
<rect x="830" y="420" width="260" height="84" rx="4" fill="#F4F8FC" stroke="#10547C" stroke-width="4"/>
<text x="960" y="473" font-size="30" font-weight="700" fill="#10547C" text-anchor="middle">結果 B</text>
```

### 循環

```svg
<defs>
  <marker id="f6-head" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="3.5" markerHeight="3.5" orient="auto">
    <path d="M0 0 L10 5 L0 10 Z" fill="#0C6CA4"/>
  </marker>
</defs>
<!-- 中心 (640,420)、半径 170 の円周上に 3 つの点。弧は点の手前で止める -->
<path d="M692 258 A170 170 0 0 1 800 480" fill="none" stroke="#0C6CA4" stroke-width="10" marker-end="url(#f6-head)"/>
<path d="M740 560 A170 170 0 0 1 540 560" fill="none" stroke="#0C6CA4" stroke-width="10" marker-end="url(#f6-head)"/>
<path d="M480 480 A170 170 0 0 1 588 258" fill="none" stroke="#0C6CA4" stroke-width="10" marker-end="url(#f6-head)"/>
<text x="640" y="235" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">つくる</text>
<text x="860" y="560" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">確かめる</text>
<text x="420" y="560" font-size="26" font-weight="700" fill="#10547C" text-anchor="middle">直す</text>
<text x="640" y="430" font-size="24" fill="#2C4C60" text-anchor="middle">条件を満たすまで</text>
```

### 段階パネル

パネル 3 枚（幅 340、間 60）の間に ▶。各パネルの中は「絵記号 → 短い説明」か「小さな箱 → 結果」。最後のパネルに吹き出しで答えを言わせると、流れの終点がはっきりする。

```svg
<!-- パネル 1（x=60）。2 枚目は x=470、3 枚目は x=880 に同じ形で置く -->
<rect x="60" y="210" width="340" height="420" fill="#ECF4F8"/>
<rect x="60" y="210" width="340" height="3" fill="#10547C"/>
<rect x="60" y="627" width="340" height="3" fill="#10547C"/>
<rect x="110" y="184" width="240" height="56" rx="28" fill="#10547C"/>
<text x="230" y="221" font-size="26" font-weight="700" fill="#FFFFFF" text-anchor="middle">数値に変える</text>
<g transform="translate(182 290) scale(4)" fill="none" stroke="#10547C" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/>
</g>
<text x="230" y="450" font-size="22" fill="#2C4C60" text-anchor="middle"><tspan x="230">写真の特徴を</tspan><tspan x="230" dy="1.4em">数値で表す</tspan></text>
<path d="M0 -14 L22 0 L0 14 Z" fill="#1B4B68" transform="translate(424 420)"/>
<path d="M0 -14 L22 0 L0 14 Z" fill="#1B4B68" transform="translate(834 420)"/>
```

### 式

```svg
<rect x="100" y="300" width="280" height="160" rx="12" fill="#ECF4F8"/>
<text x="240" y="355" font-size="22" fill="#2C4C60" text-anchor="middle">最初にかけた費用</text>
<text x="240" y="420" font-size="44" font-weight="700" fill="#1B4B68" text-anchor="middle">−10万円</text>
<text x="430" y="400" font-size="48" font-weight="700" fill="#909090" text-anchor="middle">＋</text>
<rect x="480" y="300" width="280" height="160" rx="12" fill="#ECF4F8"/>
<text x="620" y="355" font-size="22" fill="#2C4C60" text-anchor="middle">毎月の差し引き×12</text>
<text x="620" y="420" font-size="44" font-weight="700" fill="#1B4B68" text-anchor="middle">0円</text>
<text x="810" y="400" font-size="48" font-weight="700" fill="#909090" text-anchor="middle">＝</text>
<rect x="860" y="300" width="300" height="160" rx="12" fill="#FFFFFF" stroke="#DC1C18" stroke-width="4"/>
<text x="1010" y="355" font-size="22" fill="#2C4C60" text-anchor="middle">1年後の収支</text>
<text x="1010" y="420" font-size="44" font-weight="700" fill="#DC1C18" text-anchor="middle">−10万円</text>
```

### やり取り

登場する者を横に並べ（3〜4 者）、それぞれから下へ点線を伸ばす。登場する者は、ピルの代わりに場面の部品（人・ツール・サーバー）で描くとよい。そのときは部品を y=110〜280 に置き、名前を y=305、点線を y=320 から、やり取りを y=365 から 62 ずつ下げて並べる。やり取りは上から下へ時間の順に、横向きの矢印で描く。矢印の上に「何を渡すか」を書き、左端に順番の番号を振る。一番大事な 1 本だけ赤にする。やり取りは 5 本まで。それより多いなら 2 枚に分ける。

```svg
<defs>
  <marker id="f7-head" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4" markerHeight="4" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#0C6CA4"/></marker>
  <marker id="f7-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4" markerHeight="4" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#DC1C18"/></marker>
</defs>
<!-- 登場する者（x の中心：240 / 640 / 1040）-->
<rect x="130" y="140" width="220" height="56" rx="28" fill="#10547C"/>
<text x="240" y="177" font-size="26" font-weight="700" fill="#FFFFFF" text-anchor="middle">利用者</text>
<rect x="530" y="140" width="220" height="56" rx="28" fill="#10547C"/>
<text x="640" y="177" font-size="26" font-weight="700" fill="#FFFFFF" text-anchor="middle">ツール</text>
<rect x="930" y="140" width="220" height="56" rx="28" fill="#10547C"/>
<text x="1040" y="177" font-size="26" font-weight="700" fill="#FFFFFF" text-anchor="middle">サーバー</text>
<line x1="240" y1="196" x2="240" y2="660" stroke="#909090" stroke-width="2" stroke-dasharray="6 6"/>
<line x1="640" y1="196" x2="640" y2="660" stroke="#909090" stroke-width="2" stroke-dasharray="6 6"/>
<line x1="1040" y1="196" x2="1040" y2="660" stroke="#909090" stroke-width="2" stroke-dasharray="6 6"/>
<!-- やり取り 1 本の形：番号 → 矢印 → 矢印の上の字。y を 90 ずつ下げて並べる -->
<text x="70" y="288" font-size="24" font-weight="700" fill="#1B4B68">①</text>
<line x1="248" y1="280" x2="632" y2="280" stroke="#0C6CA4" stroke-width="5" marker-end="url(#f7-head)"/>
<text x="440" y="264" font-size="22" fill="#2C4C60" text-anchor="middle">連携を頼む</text>
<text x="70" y="378" font-size="24" font-weight="700" fill="#1B4B68">②</text>
<line x1="648" y1="370" x2="1032" y2="370" stroke="#0C6CA4" stroke-width="5" marker-end="url(#f7-head)"/>
<text x="840" y="354" font-size="22" fill="#2C4C60" text-anchor="middle">許可を求める</text>
<text x="70" y="468" font-size="24" font-weight="700" fill="#1B4B68">③</text>
<line x1="1032" y1="460" x2="648" y2="460" stroke="#DC1C18" stroke-width="5" marker-end="url(#f7-red)"/>
<text x="840" y="444" font-size="22" font-weight="700" fill="#DC1C18" text-anchor="middle">合言葉を渡す</text>
<!-- 自分の中で起きる処理は、線の横に小さな箱で書く -->
<rect x="660" y="510" width="260" height="56" rx="8" fill="#F4F8FC" stroke="#10547C" stroke-width="3"/>
<text x="790" y="546" font-size="22" font-weight="700" fill="#10547C" text-anchor="middle">合言葉を保管する</text>
```
