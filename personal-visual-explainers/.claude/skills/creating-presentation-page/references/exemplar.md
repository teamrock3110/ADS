# 成功パターン集

## 模範ページ

**スキル育て日記** — 実際に本スキルで作成した発表ページ。
- URL: https://diagram-skill-journey.surge.sh
- ソース: `output/skill-journey/index.html`

このページを「正解の形」として参照する。

---

## ページ全体の構成パターン

### 標準4セクション構成

```
[ヘッダー]
  ├── イベント名・文脈
  ├── メインタイトル
  ├── サブタイトル
  └── タグバッジ2〜3個

[ざっくり一言カード]（紺背景・白文字・30字以内）

[背景セクション]
  ├── マジくん＆マスターの対話（なぜ取り組んだか）
  └── 3カード：使う人 / 使う場面 / ゴール

[本論セクション × 2〜3]
  ├── セクションヘッダー（Lucide icon）
  ├── 工夫・学びのポイントを展開
  └── （任意）マジくん＆マスターの対話

[まとめセクション]
  ├── マスターの締めの言葉
  └── 持ち帰ってほしい3点

[フッター]
```

---

## 「ざっくり一言」の成功例・失敗例

### ✅ 成功例

```
「ダメなスキルをFBで育てたら、使える図解ツールになった」
（29字）
```

- 結果（何が起きたか）が明確
- 主人公（誰の話か）が明確
- 読んだ後の「へぇ」が想像できる

### ❌ 失敗例

```
「パーソナル図解スキルの作成における工夫点について」
```

- タイトルの言い換えになっていて、新情報がない
- 30字を超えている（37字）
- 「何がすごいのか」が伝わらない

---

## 背景セクションの対話パターン

「なぜ取り組んだか」「誰が使うのか」を対話で自然に引き出す。

```html
<!-- マジくんが「なぜ？」を聞く → マスターが目的を説明 -->
<div class="flex items-start gap-3 mb-4">
  <img src="images/マジくん-疑っている-512×512-透過.png" alt="マジくん" class="w-14 h-14 object-contain flex-shrink-0">
  <div>
    <p class="text-xs font-bold text-amber-600 mb-1">マジくん</p>
    <div class="char-bubble maji-bubble">
      <p class="text-sm">「〇〇向け」って書いてありますけど、具体的にどんな場面で使うんですか？</p>
    </div>
  </div>
</div>
<div class="flex items-start gap-3 mb-6">
  <img src="images/マスター-諭す-512×512-透過.png" alt="マスター" class="w-14 h-14 object-contain flex-shrink-0">
  <div>
    <p class="text-xs font-bold text-blue-600 mb-1">マスター</p>
    <div class="char-bubble master-bubble">
      <p class="text-sm">「〇〇なとき」のためのスキルです。<br>
      ゴールは「□□できる状態」——それが狙いです。</p>
    </div>
  </div>
</div>
```

---

## 本論セクションの対話パターン

「意外だった発見」「なぜそうしたか」を対話で掘り下げる。

```html
<!-- マジくんが驚く → マスターがWhyを説明 -->
<div class="flex items-start gap-3 mb-4">
  <img src="images/マジくん-マジ？-512×512-透過.png" alt="マジくん" class="w-14 h-14 object-contain flex-shrink-0">
  <div>
    <p class="text-xs font-bold text-amber-600 mb-1">マジくん</p>
    <div class="char-bubble maji-bubble">
      <p class="text-sm">〇〇を参考にしたと聞きましたが、具体的にどういう方法を使ったんですか？</p>
    </div>
  </div>
</div>
<div class="flex items-start gap-3 mb-6">
  <img src="images/マスター-思考、分析-512×512-透過.png" alt="マスター" class="w-14 h-14 object-contain flex-shrink-0">
  <div>
    <p class="text-xs font-bold text-blue-600 mb-1">マスター</p>
    <div class="char-bubble master-bubble">
      <p class="text-sm">〇〇するだけでデザインが一変しました。<br>
      <strong>△△しにくいものは、□□が最も確実な方法です。</strong></p>
    </div>
  </div>
</div>
```

---

## まとめセクションの対話パターン

マジくんが学びを整理 → マスターが一言で締める。

```html
<div class="flex items-start gap-3 mb-4">
  <img src="images/マジくん-調子に乗ってる-512×512-透過.png" alt="マジくん" class="w-14 h-14 object-contain flex-shrink-0">
  <div>
    <p class="text-xs font-bold text-amber-600 mb-1">マジくん</p>
    <div class="char-bubble maji-bubble">
      <p class="text-sm">なるほど！つまり「〇〇 ＋ △△」のセットで動かすのが大事なんですね！</p>
    </div>
  </div>
</div>
<div class="flex items-start gap-3 mb-6">
  <img src="images/マスター-標準-512×512-透過.png" alt="マスター" class="w-14 h-14 object-contain flex-shrink-0">
  <div>
    <p class="text-xs font-bold text-blue-600 mb-1">マスター</p>
    <div class="char-bubble master-bubble">
      <p class="text-sm">〇〇は「作って終わり」ではなく「△△するもの」です。<br>
      <strong>□□のループを速く回す</strong>ほうが、最初から完璧を目指すより精度が上がります。</p>
    </div>
  </div>
</div>
```

---

## Before/After 比較パターン

工夫の「前後の差」を視覚的に見せる。

```html
<div class="grid md:grid-cols-2 gap-4 my-6">
  <div class="before-card">
    <p class="font-bold text-red-700 mb-3 flex items-center gap-2">
      <i data-lucide="x-circle" class="w-4 h-4"></i> Before
    </p>
    <!-- Before の内容 -->
    <ul class="text-sm text-gray-700 space-y-1 mt-3">
      <li>・問題点1</li>
      <li>・問題点2</li>
    </ul>
  </div>
  <div class="after-card">
    <p class="font-bold text-green-700 mb-3 flex items-center gap-2">
      <i data-lucide="check-circle" class="w-4 h-4"></i> After（改善後）
    </p>
    <!-- After の内容 -->
    <ul class="text-sm text-gray-700 space-y-1 mt-3">
      <li>・改善点1</li>
      <li>・改善点2</li>
    </ul>
  </div>
</div>
```

---

## ステップフロー（改善ループなど）

プロセスや流れを横並びで見せる。

```html
<div class="step-flow my-6">
  <div class="step-box bg-blue-100 text-blue-800">生成</div>
  <span class="step-arrow">→</span>
  <div class="step-box bg-amber-100 text-amber-800">FBを出す</div>
  <span class="step-arrow">→</span>
  <div class="step-box bg-purple-100 text-purple-800">改善案を出す</div>
  <span class="step-arrow">→</span>
  <div class="step-box bg-green-100 text-green-800">スキルに反映</div>
  <span class="step-arrow">→</span>
  <span class="text-gray-400 text-sm">くり返す…</span>
</div>
```

---

## 実際の会話を引用するパターン

「黄金パターン」など抽象的な概念に、実際の例を添える。

```html
<!-- 実際の送信例パネル -->
<div class="bg-gray-50 border border-gray-200 rounded-xl p-4 mt-4">
  <p class="text-xs font-bold text-gray-500 mb-3 flex items-center gap-1">
    <i data-lucide="message-square" class="w-3 h-3"></i> 実際の送信例
  </p>
  <!-- 自分の発言 -->
  <div class="flex justify-end mb-3">
    <div class="bg-blue-600 text-white rounded-xl rounded-br-sm px-4 py-2 text-sm max-w-xs">
      「この表現は読み手がイメージしにくいと感じた。<strong>具体例がないからだと思う</strong>のですが、あなたの改善案も聞かせてください」
    </div>
  </div>
  <!-- AIの返答 -->
  <div class="flex gap-2 mb-3">
    <div class="w-7 h-7 bg-gray-300 rounded-full flex items-center justify-center flex-shrink-0 text-xs font-bold">AI</div>
    <div class="bg-white border border-gray-200 rounded-xl rounded-bl-sm px-4 py-2 text-sm max-w-xs">
      「具体例不足はその通りです。加えて ①〇〇 ②△△ ③□□ の3点も原因と考えます」
    </div>
  </div>
  <p class="text-xs text-gray-500 text-center mt-2">自分の仮説にプラスαの視点が返ってきた。あとは「どれを採用するか」の判断のみ。</p>
</div>
```

---

## 品質チェック：ざっくり一言の検証

生成後に必ず確認する。

| チェック項目 | OK例 | NG例 |
|------------|------|------|
| 30字以内か | 「FBで育てたら使えるツールになった」（18字）✅ | 「パーソナル図解スキルを作成する際の工夫点」（22字）△ |
| 新情報があるか | 結果・発見が含まれている ✅ | タイトルの言い換えになっている ❌ |
| 「へぇ」と思えるか | 意外性・発見感がある ✅ | 当たり前のことしか言っていない ❌ |

---

## NG パターン

### ❌ 対話が質問のくり返しになっている

```
マジくん：「この図解ってどういうものですか？」
マスター：「これは〇〇という図解です」
マジくん：「なるほど。つまり〇〇ということですか？」
マスター：「そうです、〇〇です」
```

→ **Fix**: マジくんは1往復に1つの疑問だけ。マスターは答えた後にもう1歩「Why」まで踏み込む。

### ❌ まとめの3点がふわっとしている

```
1. 大事なことをやる
2. 丁寧に進める
3. 振り返りをする
```

→ **Fix**: 「何を / どう / なぜ」の型で書く。
例: `スキルは育てるもの。最初の出力に一喜一憂せず、FB × 改善ループを速く回す`
