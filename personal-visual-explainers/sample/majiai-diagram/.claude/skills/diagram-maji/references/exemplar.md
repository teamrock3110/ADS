# 模範解答パターン

## 成功する図解の構造

```
1. ヘッダー（グラデーション背景）
   └─ タイトル + サブタイトル

2. 導入（キャラクター対話）
   └─ マジくん: 「〇〇って何ですか？」
   └─ マスター: たとえ話で概要説明

3. 用語解説ボックス
   └─ 最初に出てくる技術用語を全て解説

4. まず覚える3つ
   └─ 絞り込んだ最重要ポイント
   └─ 重要度バッジ（必須/推奨/任意）

5. 各セクション詳細
   └─ セクションカード形式
   └─ Lucide iconでビジュアル化
   └─ たとえ話で補足
   └─ コード例の前に日本語解説

6. まとめ（キャラクター対話）
   └─ マスター: 要点を3つで整理
   └─ マジくん: 理解の確認

7. 目次（フローティング）
   └─ デスクトップのみ表示
```

---

## 「まず覚える3つ」の書き方

```html
<div class="section-card">
  <div class="flex items-center gap-3 mb-6">
    <div class="w-12 h-12 bg-gradient-to-br from-rose-500 to-pink-500 rounded-xl flex items-center justify-center">
      <i data-lucide="star" class="w-6 h-6 text-white"></i>
    </div>
    <div>
      <h2 class="text-2xl font-bold text-gray-800">まず覚える3つ</h2>
      <p class="text-gray-500">最初はこれだけでOK！</p>
    </div>
  </div>

  <div class="grid gap-4">
    <!-- 1つ目 -->
    <div class="flex items-start gap-4 p-4 bg-gradient-to-r from-red-50 to-red-100 rounded-xl border-l-4 border-red-500">
      <div class="w-10 h-10 bg-red-500 text-white rounded-full flex items-center justify-center font-bold text-lg flex-shrink-0">1</div>
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold text-lg text-gray-800">PreToolUse</span>
          <span class="badge-essential">必須</span>
        </div>
        <p class="text-gray-600">ツールが実行される<strong>前</strong>にチェック。「本当にやっていい？」と確認する門番。</p>
      </div>
    </div>

    <!-- 2つ目 -->
    <div class="flex items-start gap-4 p-4 bg-gradient-to-r from-blue-50 to-blue-100 rounded-xl border-l-4 border-blue-500">
      <div class="w-10 h-10 bg-blue-500 text-white rounded-full flex items-center justify-center font-bold text-lg flex-shrink-0">2</div>
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold text-lg text-gray-800">PostToolUse</span>
          <span class="badge-recommended">推奨</span>
        </div>
        <p class="text-gray-600">ツールが実行された<strong>後</strong>に確認。結果をログに残したり、通知を送ったり。</p>
      </div>
    </div>

    <!-- 3つ目 -->
    <div class="flex items-start gap-4 p-4 bg-gradient-to-r from-green-50 to-green-100 rounded-xl border-l-4 border-green-500">
      <div class="w-10 h-10 bg-green-500 text-white rounded-full flex items-center justify-center font-bold text-lg flex-shrink-0">3</div>
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold text-lg text-gray-800">Stop</span>
          <span class="badge-optional">任意</span>
        </div>
        <p class="text-gray-600">AIが作業を終えるとき。「お疲れ様、次はこれをやってね」とフォローアップを追加。</p>
      </div>
    </div>
  </div>
</div>
```

---

## たとえ話の展開パターン

### パターン1: 会社のセキュリティゲート

```html
<div class="bg-gradient-to-r from-amber-50 to-orange-50 p-6 rounded-xl border border-amber-200 my-6">
  <div class="flex items-center gap-2 mb-3">
    <i data-lucide="building-2" class="w-6 h-6 text-amber-600"></i>
    <span class="font-bold text-amber-800">たとえ話：会社のセキュリティゲート</span>
  </div>
  <div class="space-y-3 text-gray-700">
    <p>あなたが会社に出勤するとき、入口にはセキュリティゲートがありますよね。</p>
    <ul class="list-disc list-inside space-y-1 ml-2">
      <li><strong>社員証をかざす</strong> → 本人確認（PreToolUse）</li>
      <li><strong>ゲートが開く</strong> → 許可された行動が実行される</li>
      <li><strong>入館記録が残る</strong> → ログ記録（PostToolUse）</li>
    </ul>
    <p>フックは、この<strong>セキュリティゲートのような役割</strong>をプログラムの中で果たします。</p>
  </div>
</div>
```

### パターン2: スマホの権限ダイアログ

```html
<div class="bg-gradient-to-r from-blue-50 to-indigo-50 p-6 rounded-xl border border-blue-200 my-6">
  <div class="flex items-center gap-2 mb-3">
    <i data-lucide="smartphone" class="w-6 h-6 text-blue-600"></i>
    <span class="font-bold text-blue-800">たとえ話：スマホの権限ダイアログ</span>
  </div>
  <div class="space-y-3 text-gray-700">
    <p>スマホでアプリを使うとき、こんな画面を見たことありませんか？</p>
    <div class="bg-white p-4 rounded-lg border text-center my-3">
      「カメラへのアクセスを許可しますか？」<br>
      <span class="text-blue-600">[許可する]</span> / <span class="text-gray-500">[許可しない]</span>
    </div>
    <p>これがまさに<strong>PreToolUse</strong>の動き！</p>
    <ul class="list-disc list-inside space-y-1 ml-2">
      <li><strong>許可する</strong> → allow（実行OK）</li>
      <li><strong>許可しない</strong> → deny（実行NG）</li>
      <li><strong>毎回確認する</strong> → ask（ユーザーに聞く）</li>
    </ul>
  </div>
</div>
```

---

## 詳細セクションの書き方

```html
<div class="section-card" id="pretooluse">
  <!-- セクションヘッダー -->
  <div class="flex items-center gap-3 mb-6">
    <div class="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center">
      <i data-lucide="shield-check" class="w-6 h-6 text-blue-600"></i>
    </div>
    <div>
      <h2 class="text-2xl font-bold text-gray-800">PreToolUse</h2>
      <p class="text-gray-500">ツール実行前のチェックポイント</p>
    </div>
  </div>

  <!-- キャラクター対話 -->
  <div class="flex items-start gap-4 mb-6">
    <img src="./images/マジくん-疑っている-512×512-透過.png" 
         alt="マジくん" class="w-16 h-16 object-contain flex-shrink-0">
    <div class="char-bubble maji-bubble flex-1">
      <p>「Pre」って「前」という意味ですよね？つまり、ツールを使う前に何かするってことですか？</p>
    </div>
  </div>

  <div class="flex items-start gap-4 mb-6">
    <img src="./images/マスター-諭す-512×512-透過.png" 
         alt="マスター" class="w-16 h-16 object-contain flex-shrink-0">
    <div class="char-bubble master-bubble flex-1">
      <p>その通りです。AIが何かツールを使おうとしたとき、<strong>実行する前に「ちょっと待って」と割り込める</strong>ポイントです。</p>
    </div>
  </div>

  <!-- 本文 -->
  <div class="space-y-4">
    <h3 class="text-xl font-bold text-gray-700 flex items-center gap-2">
      <i data-lucide="target" class="w-5 h-5 text-blue-500"></i>
      何ができるの？
    </h3>
    <ul class="space-y-2">
      <li class="flex items-start gap-2">
        <i data-lucide="check" class="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5"></i>
        <span>特定のツールの使用を<strong>禁止</strong>できる</span>
      </li>
      <li class="flex items-start gap-2">
        <i data-lucide="check" class="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5"></i>
        <span>ツールに渡す<strong>入力内容を変更</strong>できる</span>
      </li>
      <li class="flex items-start gap-2">
        <i data-lucide="check" class="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5"></i>
        <span>ユーザーに<strong>確認を求める</strong>ことができる</span>
      </li>
    </ul>
  </div>

  <!-- コード例 -->
  <div class="mt-6">
    <div class="flex items-center gap-2 mb-2">
      <i data-lucide="code" class="w-5 h-5 text-purple-500"></i>
      <span class="font-bold text-gray-700">このコードがやること</span>
    </div>
    <p class="text-gray-600 mb-3">
      「Writeツール（ファイルを書き込む道具）」が使われそうになったら、
      <span class="font-bold text-red-600">許可しない</span>というルールを設定しています。
    </p>
    <div class="code-block">
      <pre><code>hook.onPreToolUse((event) => {
  if (event.toolName === 'Write') {
    return { permissionDecision: 'deny' };
  }
});</code></pre>
    </div>
  </div>
</div>
```

---

## 品質チェックリスト

作成後、以下を確認：

- [ ] 全ての技術用語に用語解説ボックスがある
- [ ] たとえ話が3つ以上ある
- [ ] 導入・中間・まとめにキャラクター対話がある
- [ ] 「まず覚える3つ」がある
- [ ] コード例の前に「このコードがやること」がある
- [ ] Lucide iconのみ使用（絵文字なし）
- [ ] 本気AIブランドカラーが適用されている
- [ ] キャラクター画像のパスが正しい
- [ ] スマホで読みやすい（レスポンシブ）
- [ ] 目次がフローティング表示される（デスクトップ）
