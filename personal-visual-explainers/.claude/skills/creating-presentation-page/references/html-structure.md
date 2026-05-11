# HTMLデザインガイド — 本気AIスタイル

## デザインテーマ: 本気AI（マジ図解）スタイル

本気AIブランドのカラーパレットを採用。ブルー×レッドのグラデーションヘッダーが特徴。

| 変数 | カラー | 用途 |
|-----|-------|------|
| `--majiai-primary` | `hsl(343, 85%, 45%)` | プライマリ（レッド系） |
| `--majiai-secondary` | `hsl(213, 63%, 38%)` | セカンダリ（ブルー系） |
| `--majiai-gradient` | `linear-gradient(90deg, #24609E, #D60C52)` | ヘッダー背景 |

---

## 基本テンプレート

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>【タイトル】 | 本気AI</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --majiai-primary: hsl(343, 85%, 45%);
      --majiai-secondary: hsl(213, 63%, 38%);
      --majiai-gradient: linear-gradient(90deg, #24609E, #D60C52);
    }
    body { font-family: 'Noto Sans JP', 'Inter', sans-serif; }

    .header-gradient { background: var(--majiai-gradient); }

    .section-card {
      background: white;
      border-radius: 1rem;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,.1);
      padding: 2rem;
      margin-bottom: 2rem;
    }

    /* キャラクター吹き出し */
    .char-bubble {
      position: relative;
      padding: 1.25rem 1.5rem;
      border-radius: 1rem;
      margin-left: 1rem;
    }
    .char-bubble::before {
      content: '';
      position: absolute;
      left: -10px;
      top: 20px;
      border-width: 10px;
      border-style: solid;
    }
    .maji-bubble {
      background: linear-gradient(135deg, #fef3c7, #fde68a);
      border: 2px solid #f59e0b;
    }
    .maji-bubble::before { border-color: transparent #f59e0b transparent transparent; }
    .master-bubble {
      background: linear-gradient(135deg, #dbeafe, #bfdbfe);
      border: 2px solid #3b82f6;
    }
    .master-bubble::before { border-color: transparent #3b82f6 transparent transparent; }

    /* 用語解説ボックス */
    .term-explain {
      background: linear-gradient(135deg, #f3e8ff, #e9d5ff);
      border-left: 4px solid #9333ea;
      padding: 1.25rem 1.5rem;
      border-radius: 0.75rem;
      margin: 1rem 0;
    }

    /* ポイントカード */
    .point-card {
      background: white;
      border-radius: 0.875rem;
      border: 1px solid #e5e7eb;
      padding: 1.25rem 1.5rem;
      transition: box-shadow .2s;
    }
    .point-card:hover { box-shadow: 0 4px 12px rgba(0,0,0,.08); }

    /* ステップフロー */
    .step-flow { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
    .step-box { padding: 0.5rem 1rem; border-radius: 0.5rem; font-weight: 600; font-size: 0.875rem; }
    .step-arrow { color: #9ca3af; font-size: 1.25rem; }

    /* スティッキーナビ */
    .sticky-nav {
      position: fixed;
      top: 50%;
      right: 1.5rem;
      transform: translateY(-50%);
      background: white;
      border-radius: 0.75rem;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,.1);
      padding: 1rem;
      z-index: 50;
    }
    @media (max-width: 1280px) { .sticky-nav { display: none; } }

    /* ざっくり一言カード */
    .summary-card {
      background: linear-gradient(135deg, #1e3a5f, #2d5a8e);
      color: white;
      border-radius: 1rem;
      padding: 1.5rem 2rem;
      margin-bottom: 2rem;
    }

    /* Before/After比較 */
    .before-card { background: #fef2f2; border: 2px solid #fca5a5; border-radius: 0.75rem; padding: 1.25rem; }
    .after-card  { background: #f0fdf4; border: 2px solid #86efac; border-radius: 0.75rem; padding: 1.25rem; }

    /* バッジ */
    .badge-essential   { background: linear-gradient(135deg, #dc2626, #ef4444); color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .badge-recommended { background: linear-gradient(135deg, #2563eb, #3b82f6); color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .badge-optional    { background: linear-gradient(135deg, #6b7280, #9ca3af); color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
  </style>
</head>
<body class="bg-gray-50">

  <!-- スティッキーナビ -->
  <nav class="sticky-nav">
    <p class="text-xs text-gray-500 font-bold mb-2">目次</p>
    <ul class="space-y-1 text-sm">
      <li><a href="#intro"    class="text-gray-600 hover:text-blue-600 block">背景</a></li>
      <li><a href="#section1" class="text-gray-600 hover:text-blue-600 block">セクション1</a></li>
      <li><a href="#section2" class="text-gray-600 hover:text-blue-600 block">セクション2</a></li>
      <li><a href="#summary"  class="text-gray-600 hover:text-blue-600 block">まとめ</a></li>
    </ul>
  </nav>

  <!-- ヘッダー -->
  <header class="header-gradient text-white py-10">
    <div class="max-w-3xl mx-auto px-4">
      <p class="text-sm opacity-75 mb-1">【イベント名・文脈】</p>
      <h1 class="text-3xl md:text-4xl font-bold mb-2">【メインタイトル】</h1>
      <p class="opacity-90">【サブタイトル：伝えたい内容のひと言まとめ】</p>
      <div class="flex gap-2 mt-4 flex-wrap">
        <span class="bg-white bg-opacity-20 px-3 py-1 rounded-full text-sm">【タグ1】</span>
        <span class="bg-white bg-opacity-20 px-3 py-1 rounded-full text-sm">【タグ2】</span>
      </div>
    </div>
  </header>

  <!-- メインコンテンツ -->
  <main class="max-w-3xl mx-auto px-4 py-8">

    <!-- ざっくり一言 -->
    <div class="summary-card">
      <p class="text-sm opacity-75 mb-1">ざっくり一言</p>
      <p class="text-xl font-bold">「【30字以内で本質を一言】」</p>
    </div>

    <!-- 背景セクション -->
    <section id="intro" class="section-card">
      <!-- キャラクター対話 -->
      <!-- 本文 -->
      <!-- 3カード（使う人・使う場面・ゴール） -->
    </section>

    <!-- 本論セクション群 -->
    <section id="section1" class="section-card">
      <!-- セクションヘッダー（Lucide icon + タイトル） -->
      <!-- キャラクター対話（任意） -->
      <!-- 本文コンテンツ -->
    </section>

    <!-- まとめ -->
    <section id="summary" class="section-card">
      <!-- キャラクター対話 -->
      <!-- 持ち帰ってほしい3点 -->
    </section>

  </main>

  <!-- フッター -->
  <footer class="header-gradient text-white py-6 mt-8">
    <div class="max-w-3xl mx-auto px-4 text-center text-sm opacity-80">
      【イベント名】/ 本気AI — 【年月】
    </div>
  </footer>

  <script>lucide.createIcons();</script>
</body>
</html>
```

---

## キャラクター画像

画像は `images/` ディレクトリに配置する。以下のファイルが利用可能（コピー元: `output/skill-journey/images/`）。

### マジくん（読者の疑問役）

| ファイル名 | 使いどころ |
|-----------|-----------|
| `マジくん-標準-512×512-透過.png` | 普通の発言・相槌 |
| `マジくん-疑っている-512×512-透過.png` | 「本当に？」な疑問 |
| `マジくん-マジ？-512×512-透過.png` | 驚き・意外な発見 |
| `マジくん-調子に乗ってる-512×512-透過.png` | 理解して得意げ |
| `マジくん-焦り-512×512-透過.png` | 失敗・困惑 |
| `マジくん-驚き-512×512-透過.png` | 衝撃の事実 |

### マスター（本質を語る導き手）

| ファイル名 | 使いどころ |
|-----------|-----------|
| `マスター-標準-512×512-透過.png` | 普通の説明 |
| `マスター-諭す-512×512-透過.png` | 大切なことを伝えるとき |
| `マスター-思考、分析-512×512-透過.png` | 考えながら説明するとき |
| `マスター-真顔-512×512-透過.png` | 厳しいことを言うとき |

---

## キャラクター対話のHTMLパターン

```html
<!-- マジくん → マスターの1往復 -->
<div class="flex items-start gap-3 mb-4">
  <img src="images/マジくん-疑っている-512×512-透過.png" alt="マジくん" class="w-14 h-14 object-contain flex-shrink-0">
  <div>
    <p class="text-xs font-bold text-amber-600 mb-1">マジくん</p>
    <div class="char-bubble maji-bubble">
      <p class="text-sm">【マジくんのセリフ：読者の疑問を代弁】</p>
    </div>
  </div>
</div>
<div class="flex items-start gap-3 mb-6">
  <img src="images/マスター-諭す-512×512-透過.png" alt="マスター" class="w-14 h-14 object-contain flex-shrink-0">
  <div>
    <p class="text-xs font-bold text-blue-600 mb-1">マスター</p>
    <div class="char-bubble master-bubble">
      <p class="text-sm">【マスターのセリフ：本質・Whyを説明】</p>
    </div>
  </div>
</div>
```

---

## 3カード（使う人・使う場面・ゴール）

```html
<div class="grid md:grid-cols-3 gap-4 mt-6">
  <div class="point-card text-center">
    <div class="w-10 h-10 bg-blue-100 rounded-xl flex items-center justify-center mx-auto mb-3">
      <i data-lucide="user" class="w-5 h-5 text-blue-600"></i>
    </div>
    <p class="text-xs text-gray-500 mb-1">使う人</p>
    <p class="font-bold text-sm text-gray-800">【対象者の一言説明】</p>
  </div>
  <div class="point-card text-center">
    <div class="w-10 h-10 bg-green-100 rounded-xl flex items-center justify-center mx-auto mb-3">
      <i data-lucide="map-pin" class="w-5 h-5 text-green-600"></i>
    </div>
    <p class="text-xs text-gray-500 mb-1">使う場面</p>
    <p class="font-bold text-sm text-gray-800">【具体的な場面】</p>
  </div>
  <div class="point-card text-center">
    <div class="w-10 h-10 bg-purple-100 rounded-xl flex items-center justify-center mx-auto mb-3">
      <i data-lucide="target" class="w-5 h-5 text-purple-600"></i>
    </div>
    <p class="text-xs text-gray-500 mb-1">ゴール</p>
    <p class="font-bold text-sm text-gray-800">【読んだ後の状態】</p>
  </div>
</div>
```

---

## まとめの「持ち帰ってほしい3点」

```html
<div class="space-y-4 mt-6">
  <div class="flex gap-4 items-start point-card">
    <span class="text-2xl font-black text-blue-600 flex-shrink-0">1</span>
    <p class="text-gray-800"><strong>【ポイント1の太字タイトル】</strong> 【補足説明】</p>
  </div>
  <div class="flex gap-4 items-start point-card">
    <span class="text-2xl font-black text-blue-600 flex-shrink-0">2</span>
    <p class="text-gray-800"><strong>【ポイント2の太字タイトル】</strong> 【補足説明】</p>
  </div>
  <div class="flex gap-4 items-start point-card">
    <span class="text-2xl font-black text-blue-600 flex-shrink-0">3</span>
    <p class="text-gray-800"><strong>【ポイント3の太字タイトル】</strong> 【補足説明】</p>
  </div>
</div>
```

---

## セクションヘッダー（Lucide icon + タイトル）

```html
<div class="flex items-center gap-3 mb-6">
  <div class="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center">
    <i data-lucide="lightbulb" class="w-6 h-6 text-blue-600"></i>
  </div>
  <div>
    <h2 class="text-2xl font-bold text-gray-800">【セクションタイトル】</h2>
    <p class="text-gray-500 text-sm">【サブ説明（任意）】</p>
  </div>
</div>
```

---

## よく使う Lucide アイコン

| 用途 | アイコン名 |
|-----|-----------|
| 背景・目的 | `target`, `map-pin`, `compass` |
| 工夫・アイデア | `lightbulb`, `sparkles`, `wand` |
| 構成・設計 | `layout`, `layers`, `grid` |
| デザイン | `palette`, `pen-tool`, `image` |
| まとめ | `check-circle`, `award`, `flag` |
| 重要 | `alert-circle`, `star` |
| ユーザー | `user`, `users` |
| ループ・改善 | `refresh-cw`, `trending-up` |
| Before/After | `x-circle`, `check-circle` |
