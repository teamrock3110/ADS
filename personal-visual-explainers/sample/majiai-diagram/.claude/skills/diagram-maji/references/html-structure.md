# HTML構造ガイド

## 基本テンプレート

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>【図解タイトル】- 本気AI</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    /* 本気AIブランドカラー */
    :root {
      --majiai-primary: hsl(343, 85%, 45%);
      --majiai-secondary: hsl(213, 63%, 38%);
      --majiai-gradient: linear-gradient(90deg, #24609E, #D60C52);
    }
    
    body {
      font-family: 'Noto Sans JP', 'Inter', sans-serif;
    }

    /* ヘッダーグラデーション */
    .header-gradient {
      background: var(--majiai-gradient);
    }

    /* セクションカード */
    .section-card {
      background: white;
      border-radius: 1rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
      padding: 2rem;
      margin-bottom: 2rem;
    }

    /* 用語解説ボックス */
    .term-explain {
      background: linear-gradient(135deg, #f3e8ff 0%, #e9d5ff 100%);
      border-left: 4px solid #9333ea;
      padding: 1.5rem;
      border-radius: 0.75rem;
      margin: 1.5rem 0;
    }

    /* キャラクター吹き出し */
    .char-bubble {
      position: relative;
      padding: 1.5rem;
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
      background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
      border: 2px solid #f59e0b;
    }
    .maji-bubble::before {
      border-color: transparent #f59e0b transparent transparent;
    }
    .master-bubble {
      background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
      border: 2px solid #3b82f6;
    }
    .master-bubble::before {
      border-color: transparent #3b82f6 transparent transparent;
    }

    /* 重要度バッジ */
    .badge-essential {
      background: linear-gradient(135deg, #dc2626 0%, #ef4444 100%);
      color: white;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.875rem;
      font-weight: 600;
    }
    .badge-recommended {
      background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
      color: white;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.875rem;
      font-weight: 600;
    }
    .badge-optional {
      background: linear-gradient(135deg, #6b7280 0%, #9ca3af 100%);
      color: white;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.875rem;
      font-weight: 600;
    }

    /* コードブロック */
    .code-block {
      background: #1e293b;
      color: #e2e8f0;
      padding: 1.5rem;
      border-radius: 0.75rem;
      overflow-x: auto;
      font-family: 'Fira Code', monospace;
      font-size: 0.875rem;
      line-height: 1.7;
    }

    /* 目次 */
    .toc {
      position: fixed;
      right: 2rem;
      top: 50%;
      transform: translateY(-50%);
      background: white;
      padding: 1rem;
      border-radius: 0.75rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
      max-height: 80vh;
      overflow-y: auto;
      z-index: 50;
    }
    @media (max-width: 1280px) {
      .toc { display: none; }
    }
  </style>
</head>
<body class="bg-gray-50">
  <!-- ヘッダー -->
  <header class="header-gradient text-white py-8">
    <div class="max-w-4xl mx-auto px-4">
      <h1 class="text-3xl md:text-4xl font-bold">【タイトル】</h1>
      <p class="mt-2 text-lg opacity-90">サブタイトル</p>
    </div>
  </header>

  <!-- メインコンテンツ -->
  <main class="max-w-4xl mx-auto px-4 py-8">
    <!-- セクション例 -->
  </main>

  <!-- Lucide初期化 -->
  <script>
    lucide.createIcons();
  </script>
</body>
</html>
```

---

## Lucide Icon の使い方

### 基本構文

```html
<i data-lucide="icon-name" class="w-6 h-6"></i>
```

### よく使うアイコン

| 用途 | アイコン名 | コード |
|-----|----------|--------|
| 重要 | `alert-circle` | `<i data-lucide="alert-circle" class="w-6 h-6 text-red-500"></i>` |
| ヒント | `lightbulb` | `<i data-lucide="lightbulb" class="w-6 h-6 text-yellow-500"></i>` |
| チェック | `check-circle` | `<i data-lucide="check-circle" class="w-6 h-6 text-green-500"></i>` |
| 情報 | `info` | `<i data-lucide="info" class="w-6 h-6 text-blue-500"></i>` |
| 警告 | `triangle-alert` | `<i data-lucide="triangle-alert" class="w-6 h-6 text-orange-500"></i>` |
| 設定 | `settings` | `<i data-lucide="settings" class="w-6 h-6 text-gray-500"></i>` |
| コード | `code` | `<i data-lucide="code" class="w-6 h-6 text-purple-500"></i>` |
| ファイル | `file-text` | `<i data-lucide="file-text" class="w-6 h-6 text-blue-500"></i>` |
| フォルダ | `folder` | `<i data-lucide="folder" class="w-6 h-6 text-yellow-600"></i>` |
| 矢印 | `arrow-right` | `<i data-lucide="arrow-right" class="w-6 h-6"></i>` |
| ユーザー | `user` | `<i data-lucide="user" class="w-6 h-6"></i>` |
| ロック | `lock` | `<i data-lucide="lock" class="w-6 h-6 text-gray-600"></i>` |
| 鍵 | `key` | `<i data-lucide="key" class="w-6 h-6 text-yellow-500"></i>` |
| 許可 | `shield-check` | `<i data-lucide="shield-check" class="w-6 h-6 text-green-500"></i>` |
| 禁止 | `shield-x` | `<i data-lucide="shield-x" class="w-6 h-6 text-red-500"></i>` |
| 質問 | `help-circle` | `<i data-lucide="help-circle" class="w-6 h-6 text-blue-500"></i>` |
| 本 | `book-open` | `<i data-lucide="book-open" class="w-6 h-6 text-indigo-500"></i>` |
| 学習 | `graduation-cap` | `<i data-lucide="graduation-cap" class="w-6 h-6 text-purple-500"></i>` |
| ツール | `wrench` | `<i data-lucide="wrench" class="w-6 h-6 text-gray-600"></i>` |
| プレイ | `play` | `<i data-lucide="play" class="w-6 h-6 text-green-500"></i>` |
| 停止 | `square` | `<i data-lucide="square" class="w-6 h-6 text-red-500"></i>` |

### セクションヘッダーでの使用例

```html
<div class="section-card">
  <div class="flex items-center gap-3 mb-6">
    <div class="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center">
      <i data-lucide="shield-check" class="w-6 h-6 text-blue-600"></i>
    </div>
    <div>
      <h2 class="text-2xl font-bold text-gray-800">セクションタイトル</h2>
      <p class="text-gray-500">サブタイトル</p>
    </div>
  </div>
  <!-- コンテンツ -->
</div>
```

---

## コード例の前の日本語解説

コードを見せる前に、必ず「このコードが何をするのか」を日本語で説明する。

### ❌ 悪い例

```html
<div class="code-block">
  <pre><code>
hook.onPreToolUse((event) => {
  if (event.toolName === 'Write') {
    return { permissionDecision: 'deny' };
  }
});
  </code></pre>
</div>
```

### ✅ 良い例

```html
<div class="mb-4">
  <div class="flex items-center gap-2 mb-2">
    <i data-lucide="code" class="w-5 h-5 text-purple-500"></i>
    <span class="font-bold text-gray-700">このコードがやること</span>
  </div>
  <p class="text-gray-600 ml-7">
    「Writeツール（ファイルを書き込む道具）が使われそうになったら、
    <span class="font-bold text-red-600">許可しない</span>」というルールを設定しています。
  </p>
</div>
<div class="code-block">
  <pre><code>
hook.onPreToolUse((event) => {
  if (event.toolName === 'Write') {
    return { permissionDecision: 'deny' };
  }
});
  </code></pre>
</div>
```

---

## フローチャートの表現

```html
<div class="flex flex-col md:flex-row items-center justify-center gap-4 my-8">
  <div class="bg-blue-100 px-6 py-4 rounded-xl text-center">
    <i data-lucide="play" class="w-8 h-8 text-blue-600 mx-auto mb-2"></i>
    <div class="font-bold">開始</div>
  </div>
  <i data-lucide="arrow-right" class="w-8 h-8 text-gray-400 hidden md:block"></i>
  <i data-lucide="arrow-down" class="w-8 h-8 text-gray-400 md:hidden"></i>
  <div class="bg-yellow-100 px-6 py-4 rounded-xl text-center">
    <i data-lucide="shield-check" class="w-8 h-8 text-yellow-600 mx-auto mb-2"></i>
    <div class="font-bold">チェック</div>
  </div>
  <i data-lucide="arrow-right" class="w-8 h-8 text-gray-400 hidden md:block"></i>
  <i data-lucide="arrow-down" class="w-8 h-8 text-gray-400 md:hidden"></i>
  <div class="bg-green-100 px-6 py-4 rounded-xl text-center">
    <i data-lucide="check-circle" class="w-8 h-8 text-green-600 mx-auto mb-2"></i>
    <div class="font-bold">完了</div>
  </div>
</div>
```
