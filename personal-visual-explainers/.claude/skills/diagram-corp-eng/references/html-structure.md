# HTMLデザインガイド

## デザインテーマ: ADS スタイル

Tailwind CSS + Lucide Icons + ADS配色を使用。
**このスタイルをデフォルトとして使う。**

---

## ベーステンプレート（額縁）

毎回このHTMLから始める。`<!-- CONTENT_START -->` と `<!-- CONTENT_END -->` の間にコンテンツを挿入する。

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
  <title>【図解タイトル】</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700;900&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            ads: {
              bg: '#FFFFFF',
              surface: '#F8FAFC',
              hover: '#F1F5F9',
              border: '#E2E8F0',
              accent: '#3B82F6',
              'accent-light': '#2563EB',
              text: '#1E293B',
              muted: '#64748B',
              dim: '#94A3B8',
              positive: '#10B981',
              negative: '#EF4444',
              warning: '#F59E0B',
            }
          },
          fontFamily: {
            sans: ['"Noto Sans JP"', '"Hiragino Sans"', '"Hiragino Kaku Gothic ProN"', '"Yu Gothic UI"', '"Meiryo"', 'sans-serif'],
          }
        }
      }
    }
  </script>
  <style>
    @media print {
      .no-print { display: none !important; }
      .rounded-xl { break-inside: avoid; }
      .bg-clip-text.text-transparent {
        -webkit-background-clip: initial !important;
        background-clip: initial !important;
        color: #2563EB !important;
        -webkit-text-fill-color: #2563EB !important;
      }
    }
  </style>
</head>
<body class="bg-ads-bg text-ads-text antialiased leading-relaxed border-t-4 border-ads-accent">
  <main class="max-w-3xl mx-auto px-5 py-10 md:py-16">
<!-- CONTENT_START -->

<!-- CONTENT_END -->
  </main>
  <footer class="max-w-3xl mx-auto px-5 pb-10 pt-6 border-t border-ads-border/30">
    <p class="text-xs text-ads-dim text-center">コーポレートエンジニア技術図解</p>
  </footer>
  <script src="https://unpkg.com/lucide@latest"></script>
  <script>lucide.createIcons();</script>
</body>
</html>
```

---

## ADS カラーパレット（Tailwindクラス）

| クラス | カラー | 用途 |
|-------|-------|------|
| `text-ads-text` | `#1E293B` | 本文・見出し |
| `text-ads-muted` | `#64748B` | 説明文・補足 |
| `text-ads-dim` | `#94A3B8` | 薄いテキスト |
| `bg-ads-bg` | `#FFFFFF` | ページ背景 |
| `bg-ads-surface` | `#F8FAFC` | カード・セクション背景 |
| `bg-ads-accent` | `#3B82F6` | アクセント（青） |
| `text-ads-accent` | `#3B82F6` | アクセントテキスト |
| `text-ads-positive` | `#10B981` | 緑（良い点・成功） |
| `text-ads-negative` | `#EF4444` | 赤（問題・警告） |
| `border-ads-border` | `#E2E8F0` | 区切り線 |

---

## コンテンツ構成テンプレート

### ① ヘッダー（冒頭）

```html
<!-- カテゴリバッジ + タイトル + ざっくり一言 -->
<div class="mb-10 md:mb-16">
  <span class="inline-block text-xs font-semibold tracking-widest text-ads-accent uppercase mb-3">
    【カテゴリ: ネットワーク / 認証 / SaaS など】
  </span>
  <h1 class="text-3xl md:text-4xl font-black text-ads-text leading-tight mb-4">
    【図解タイトル】
  </h1>
  <div class="bg-ads-accent/10 border border-ads-accent/30 rounded-xl px-5 py-4 mb-4">
    <p class="text-sm text-ads-accent font-semibold mb-1">ざっくり一言</p>
    <p class="text-base font-bold text-ads-text">【30字以内の本質的な答え】</p>
  </div>
  <p class="text-ads-muted leading-relaxed">【この図解でわかること・1〜2文】</p>
</div>
```

### ② 「読む前の問い」カード

```html
<div class="bg-ads-accent rounded-xl px-6 py-5 mb-8 text-white">
  <p class="text-sm text-blue-200 mb-1 font-medium">この図解が答える問い</p>
  <p class="text-lg font-bold leading-snug">【問いの文章】</p>
</div>
```

### ③ ASCIIアート（全体像）

```html
<div class="mb-8">
  <div class="flex items-center gap-3 mb-4">
    <div class="w-10 h-10 rounded-xl bg-ads-text flex items-center justify-center flex-shrink-0">
      <i data-lucide="layout-template" class="w-5 h-5 text-white"></i>
    </div>
    <div>
      <h2 class="text-xl font-bold text-ads-text">全体像</h2>
      <p class="text-sm text-ads-muted">まずこの図で登場人物と通信の流れを把握する</p>
    </div>
  </div>
  <div class="bg-slate-900 rounded-xl p-5 md:p-8 overflow-x-auto">
    <pre class="font-mono text-sm leading-relaxed text-emerald-400 whitespace-pre">
【ASCIIアートをここに書く】
    </pre>
  </div>
</div>
```

### ④ まず理解する3つの構造

```html
<div class="mb-8">
  <div class="flex items-center gap-3 mb-6">
    <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-blue-700 rounded-xl flex items-center justify-center">
      <i data-lucide="layers" class="w-5 h-5 text-white"></i>
    </div>
    <div>
      <h2 class="text-xl font-bold text-ads-text">まず理解する3つの構造</h2>
      <p class="text-sm text-ads-muted">この順に理解すると全体像がつながる</p>
    </div>
  </div>

  <div class="grid gap-4">
    <!-- 1つ目：骨格 -->
    <div class="flex items-start gap-4 p-4 bg-gradient-to-r from-blue-50 to-blue-100 rounded-xl border-l-4 border-blue-500">
      <div class="w-10 h-10 bg-blue-500 text-white rounded-full flex items-center justify-center font-bold text-lg flex-shrink-0">1</div>
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold text-lg text-ads-text">【構造1タイトル】</span>
          <span class="text-xs bg-blue-500 text-white px-2 py-0.5 rounded-full font-semibold">骨格</span>
        </div>
        <p class="text-ads-muted text-sm leading-relaxed">【説明】</p>
        <a href="URL" target="_blank" class="text-xs text-ads-accent hover:underline mt-2 inline-block">↗ 【出典名】</a>
      </div>
    </div>

    <!-- 2つ目：補足 -->
    <div class="flex items-start gap-4 p-4 bg-gradient-to-r from-cyan-50 to-cyan-100 rounded-xl border-l-4 border-cyan-500">
      <div class="w-10 h-10 bg-cyan-500 text-white rounded-full flex items-center justify-center font-bold text-lg flex-shrink-0">2</div>
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold text-lg text-ads-text">【構造2タイトル】</span>
          <span class="text-xs bg-cyan-500 text-white px-2 py-0.5 rounded-full font-semibold">補足</span>
        </div>
        <p class="text-ads-muted text-sm leading-relaxed">【説明】</p>
        <a href="URL" target="_blank" class="text-xs text-ads-accent hover:underline mt-2 inline-block">↗ 【出典名】</a>
      </div>
    </div>

    <!-- 3つ目：応用 -->
    <div class="flex items-start gap-4 p-4 bg-gradient-to-r from-gray-50 to-gray-100 rounded-xl border-l-4 border-gray-400">
      <div class="w-10 h-10 bg-gray-400 text-white rounded-full flex items-center justify-center font-bold text-lg flex-shrink-0">3</div>
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold text-lg text-ads-text">【構造3タイトル】</span>
          <span class="text-xs bg-gray-400 text-white px-2 py-0.5 rounded-full font-semibold">応用</span>
        </div>
        <p class="text-ads-muted text-sm leading-relaxed">【説明】</p>
        <a href="URL" target="_blank" class="text-xs text-ads-accent hover:underline mt-2 inline-block">↗ 【出典名】</a>
      </div>
    </div>
  </div>
</div>
```

### ⑤ 詳細セクション（セクションカード）

```html
<div class="bg-ads-surface rounded-2xl p-6 md:p-8 mb-6">
  <div class="flex items-center gap-3 mb-4">
    <div class="w-10 h-10 rounded-xl bg-ads-accent flex items-center justify-center flex-shrink-0">
      <i data-lucide="【アイコン名】" class="w-5 h-5 text-white"></i>
    </div>
    <div>
      <p class="text-xs font-semibold text-ads-accent uppercase tracking-widest mb-0.5">【eyebrow】</p>
      <h2 class="text-xl font-bold text-ads-text">【セクションタイトル】</h2>
    </div>
  </div>

  <p class="text-ads-muted leading-relaxed mb-4">【原理原則の説明】</p>
  <a href="URL" target="_blank" class="text-xs text-ads-accent hover:underline">↗ 【出典名】</a>

  <!-- ステップリスト -->
  <div class="space-y-3 mt-6">
    <div class="flex items-start gap-4 p-4 bg-white rounded-xl border border-ads-border">
      <span class="w-7 h-7 bg-ads-accent text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">1</span>
      <div>
        <p class="font-semibold text-ads-text mb-1">【ステップタイトル】</p>
        <p class="text-sm text-ads-muted leading-relaxed">【説明】</p>
      </div>
    </div>
  </div>
</div>
```

### ⑥ 比較テーブル

```html
<div class="bg-ads-surface rounded-2xl p-6 md:p-8 mb-6">
  <h2 class="text-xl font-bold text-ads-text mb-6">【比較タイトル】</h2>

  <div class="overflow-x-auto">
    <table class="w-full text-sm">
      <thead>
        <tr class="border-b border-ads-border">
          <th class="text-left py-2 px-3 text-ads-muted font-semibold text-xs uppercase tracking-wide">項目</th>
          <th class="text-left py-2 px-3 text-ads-muted font-semibold text-xs uppercase tracking-wide">【A】</th>
          <th class="text-left py-2 px-3 text-ads-muted font-semibold text-xs uppercase tracking-wide">【B】</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-ads-border">
        <tr>
          <td class="py-3 px-3 font-semibold text-ads-text">【比較項目】</td>
          <td class="py-3 px-3 text-ads-negative">【Aの評価】</td>
          <td class="py-3 px-3 text-ads-positive">
            【Bの評価】
            <a href="URL" target="_blank" class="text-xs text-ads-accent hover:underline block mt-0.5">↗ 出典</a>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
```

### ⑦ まとめ

```html
<div class="bg-ads-text rounded-2xl p-6 md:p-8 mb-6">
  <p class="text-xs font-bold tracking-widest text-ads-positive uppercase mb-4">まとめ</p>
  <h2 class="text-xl font-bold text-white mb-6">この図解でわかること</h2>

  <div class="grid gap-4 md:grid-cols-3 mb-8">
    <div class="bg-white/10 rounded-xl p-4">
      <div class="text-3xl font-black text-white mb-1">01</div>
      <p class="font-semibold text-white mb-1">【ポイント1タイトル】</p>
      <p class="text-sm text-slate-400 leading-relaxed">【説明】</p>
    </div>
    <div class="bg-white/10 rounded-xl p-4">
      <div class="text-3xl font-black text-white mb-1">02</div>
      <p class="font-semibold text-white mb-1">【ポイント2タイトル】</p>
      <p class="text-sm text-slate-400 leading-relaxed">【説明】</p>
    </div>
    <div class="bg-white/10 rounded-xl p-4">
      <div class="text-3xl font-black text-white mb-1">03</div>
      <p class="font-semibold text-white mb-1">【ポイント3タイトル】</p>
      <p class="text-sm text-slate-400 leading-relaxed">【説明】</p>
    </div>
  </div>

  <!-- この理解でできること -->
  <div class="border-t border-white/20 pt-6">
    <p class="text-xs font-bold tracking-widest text-ads-positive uppercase mb-4">この理解で次にできること</p>
    <div class="space-y-3">
      <div class="flex gap-3 items-start">
        <span class="text-ads-positive flex-shrink-0 leading-relaxed">→</span>
        <p class="text-white leading-relaxed">【できること1】</p>
      </div>
      <div class="flex gap-3 items-start">
        <span class="text-ads-positive flex-shrink-0 leading-relaxed">→</span>
        <p class="text-white leading-relaxed">【できること2】</p>
      </div>
      <div class="flex gap-3 items-start">
        <span class="text-ads-positive flex-shrink-0 leading-relaxed">→</span>
        <p class="text-white leading-relaxed">【できること3】</p>
      </div>
    </div>
  </div>
</div>
```

---

## 出典リンクの書き方

各説明の直後にインラインで配置する。

```html
<!-- 通常（ライト背景内） -->
<a href="https://..." target="_blank" class="text-xs text-ads-accent hover:underline">↗ RFC 2865（RADIUS仕様）</a>

<!-- ダーク背景内 -->
<a href="https://..." target="_blank" class="text-xs text-blue-400 hover:underline">↗ RFC 2865（RADIUS仕様）</a>

<!-- 推測ラベル -->
<span class="text-xs text-ads-dim">※ 推測</span>
<span class="text-xs text-ads-dim">※ 環境依存</span>
```

---

## セクション構成パターン

| セクションの性質 | 背景クラス | テキスト |
|--------------|----------|--------|
| ヘッダー | `bg-ads-bg` | `text-ads-text` |
| 読む前の問いカード | `bg-ads-accent` | `text-white` |
| ASCIIアート（全体像） | `bg-slate-900`（pre内） | `text-emerald-400` |
| まず理解する3つの構造 | グラデーション（青/シアン/グレー） | `text-ads-text` |
| 詳細セクション | `bg-ads-surface` | `text-ads-text` |
| 比較テーブル | `bg-ads-surface` | 良: `text-ads-positive` / 悪: `text-ads-negative` |
| まとめ | `bg-ads-text` | `text-white` |

---

## Lucide Icons の使い方

```html
<!-- アイコンを埋め込む（data-lucide属性で指定） -->
<i data-lucide="shield" class="w-5 h-5 text-white"></i>
<i data-lucide="layers" class="w-5 h-5 text-ads-accent"></i>
<i data-lucide="arrow-right" class="w-4 h-4"></i>

<!-- bodyの末尾で初期化（ベーステンプレートに含まれる） -->
<script src="https://unpkg.com/lucide@latest"></script>
<script>lucide.createIcons();</script>
```

よく使うアイコン名: `shield`, `layers`, `layout-template`, `key-round`, `globe`, `user`, `server`, `arrow-right`, `check-circle`, `alert-triangle`, `link`

---

## 禁止事項（デザイン）

- **絵文字を使わない**（テキスト記号 `→` `✓` `↗` はOK）
- **`<style>` タグを追加しない**（Tailwindクラスで表現する）
- **`<script>` タグを追加しない**（テンプレートに含まれるもの以外）
- **外部CDNを追加しない**（Tailwind / Lucide 以外の外部読み込み禁止）
- **インタラクティブ要素を入れない**（トグル・アニメーション等）
