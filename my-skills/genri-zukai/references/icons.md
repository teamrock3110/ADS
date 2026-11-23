# 絵記号の一覧

lucide の形を 24 マスの線画で書き写したもの。外部から読み込まない。

## 使い方

- **本文（カード・まとめ）**：次の枠に path を入れる。色は `currentColor` で、置いた場所の色になる

```html
<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  <!-- path -->
</svg>
```

- **図（SVG）の中**：`<g transform="translate(x y) scale(3)" fill="none" stroke="#10547C" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">` に入れる。scale(3) で 72px 角、scale(4) で 96px 角
- 意味が合うものがなければ、絵記号を使わずに言葉だけにする。形を自作しない

## 一覧

| 名前 | 意味の目安 | path |
|---|---|---|
| search | 調べる・探す | `<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>` |
| compass | 全体像・方向（表紙とまとめの定番） | `<circle cx="12" cy="12" r="10"/><path d="m16.24 7.76-1.804 5.411a2 2 0 0 1-1.265 1.265L7.76 16.24l1.804-5.411a2 2 0 0 1 1.265-1.265z"/>` |
| book-open | 学ぶ・知識 | `<path d="M12 7v14"/><path d="M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h3a6 6 0 0 1 6 4 6 6 0 0 1 6-4h3a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-4a5 5 0 0 0-5 3 5 5 0 0 0-5-3z"/>` |
| image | 画像 | `<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/>` |
| file-text | 書類・データ | `<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/>` |
| cpu | AI・計算する機械 | `<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="8" y="8" width="8" height="8" rx="1"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M7 2v2M17 2v2M7 20v2M17 20v2M2 7h2M2 17h2M20 7h2M20 17h2"/>` |
| bot | AI・エージェント | `<path d="M12 8V4H8"/><rect x="4" y="8" width="16" height="12" rx="2"/><path d="M2 14h2M20 14h2M15 13v2M9 13v2"/>` |
| user-round | 人 | `<circle cx="12" cy="8" r="5"/><path d="M20 21a8 8 0 0 0-16 0"/>` |
| server | サーバー | `<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01M6 18h.01"/>` |
| database | データベース・保存 | `<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>` |
| globe | インターネット・世界中 | `<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>` |
| lock | 鍵をかける・守る | `<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>` |
| key-round | 鍵・合言葉 | `<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5"/>` |
| git-branch | 分かれる・分岐 | `<path d="M15 6a9 9 0 0 0-9 9V3"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/>` |
| refresh-cw | 繰り返す・更新する | `<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>` |
| layers | 層・重なり | `<path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z"/><path d="m22 17.65-9.17 4.16a2 2 0 0 1-1.66 0L2 17.65"/><path d="m22 12.65-9.17 4.16a2 2 0 0 1-1.66 0L2 12.65"/>` |
| scale | 比べる・天秤 | `<path d="M12 3v18"/><path d="m19 8 3 8a5 5 0 0 1-6 0zV7"/><path d="M3 7h1a17 17 0 0 0 8-2 17 17 0 0 0 8 2h1"/><path d="m5 8 3 8a5 5 0 0 1-6 0zV7"/><path d="M7 21h10"/>` |
| receipt | 費用・明細 | `<path d="M4 2v20l2-1 2 1 2-1 2 1 2-1 2 1 2-1 2 1V2l-2 1-2-1-2 1-2-1-2 1-2-1-2 1Z"/><path d="M16 8h-6a2 2 0 1 0 0 4h4a2 2 0 1 1 0 4H8"/><path d="M12 17.5v-11"/>` |
| lightbulb | 原理・気づき | `<path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/>` |
| triangle-alert | 注意・落とし穴 | `<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>` |
| check | できる・正しい | `<path d="M20 6 9 17l-5-5"/>` |
| x | できない・誤り | `<path d="M18 6 6 18"/><path d="m6 6 12 12"/>` |
| send | 送る | `<path d="M14.536 21.686a.5.5 0 0 0 .937-.024l6.5-19a.496.496 0 0 0-.635-.635l-19 6.5a.5.5 0 0 0-.024.937l7.93 3.18a2 2 0 0 1 1.112 1.11z"/><path d="m21.854 2.147-10.94 10.939"/>` |
| arrow-up | 先頭へ戻る | `<path d="m5 12 7-7 7 7"/><path d="M12 19V5"/>` |
