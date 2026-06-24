# workspace-it-kit

コーポレートIT担当向け **Task Worker**（4ペイン）。

## 起動

```bash
cd workspace-it-kit
npm run dev
```

→ `http://localhost:3000`

## 4ペイン構成

| ペイン | 幅 | 役割 |
|--------|-----|------|
| P1 | 狭 (~208px) | タスク一覧（期限・遅延順） |
| P2 | 広 (flex) | 概要（読取）・作業メモ・**報告入力3欄** |
| P3 | 中 (~256px) | 関連リンク（ワンクリックで開く） |
| P4 | 中 (~288px) | 週次報告書（折りたたみ可） |

## 操作

1. 左でタスクを選択
2. P3 のリンクをクリック → Slack / Slides / Sheet 等を開く
3. P2 の「週次報告の入力」3欄 → P4 週次報告書に反映
4. P4「コピー」→ Google ドキュメントへ貼り付け
5. P4 の `›` でペインを閉じて作業スペースを広げる

## 週次報告書の生成

P2 の入力のみが報告書の中身になります（タスクJSONからは自動挿入しません）。

| 入力欄 | 報告セクション | 必須 |
|--------|----------------|------|
| 今週の進捗 | ■ 進行中のアクションアイテム… | 必須（空なら警告） |
| 遅延理由・課題 | ■ 遅延理由・課題 | 任意（空なら見出しのみ） |
| 相談・承認依頼 | ■ 相談・作業承認依頼 | 任意（空なら見出しのみ） |

来月: 入力内容の localStorage 保存 + AI生成（予定）

## データ

- `data/tasks.json` — タスク
- `data/task-links.json` — タスク別関連リンク（モック）
- **作業データ（Overlay）** — `DATABASE_URL` 設定時は **Neon DB**、未設定時は `data/overlay.json`

## Neon DB セットアップ（Vercel 連携）

### 1. Vercel アカウント作成（未登録の場合）

1. [https://vercel.com/signup](https://vercel.com/signup) を開く
2. GitHub / GitLab / Bitbucket / Email のいずれかで登録

### 2. Vercel にプロジェクトを作成

1. [Vercel Dashboard](https://vercel.com/dashboard) → **Add New…** → **Project**
2. このリポジトリ（`11_ADS`）を Import
3. **Root Directory** を `workspace-it-kit` に設定して Deploy

### 3. Neon データベースを追加

1. デプロイしたプロジェクトを開く → **Storage** タブ
2. **Create Database** → **Neon** を選択
3. リージョンは **Tokyo (ap-northeast-1)** 推奨 → **Create**
4. 作成後 **Connect to Project** でこのプロジェクトに紐付け  
   → `DATABASE_URL` などの環境変数が Vercel に自動設定される

### 4. ローカルに環境変数を取り込む

```bash
cd workspace-it-kit
npx vercel login          # 初回のみ
npx vercel link           # プロジェクトを選択
npx vercel env pull .env.local
```

### 5. テーブル作成（初回のみ）

```bash
npm run db:migrate
```

### 6. 開発サーバー再起動

```bash
npm run dev
```

`DATABASE_URL` が設定されていれば、作業データ（報告・メモ・リンク等）は Neon に保存されます。  
既存の `data/overlay.json` がある場合、初回アクセス時に自動で Neon へ移行されます。

## 来月

- メモ・相談・リンクの永続化
- Jira 連携はその次
