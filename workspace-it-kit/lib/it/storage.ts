import { z } from "zod";

import {
  EMPTY_WEEKLY_REPORT_INPUT,
  type WeeklyReportInput,
} from "@/lib/it/report";
import { execLinkSchema, isLocalTask, localTaskSchema, type ExecLink, type LocalTask } from "@/lib/it/schema";

// ─── スキーマ ────────────────────────────────────────────────

const weeklyReportInputSchema = z.object({
  progress: z.string(),
  issues: z.string(),
  consult: z.string(),
});

const taskEditSchema = z.object({
  title: z.string().optional(),
  deadline: z.string().optional(),
  description: z.string().optional(),
});

export type TaskEdit = z.infer<typeof taskEditSchema>;

const workspaceStorageSchema = z.object({
  reportInputs: z.record(z.string(), weeklyReportInputSchema).default({}),
  workMemos: z.record(z.string(), z.string()).default({}),
  taskLinks: z.record(z.string(), z.array(execLinkSchema)).default({}),
  delayedOverrides: z.record(z.string(), z.boolean()).default({}),
  completedTaskIds: z.array(z.string()).default([]),
  selectedTaskId: z.string().nullable().default(null),
  localTasks: z.array(localTaskSchema).default([]),
  deletedTaskIds: z.array(z.string()).default([]),
  taskEdits: z.record(z.string(), taskEditSchema).default({}),
});

/** v2（localStorage）からの移行用: 古いキーを許容 */
const legacyStorageSchema = z.object({
  reportInputs: z.record(z.string(), weeklyReportInputSchema).default({}),
  workMemos: z.record(z.string(), z.string()).default({}),
  taskLinks: z.record(z.string(), z.array(execLinkSchema)).default({}),
  delayedOverrides: z.record(z.string(), z.boolean()).default({}),
  completedTaskIds: z.array(z.string()).default([]),
});

const LEGACY_STORAGE_KEY = "workspace-it-kit:v2";
const LEGACY_STORAGE_KEY_V1 = "workspace-it-kit:v1";

export type WorkspaceStorage = z.infer<typeof workspaceStorageSchema>;

/**
 * PUT /api/overlay に送る部分更新ペイロード。
 * 全キーに .default() が付いた workspaceStorageSchema を .partial() すると
 * 未指定キーがデフォルト値で埋まってしまう（＝空パッチのつもりが全キー送信になる）ため、
 * デフォルト無しの別スキーマとして定義する。
 */
const workspaceStoragePatchSchema = z.object({
  reportInputs: z.record(z.string(), weeklyReportInputSchema).optional(),
  workMemos: z.record(z.string(), z.string()).optional(),
  taskLinks: z.record(z.string(), z.array(execLinkSchema)).optional(),
  delayedOverrides: z.record(z.string(), z.boolean()).optional(),
  completedTaskIds: z.array(z.string()).optional(),
  selectedTaskId: z.string().nullable().optional(),
  localTasks: z.array(localTaskSchema).optional(),
  deletedTaskIds: z.array(z.string()).optional(),
  taskEdits: z.record(z.string(), taskEditSchema).optional(),
});

export type WorkspaceStoragePatch = z.infer<typeof workspaceStoragePatchSchema>;

const STORAGE_KEYS = [
  "reportInputs",
  "workMemos",
  "taskLinks",
  "delayedOverrides",
  "completedTaskIds",
  "selectedTaskId",
  "localTasks",
  "deletedTaskIds",
  "taskEdits",
] as const satisfies readonly (keyof WorkspaceStorage)[];

/**
 * baseline（前回保存/読み込み時点のスナップショット）と current を比較し、
 * 実際に変化したトップレベルキーだけを含む部分更新を返す。
 * 複数クライアントが同じ overlay を共有していても、触っていないキーは
 * 送信しない＝他クライアントの変更を上書きしない（キー単位マージの前提）。
 */
export function diffWorkspaceStorage(
  baseline: WorkspaceStorage,
  current: WorkspaceStorage,
): WorkspaceStoragePatch {
  const patch: WorkspaceStoragePatch = {};
  for (const key of STORAGE_KEYS) {
    if (JSON.stringify(baseline[key]) !== JSON.stringify(current[key])) {
      (patch as Record<string, unknown>)[key] = current[key];
    }
  }
  return patch;
}

// ─── デフォルト ───────────────────────────────────────────────

export function createEmptyStorage(): WorkspaceStorage {
  return {
    reportInputs: {},
    workMemos: {},
    taskLinks: {},
    delayedOverrides: {},
    completedTaskIds: [],
    selectedTaskId: null,
    localTasks: [],
    deletedTaskIds: [],
    taskEdits: {},
  };
}

export type { LocalTask };

function parseStorage(raw: unknown): WorkspaceStorage {
  const parsed = workspaceStorageSchema.safeParse(raw);
  if (parsed.success) return parsed.data;
  return createEmptyStorage();
}

function parseLegacy(raw: unknown): WorkspaceStorage | null {
  const parsed = legacyStorageSchema.safeParse(raw);
  if (!parsed.success) return null;
  return { ...parsed.data, selectedTaskId: null, localTasks: [], deletedTaskIds: [], taskEdits: {} };
}

// ─── localStorage 移行 ────────────────────────────────────────

function readLegacyLocalStorage(): WorkspaceStorage | null {
  if (typeof window === "undefined") return null;
  try {
    const raw =
      window.localStorage.getItem(LEGACY_STORAGE_KEY) ??
      window.localStorage.getItem(LEGACY_STORAGE_KEY_V1);
    if (!raw) return null;
    return parseLegacy(JSON.parse(raw));
  } catch {
    return null;
  }
}

function clearLegacyLocalStorage(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(LEGACY_STORAGE_KEY);
  window.localStorage.removeItem(LEGACY_STORAGE_KEY_V1);
}

// ─── API Route 経由の読み書き ─────────────────────────────────

export async function loadWorkspaceStorage(): Promise<WorkspaceStorage> {
  try {
    const res = await fetch("/api/overlay");
    if (!res.ok) throw new Error(`GET /api/overlay failed: ${res.status}`);
    const json: unknown = await res.json();
    const loaded = parseStorage(json);

    // overlay が空で localStorage にデータがあれば移行
    const isEmpty =
      Object.keys(loaded.reportInputs).length === 0 &&
      Object.keys(loaded.workMemos).length === 0 &&
      Object.keys(loaded.taskLinks).length === 0 &&
      loaded.completedTaskIds.length === 0;

    if (isEmpty) {
      const legacy = readLegacyLocalStorage();
      if (legacy) {
        await saveWorkspaceStorage(pruneOrphanLocalData(legacy));
        clearLegacyLocalStorage();
        return legacy;
      }
    }

    return loaded;
  } catch {
    return createEmptyStorage();
  }
}

/**
 * ローカルタスク実体が存在しない LOCAL-* キーの overlay データを取り除く。
 * LOCAL タスクはハード削除のため、残った関連データは孤児（削除タスクの残骸）。
 * 削除直後に InlineTextareaField のアンマウント時保存が古いクロージャ経由で
 * 削除済みキーを書き戻すレースがあるため、保存時に必ず間引く。
 * （JSON タスクはソフト削除＝復元前提なので対象外）
 */
export function pruneOrphanLocalData(data: WorkspaceStorage): WorkspaceStorage {
  const liveIds = new Set(data.localTasks.map((t) => t.id));
  const isOrphan = (id: string) => isLocalTask({ id }) && !liveIds.has(id);
  const pruneRecord = <T,>(record: Record<string, T>): Record<string, T> =>
    Object.fromEntries(Object.entries(record).filter(([id]) => !isOrphan(id)));
  return {
    ...data,
    reportInputs: pruneRecord(data.reportInputs),
    workMemos: pruneRecord(data.workMemos),
    taskLinks: pruneRecord(data.taskLinks),
    delayedOverrides: pruneRecord(data.delayedOverrides),
    completedTaskIds: data.completedTaskIds.filter((id) => !isOrphan(id)),
    selectedTaskId:
      data.selectedTaskId !== null && isOrphan(data.selectedTaskId)
        ? null
        : data.selectedTaskId,
  };
}

/**
 * 既存データに patch のキーだけを上書きした結果を返す（キー単位マージ）。
 * patch に含まれないキーは existing の値がそのまま残る。
 */
export function applyWorkspaceStoragePatch(
  existing: WorkspaceStorage,
  patch: WorkspaceStoragePatch,
): WorkspaceStorage {
  return workspaceStorageSchema.parse({ ...existing, ...patch });
}

/**
 * 変更のあったキーだけを送る部分更新。サーバー側は既存データに対して
 * キー単位でマージするため、他クライアントが更新した未変更キーは保持される。
 * 呼び出し側は pruneOrphanLocalData 済みのデータから diffWorkspaceStorage で
 * patch を作ること。
 */
export async function saveWorkspaceStorage(patch: WorkspaceStoragePatch): Promise<void> {
  const res = await fetch("/api/overlay", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  if (!res.ok) throw new Error(`PUT /api/overlay failed: ${res.status}`);
}

// ─── ヘルパー ─────────────────────────────────────────────────

export function getTaskLinks(
  storage: WorkspaceStorage,
  taskId: string,
  initialLinks: Record<string, ExecLink[]>,
): ExecLink[] {
  return storage.taskLinks[taskId] ?? initialLinks[taskId] ?? [];
}

export function getReportInput(
  storage: WorkspaceStorage,
  taskId: string,
): WeeklyReportInput {
  return storage.reportInputs[taskId] ?? EMPTY_WEEKLY_REPORT_INPUT;
}

export function hasReportProgress(input: WeeklyReportInput): boolean {
  return input.progress.trim().length > 0;
}

export function countReportProgress(
  taskIds: string[],
  reportInputs: Record<string, WeeklyReportInput>,
): { filled: number; total: number } {
  const filled = taskIds.filter((id) =>
    hasReportProgress(reportInputs[id] ?? EMPTY_WEEKLY_REPORT_INPUT),
  ).length;
  return { filled, total: taskIds.length };
}

/** テスト用 */
export function clearWorkspaceStorageForTests(): void {
  if (typeof window !== "undefined") {
    window.localStorage.removeItem(LEGACY_STORAGE_KEY);
    window.localStorage.removeItem(LEGACY_STORAGE_KEY_V1);
  }
}

export { workspaceStorageSchema, workspaceStoragePatchSchema };
