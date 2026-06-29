import { z } from "zod";

import {
  EMPTY_WEEKLY_REPORT_INPUT,
  type WeeklyReportInput,
} from "@/lib/it/report";
import { execLinkSchema, localTaskSchema, type ExecLink, type LocalTask } from "@/lib/it/schema";

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
        await saveWorkspaceStorage(legacy);
        clearLegacyLocalStorage();
        return legacy;
      }
    }

    return loaded;
  } catch {
    return createEmptyStorage();
  }
}

export async function saveWorkspaceStorage(data: WorkspaceStorage): Promise<void> {
  const res = await fetch("/api/overlay", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
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

export { workspaceStorageSchema };
