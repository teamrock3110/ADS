import { z } from "zod";

import {
  EMPTY_WEEKLY_REPORT_INPUT,
  type WeeklyReportInput,
} from "@/lib/it/report";
import { execLinkSchema, type ExecLink } from "@/lib/it/schema";

const STORAGE_KEY = "workspace-it-kit:v2";
const LEGACY_STORAGE_KEY = "workspace-it-kit:v1";

const weeklyReportInputSchema = z.object({
  progress: z.string(),
  issues: z.string(),
  consult: z.string(),
});

const workspaceStorageSchema = z.object({
  reportInputs: z.record(z.string(), weeklyReportInputSchema),
  workMemos: z.record(z.string(), z.string()),
  taskLinks: z.record(z.string(), z.array(execLinkSchema)),
  delayedOverrides: z.record(z.string(), z.boolean()),
  completedTaskIds: z.array(z.string()).default([]),
});

/** v1（報告期間あり）からの移行用 */
const legacyStorageSchema = z.object({
  reportInputs: z.record(z.string(), weeklyReportInputSchema).default({}),
  workMemos: z.record(z.string(), z.string()).default({}),
  taskLinks: z.record(z.string(), z.array(execLinkSchema)).default({}),
  delayedOverrides: z.record(z.string(), z.boolean()).default({}),
  completedTaskIds: z.array(z.string()).default([]),
});

export type WorkspaceStorage = z.infer<typeof workspaceStorageSchema>;

export function createEmptyStorage(): WorkspaceStorage {
  return {
    reportInputs: {},
    workMemos: {},
    taskLinks: {},
    delayedOverrides: {},
    completedTaskIds: [],
  };
}

export function parseWorkspaceStorage(raw: unknown): WorkspaceStorage {
  const parsed = workspaceStorageSchema.safeParse(raw);
  if (parsed.success) {
    return parsed.data;
  }

  const legacy = legacyStorageSchema.safeParse(raw);
  if (legacy.success) {
    return legacy.data;
  }

  return createEmptyStorage();
}

export function loadWorkspaceStorage(): WorkspaceStorage {
  if (typeof window === "undefined") {
    return createEmptyStorage();
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw) {
      return parseWorkspaceStorage(JSON.parse(raw));
    }

    const legacyRaw = window.localStorage.getItem(LEGACY_STORAGE_KEY);
    if (legacyRaw) {
      const migrated = parseWorkspaceStorage(JSON.parse(legacyRaw));
      saveWorkspaceStorage(migrated);
      return migrated;
    }

    return createEmptyStorage();
  } catch {
    return createEmptyStorage();
  }
}

export function saveWorkspaceStorage(data: WorkspaceStorage): void {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

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

/** テスト用: localStorage をクリア */
export function clearWorkspaceStorageForTests(): void {
  if (typeof window !== "undefined") {
    window.localStorage.removeItem(STORAGE_KEY);
    window.localStorage.removeItem(LEGACY_STORAGE_KEY);
  }
}

export { STORAGE_KEY, workspaceStorageSchema };
