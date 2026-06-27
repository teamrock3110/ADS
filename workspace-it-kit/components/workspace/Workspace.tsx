"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";

import { flushActiveTextarea } from "@/components/primitives/InlineTextareaField";
import { ExecLinksPane } from "@/components/workspace/ExecLinksPane";
import { ItGlobalHeader } from "@/components/workspace/ItGlobalHeader";
import { ReportPane } from "@/components/workspace/ReportPane";
import { TaskDetailPane } from "@/components/workspace/TaskDetailPane";
import { TaskListPane } from "@/components/workspace/TaskListPane";
import {
  EMPTY_WEEKLY_REPORT_INPUT,
  generateWeeklyReport,
  type WeeklyReportInput,
} from "@/lib/it/report";
import { type ExecLink, type Task, type TaskBucket, isLocalTask } from "@/lib/it/schema";
import {
  countReportProgress,
  getTaskLinks,
  hasReportProgress,
  loadWorkspaceStorage,
  saveWorkspaceStorage,
  type WorkspaceStorage,
  type LocalTask,
  type TaskEdit,
} from "@/lib/it/storage";

type WorkspaceProps = {
  initialTasks: Task[];
  initialExecLinks: Record<string, ExecLink[]>;
  workspace: { name: string; assignee: string };
};

function isCompleted(completedTaskIds: string[], taskId: string): boolean {
  return completedTaskIds.includes(taskId);
}

export function Workspace({
  initialTasks,
  initialExecLinks,
  workspace,
}: WorkspaceProps) {
  const [jsonTasks] = useState<Task[]>(initialTasks);
  const [localTasks, setLocalTasks] = useState<LocalTask[]>([]);
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  const [hydrated, setHydrated] = useState(false);
  const [reportInputs, setReportInputs] = useState<
    Record<string, WeeklyReportInput>
  >({});
  const [workMemos, setWorkMemos] = useState<Record<string, string>>({});
  const [taskLinks, setTaskLinks] = useState<Record<string, ExecLink[]>>({});
  const [delayedOverrides, setDelayedOverrides] = useState<
    Record<string, boolean>
  >({});
  const [completedTaskIds, setCompletedTaskIds] = useState<string[]>([]);
  const [reportPaneOpen, setReportPaneOpen] = useState(true);
  const [deletedTaskIds, setDeletedTaskIds] = useState<string[]>([]);
  const [taskEdits, setTaskEdits] = useState<Record<string, TaskEdit>>({});
  // ── 初回読み込み ──────────────────────────────────────────
  useEffect(() => {
    loadWorkspaceStorage()
      .then((loaded) => {
        setReportInputs(loaded.reportInputs);
        setWorkMemos(loaded.workMemos);
        setTaskLinks(loaded.taskLinks);
        setDelayedOverrides(loaded.delayedOverrides);
        setCompletedTaskIds(loaded.completedTaskIds);
        setSelectedTaskId(loaded.selectedTaskId);
        setLocalTasks(loaded.localTasks);
        setDeletedTaskIds(loaded.deletedTaskIds);
        setTaskEdits(loaded.taskEdits);
        setHydrated(true);
      })
      .catch(() => {
        setHydrated(true);
      });
  }, []);

  // ── 保存（状態変化ごと）──────────────────────────────────
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!hydrated) return;

    const data: WorkspaceStorage = {
      reportInputs,
      workMemos,
      taskLinks,
      delayedOverrides,
      completedTaskIds,
      selectedTaskId,
      localTasks,
      deletedTaskIds,
      taskEdits,
    };

    // 連続した state 更新をまとめて1回だけ送る
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(() => {
      saveWorkspaceStorage(data).catch(() => {
        toast.error("保存に失敗しました。サーバーが起動しているか確認してください。");
      });
    }, 300);
  }, [
    hydrated,
    reportInputs,
    workMemos,
    taskLinks,
    delayedOverrides,
    completedTaskIds,
    selectedTaskId,
    localTasks,
    deletedTaskIds,
    taskEdits,
  ]);

  // ── タスク一覧の計算 ──────────────────────────────────────
  const tasks = useMemo<Task[]>(() => {
    const editedJsonTasks = jsonTasks.map((t) => {
      const edits = taskEdits[t.id];
      return edits ? { ...t, ...edits } : t;
    });
    const allTasks = [...editedJsonTasks, ...localTasks];
    return allTasks.filter((t) => !deletedTaskIds.includes(t.id));
  }, [jsonTasks, localTasks, taskEdits, deletedTaskIds]);

  const tasksWithDelayed = useMemo(
    () =>
      tasks.map((task) => ({
        ...task,
        delayed: delayedOverrides[task.id] ?? task.delayed,
      })),
    [tasks, delayedOverrides],
  );

  const activeTasks = useMemo(
    () =>
      tasksWithDelayed.filter(
        (task) => !isCompleted(completedTaskIds, task.id),
      ),
    [tasksWithDelayed, completedTaskIds],
  );

  const completedTasks = useMemo(
    () =>
      tasksWithDelayed.filter((task) =>
        isCompleted(completedTaskIds, task.id),
      ),
    [tasksWithDelayed, completedTaskIds],
  );

  // 選択タスクの補正（完了済み or null → 先頭へ）
  const resolvedSelectedTaskId = useMemo(() => {
    if (!hydrated) return null;
    if (
      selectedTaskId &&
      activeTasks.some((t) => t.id === selectedTaskId)
    ) {
      return selectedTaskId;
    }
    return activeTasks[0]?.id ?? null;
  }, [hydrated, selectedTaskId, activeTasks]);

  const activeTask = activeTasks.find((t) => t.id === resolvedSelectedTaskId);

  // ── 計算値 ────────────────────────────────────────────────
  const storageSnapshot: WorkspaceStorage = useMemo(
    () => ({
      reportInputs,
      workMemos,
      taskLinks,
      delayedOverrides,
      completedTaskIds,
      selectedTaskId,
      localTasks,
      deletedTaskIds,
      taskEdits,
    }),
    [reportInputs, workMemos, taskLinks, delayedOverrides, completedTaskIds, selectedTaskId, localTasks, deletedTaskIds, taskEdits],
  );

  const execLinks = useMemo(() => {
    if (!activeTask) return [];
    return getTaskLinks(storageSnapshot, activeTask.id, initialExecLinks);
  }, [activeTask, initialExecLinks, storageSnapshot]);

  const activeReportInput = activeTask
    ? (reportInputs[activeTask.id] ?? EMPTY_WEEKLY_REPORT_INPUT)
    : EMPTY_WEEKLY_REPORT_INPUT;

  const reportResult = useMemo(
    () =>
      activeTask
        ? generateWeeklyReport(activeReportInput)
        : { text: "", warnings: [] },
    [activeTask, activeReportInput],
  );

  const reportFilledByTaskId = useMemo(() => {
    const map: Record<string, boolean> = {};
    for (const task of tasksWithDelayed) {
      map[task.id] = hasReportProgress(
        reportInputs[task.id] ?? EMPTY_WEEKLY_REPORT_INPUT,
      );
    }
    return map;
  }, [tasksWithDelayed, reportInputs]);

  const progressSummary = useMemo(() => {
    const { filled, total } = countReportProgress(
      activeTasks.map((t) => t.id),
      reportInputs,
    );
    return `${filled}/${total} 入力済`;
  }, [activeTasks, reportInputs]);

  // ── ハンドラ ──────────────────────────────────────────────
  const handleSelectTask = useCallback((id: string) => {
    flushActiveTextarea();
    setSelectedTaskId(id);
  }, []);

  const handleRestoreTask = useCallback((id: string) => {
    setCompletedTaskIds((prev) => prev.filter((taskId) => taskId !== id));
    setSelectedTaskId(id);
  }, []);

  const handleCompleteTask = useCallback(() => {
    if (!activeTask) return;
    flushActiveTextarea();
    setCompletedTaskIds((prev) =>
      prev.includes(activeTask.id) ? prev : [...prev, activeTask.id],
    );
    const remaining = activeTasks.filter((t) => t.id !== activeTask.id);
    if (remaining.length > 0) {
      setSelectedTaskId(remaining[0].id);
    }
  }, [activeTask, activeTasks]);

  const saveWorkMemo = useCallback(
    (value: string) => {
      if (!activeTask) return;
      setWorkMemos((prev) => ({ ...prev, [activeTask.id]: value }));
    },
    [activeTask],
  );

  const saveReportField = useCallback(
    (field: keyof WeeklyReportInput, value: string) => {
      if (!activeTask) return;
      setReportInputs((prev) => ({
        ...prev,
        [activeTask.id]: {
          ...(prev[activeTask.id] ?? EMPTY_WEEKLY_REPORT_INPUT),
          [field]: value,
        },
      }));
    },
    [activeTask],
  );

  const addExecLink = useCallback(
    (link: Omit<ExecLink, "id">) => {
      if (!activeTask) return;
      const id = `lnk-${Date.now()}`;
      setTaskLinks((prev) => {
        const current =
          prev[activeTask.id] ?? initialExecLinks[activeTask.id] ?? [];
        return {
          ...prev,
          [activeTask.id]: [...current, { ...link, id }],
        };
      });
    },
    [activeTask, initialExecLinks],
  );

  const deleteExecLink = useCallback(
    (linkId: string) => {
      if (!activeTask) return;
      setTaskLinks((prev) => {
        const current =
          prev[activeTask.id] ?? initialExecLinks[activeTask.id] ?? [];
        return {
          ...prev,
          [activeTask.id]: current.filter((l) => l.id !== linkId),
        };
      });
    },
    [activeTask, initialExecLinks],
  );

  const editExecLink = useCallback(
    (linkId: string, updated: Omit<ExecLink, "id">) => {
      if (!activeTask) return;
      setTaskLinks((prev) => {
        const current =
          prev[activeTask.id] ?? initialExecLinks[activeTask.id] ?? [];
        return {
          ...prev,
          [activeTask.id]: current.map((l) =>
            l.id === linkId ? { ...l, ...updated } : l,
          ),
        };
      });
    },
    [activeTask, initialExecLinks],
  );

  const handleDelayedChange = useCallback(
    (delayed: boolean) => {
      if (!activeTask) return;
      setDelayedOverrides((prev) => ({ ...prev, [activeTask.id]: delayed }));
    },
    [activeTask],
  );

  const toggleReportPane = useCallback(
    () => setReportPaneOpen((v) => !v),
    [],
  );

  const addLocalTaskComment = useCallback(
    (body: string) => {
      if (!activeTask || !isLocalTask(activeTask)) return;
      const today = new Date();
      const datePrefix = `${today.getMonth() + 1}/${today.getDate()}`;
      const comment = `${datePrefix}: ${body}`;
      setLocalTasks((prev) =>
        prev.map((t) =>
          t.id === activeTask.id
            ? { ...t, comments: [...t.comments, comment] }
            : t,
        ),
      );
    },
    [activeTask],
  );

  const handleAddTask = useCallback(
    (draft: { title: string; deadline: string; bucket: TaskBucket; description: string }) => {
      const id = `LOCAL-${Date.now()}`;
      setLocalTasks((prev) => [
        ...prev,
        { id, ...draft, comments: [], delayed: false },
      ]);
      setSelectedTaskId(id);
    },
    [],
  );

  const handleDeleteTask = useCallback(
    (id: string) => {
      if (isLocalTask({ id })) {
        setLocalTasks((prev) => prev.filter((t) => t.id !== id));
      } else {
        setDeletedTaskIds((prev) => [...prev, id]);
      }
      setSelectedTaskId((prev) => {
        if (prev !== id) return prev;
        const remaining = activeTasks.filter((t) => t.id !== id);
        return remaining[0]?.id ?? null;
      });
    },
    [activeTasks],
  );

  const handleEditTask = useCallback(
    (id: string, updates: { title?: string; deadline?: string; bucket?: TaskBucket; description?: string }) => {
      if (isLocalTask({ id })) {
        setLocalTasks((prev) =>
          prev.map((t) => (t.id === id ? { ...t, ...updates } : t)),
        );
      } else {
        setTaskEdits((prev) => ({
          ...prev,
          [id]: { ...(prev[id] ?? {}), ...updates },
        }));
      }
    },
    [],
  );

  // ── 描画 ──────────────────────────────────────────────────
  if (!hydrated) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-background text-sm text-muted-foreground">
        読み込み中…
      </div>
    );
  }

  if (!activeTask) {
    return (
      <div className="flex h-screen w-full flex-col overflow-hidden bg-background text-foreground">
        <ItGlobalHeader
          workspaceName={workspace.name}
          assignee={workspace.assignee}
          selectedTaskTitle="（進行中タスクなし）"
        />
        <div className="flex min-h-0 flex-1">
          <TaskListPane
            activeTasks={activeTasks}
            completedTasks={completedTasks}
            selectedTaskId={resolvedSelectedTaskId ?? ""}
            reportFilledByTaskId={reportFilledByTaskId}
            onSelectTask={handleSelectTask}
            onRestoreTask={handleRestoreTask}
            onAddTask={handleAddTask}
            onDeleteTask={handleDeleteTask}
          />
          <section className="flex min-w-[420px] flex-1 items-center justify-center text-sm text-muted-foreground">
            進行中のタスクがありません。完了済みから「戻す」で復元できます。
          </section>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen w-full flex-col overflow-hidden bg-background text-foreground">
      <ItGlobalHeader
        workspaceName={workspace.name}
        assignee={workspace.assignee}
        selectedTaskTitle={activeTask.title}
      />
      <div className="flex min-h-0 flex-1">
        <TaskListPane
          activeTasks={activeTasks}
          completedTasks={completedTasks}
          selectedTaskId={resolvedSelectedTaskId ?? ""}
          reportFilledByTaskId={reportFilledByTaskId}
          onSelectTask={handleSelectTask}
          onRestoreTask={handleRestoreTask}
          onAddTask={handleAddTask}
          onDeleteTask={handleDeleteTask}
        />
        <TaskDetailPane
          task={activeTask}
          delayed={activeTask.delayed}
          onDelayedChange={handleDelayedChange}
          workMemo={workMemos[activeTask.id] ?? ""}
          reportInput={activeReportInput}
          onWorkMemoSave={saveWorkMemo}
          onReportFieldSave={saveReportField}
          onCompleteTask={handleCompleteTask}
          onAddComment={isLocalTask(activeTask) ? addLocalTaskComment : undefined}
          onEditTask={(updates) => handleEditTask(activeTask.id, updates)}
          onDeleteTask={() => handleDeleteTask(activeTask.id)}
        />
        <ExecLinksPane links={execLinks} onAddLink={addExecLink} onDeleteLink={deleteExecLink} onEditLink={editExecLink} />
        <ReportPane
          reportText={reportResult.text}
          warnings={reportResult.warnings}
          open={reportPaneOpen}
          onToggle={toggleReportPane}
          progressSummary={progressSummary}
        />
      </div>
    </div>
  );
}
