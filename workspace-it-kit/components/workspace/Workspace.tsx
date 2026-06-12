"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

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
import { type ExecLink, type Task } from "@/lib/it/schema";
import {
  countReportProgress,
  getTaskLinks,
  hasReportProgress,
  loadWorkspaceStorage,
  saveWorkspaceStorage,
  type WorkspaceStorage,
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
  const [tasks] = useState<Task[]>(initialTasks);
  const [selectedTaskId, setSelectedTaskId] = useState<string>("CIT-201");
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

  useEffect(() => {
    const loaded = loadWorkspaceStorage();
    setReportInputs(loaded.reportInputs);
    setWorkMemos(loaded.workMemos);
    setTaskLinks(loaded.taskLinks);
    setDelayedOverrides(loaded.delayedOverrides);
    setCompletedTaskIds(loaded.completedTaskIds);
    setHydrated(true);
  }, []);

  useEffect(() => {
    if (!hydrated) return;

    const data: WorkspaceStorage = {
      reportInputs,
      workMemos,
      taskLinks,
      delayedOverrides,
      completedTaskIds,
    };
    saveWorkspaceStorage(data);
  }, [
    hydrated,
    reportInputs,
    workMemos,
    taskLinks,
    delayedOverrides,
    completedTaskIds,
  ]);

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

  useEffect(() => {
    if (!hydrated) return;
    if (
      activeTasks.length > 0 &&
      isCompleted(completedTaskIds, selectedTaskId)
    ) {
      setSelectedTaskId(activeTasks[0].id);
    }
  }, [hydrated, activeTasks, completedTaskIds, selectedTaskId]);

  const activeTask =
    activeTasks.find((t) => t.id === selectedTaskId) ?? activeTasks[0];

  const storageSnapshot: WorkspaceStorage = useMemo(
    () => ({
      reportInputs,
      workMemos,
      taskLinks,
      delayedOverrides,
      completedTaskIds,
    }),
    [
      reportInputs,
      workMemos,
      taskLinks,
      delayedOverrides,
      completedTaskIds,
    ],
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
            selectedTaskId={selectedTaskId}
            reportFilledByTaskId={reportFilledByTaskId}
            onSelectTask={handleSelectTask}
            onRestoreTask={handleRestoreTask}
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
          selectedTaskId={selectedTaskId}
          reportFilledByTaskId={reportFilledByTaskId}
          onSelectTask={handleSelectTask}
          onRestoreTask={handleRestoreTask}
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
        />
        <ExecLinksPane links={execLinks} onAddLink={addExecLink} />
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
