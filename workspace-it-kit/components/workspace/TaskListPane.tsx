"use client";

import { useState } from "react";
import { ChevronDown, Plus, Trash2 } from "lucide-react";

import { cn } from "@/lib/utils";
import { type Task, type TaskBucket, isLocalTask } from "@/lib/it/schema";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { ScrollArea } from "@/components/ui/scroll-area";
import { DeleteConfirmDialog } from "@/components/workspace/DeleteConfirmDialog";
import { TaskFormDialog, type TaskFormValues } from "@/components/workspace/TaskFormDialog";

const BUCKET_WEIGHT = { today: 0, week: 1, backlog: 2 } as const;

function sortTasks(tasks: Task[]): Task[] {
  return [...tasks].sort((a, b) => {
    if (a.delayed !== b.delayed) return a.delayed ? -1 : 1;
    const bucketDiff = BUCKET_WEIGHT[a.bucket] - BUCKET_WEIGHT[b.bucket];
    if (bucketDiff !== 0) return bucketDiff;
    return a.deadline.localeCompare(b.deadline);
  });
}

type TaskListPaneProps = {
  activeTasks: Task[];
  completedTasks: Task[];
  selectedTaskId: string;
  reportFilledByTaskId: Record<string, boolean>;
  onSelectTask: (id: string) => void;
  onRestoreTask: (id: string) => void;
  onAddTask: (draft: { title: string; deadline: string; bucket: TaskBucket; description: string }) => void;
  onDeleteTask: (id: string) => void;
};

function TaskRow({
  task,
  selected,
  filled,
  onSelect,
  onDelete,
}: {
  task: Task;
  selected: boolean;
  filled: boolean;
  onSelect: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="group relative">
      <button
        type="button"
        onClick={onSelect}
        className={cn(
          "flex w-full flex-col gap-1 rounded-md border-l-2 px-2 py-2 pr-8 text-left transition-colors",
          selected
            ? "border-l-primary bg-sidebar-accent"
            : "border-l-transparent hover:bg-sidebar-accent/60",
        )}
      >
        <span className="line-clamp-2 text-sm font-medium leading-snug">
          {task.title}
        </span>
        <span className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
          {task.id} · {task.deadline}
          {isLocalTask(task) && (
            <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
              LOCAL
            </Badge>
          )}
          {task.delayed && (
            <Badge variant="destructive" className="h-5 px-1.5 text-[10px]">
              遅延
            </Badge>
          )}
          <Badge
            variant={filled ? "secondary" : "outline"}
            className={cn(
              "h-5 px-1.5 text-[10px]",
              !filled && "text-muted-foreground",
            )}
          >
            {filled ? "報告済" : "未入力"}
          </Badge>
        </span>
      </button>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          onDelete();
        }}
        className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground opacity-0 transition-opacity hover:text-destructive group-hover:opacity-100"
        aria-label={`${task.title}を削除`}
      >
        <Trash2 className="size-3.5" />
      </button>
    </div>
  );
}

export function TaskListPane({
  activeTasks,
  completedTasks,
  selectedTaskId,
  reportFilledByTaskId,
  onSelectTask,
  onRestoreTask,
  onAddTask,
  onDeleteTask,
}: TaskListPaneProps) {
  const [completedOpen, setCompletedOpen] = useState(false);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);
  const sortedActive = sortTasks(activeTasks);
  const sortedCompleted = sortTasks(completedTasks);

  const handleAddSubmit = (values: TaskFormValues) => {
    onAddTask(values);
  };

  const deleteTargetTask = deleteTargetId
    ? activeTasks.find((t) => t.id === deleteTargetId)
    : null;

  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-border bg-sidebar">
      <div className="flex h-12 shrink-0 items-center justify-between border-b border-border px-3">
        <span className="text-sm font-medium">タスク</span>
        <div className="flex items-center gap-1">
          <Badge variant="secondary">{activeTasks.length}件</Badge>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-7"
            onClick={() => setShowAddDialog(true)}
            aria-label="タスクを追加"
          >
            <Plus className="size-4" />
          </Button>
        </div>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-1 p-2">
          {sortedActive.length === 0 ? (
            <p className="px-2 py-4 text-sm text-muted-foreground">
              進行中のタスクはありません。
            </p>
          ) : (
            sortedActive.map((task) => (
              <TaskRow
                key={task.id}
                task={task}
                selected={selectedTaskId === task.id}
                filled={reportFilledByTaskId[task.id] ?? false}
                onSelect={() => onSelectTask(task.id)}
                onDelete={() => setDeleteTargetId(task.id)}
              />
            ))
          )}

          {sortedCompleted.length > 0 && (
            <Collapsible
              open={completedOpen}
              onOpenChange={setCompletedOpen}
              className="mt-2 border-t border-border pt-2"
            >
              <CollapsibleTrigger
                className={cn(
                  "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left",
                  "hover:bg-sidebar-accent/60",
                )}
              >
                <ChevronDown
                  className={cn(
                    "size-4 shrink-0 text-muted-foreground transition-transform",
                    completedOpen && "rotate-180",
                  )}
                />
                <span className="text-xs font-medium text-muted-foreground">
                  完了済み
                </span>
                <Badge variant="outline" className="ml-auto h-5 px-1.5 text-[10px]">
                  {sortedCompleted.length}
                </Badge>
              </CollapsibleTrigger>
              <CollapsibleContent className="flex flex-col gap-1 pt-1">
                {sortedCompleted.map((task) => (
                  <div
                    key={task.id}
                    className="flex flex-col gap-1 rounded-md bg-muted/30 px-2 py-2"
                  >
                    <span className="line-clamp-2 text-sm text-muted-foreground">
                      {task.title}
                    </span>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs text-muted-foreground">
                        {task.id}
                      </span>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-7 text-xs"
                        onClick={() => onRestoreTask(task.id)}
                      >
                        戻す
                      </Button>
                    </div>
                  </div>
                ))}
              </CollapsibleContent>
            </Collapsible>
          )}
        </div>
      </ScrollArea>

      <TaskFormDialog
        open={showAddDialog}
        onOpenChange={setShowAddDialog}
        mode="add"
        onSubmit={handleAddSubmit}
      />

      <DeleteConfirmDialog
        open={deleteTargetId !== null}
        onOpenChange={(open) => { if (!open) setDeleteTargetId(null); }}
        title="タスクを削除"
        itemName={deleteTargetTask?.title ?? ""}
        description={
          deleteTargetTask
            ? `「${deleteTargetTask.title}」を削除します。関連リンクや報告入力も失われます。`
            : undefined
        }
        onConfirm={() => {
          if (deleteTargetId) onDeleteTask(deleteTargetId);
          setDeleteTargetId(null);
        }}
      />
    </aside>
  );
}
