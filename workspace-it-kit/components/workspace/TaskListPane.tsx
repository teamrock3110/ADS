"use client";

import { useRef, useState } from "react";
import { CheckCircle2, ChevronDown, Plus, Trash2 } from "lucide-react";

import { cn } from "@/lib/utils";
import { type Task, isLocalTask } from "@/lib/it/schema";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { DeleteConfirmDialog } from "@/components/workspace/DeleteConfirmDialog";

/**
 * "M/D" 形式の期限を月*100+日の数値に変換する。文字列比較だと "10/1" が
 * "2/1" より前に来てしまうため、月・日をそれぞれ数値として比較する。
 * 期限未設定（空文字）は最優先で表示する。
 */
function deadlineRank(deadline: string): number {
  if (!deadline) return -1;
  const [month, day] = deadline.split("/").map(Number);
  if (Number.isNaN(month) || Number.isNaN(day)) return Number.MAX_SAFE_INTEGER;
  return month * 100 + day;
}

function sortTasks(tasks: Task[]): Task[] {
  return [...tasks].sort((a, b) => {
    const deadlineDiff = deadlineRank(a.deadline) - deadlineRank(b.deadline);
    if (deadlineDiff !== 0) return deadlineDiff;
    return a.id.localeCompare(b.id);
  });
}

type TaskListPaneProps = {
  activeTasks: Task[];
  completedTasks: Task[];
  selectedTaskId: string;
  reportFilledByTaskId: Record<string, boolean>;
  onSelectTask: (id: string) => void;
  onRestoreTask: (id: string) => void;
  onAddTask: (draft: {
    title: string;
    deadline: string;
    description: string;
  }) => void;
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
  const isLocal = isLocalTask(task);

  return (
    <div className="group relative">
      <Tooltip>
        <TooltipTrigger
          render={
            <button
              type="button"
              onClick={onSelect}
              className={cn(
                "flex w-full flex-col gap-1 rounded-lg border-l-2 px-2 py-2 pr-8 text-left transition-colors",
                selected
                  ? "border-l-primary bg-sidebar-accent"
                  : "border-l-transparent hover:bg-sidebar-accent/60",
              )}
            >
              <span className="line-clamp-2 text-sm leading-snug font-medium">
                {task.title}
              </span>
              <span className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                {task.deadline && <span>{task.deadline}</span>}
                {isLocal && (
                  <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
                    LOCAL
                  </Badge>
                )}
                {filled ? (
                  <CheckCircle2 className="size-3.5 text-muted-foreground" />
                ) : (
                  <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
                    未入力
                  </Badge>
                )}
              </span>
            </button>
          }
        />
        {!isLocal && <TooltipContent side="right">{task.id}</TooltipContent>}
      </Tooltip>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          onDelete();
        }}
        className="absolute top-1/2 right-1 -translate-y-1/2 rounded p-1 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:text-destructive"
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
  const [showAddInput, setShowAddInput] = useState(false);
  const [addTitle, setAddTitle] = useState("");
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);
  const addInputRef = useRef<HTMLInputElement>(null);
  const sortedActive = sortTasks(activeTasks);
  const sortedCompleted = sortTasks(completedTasks);

  const handleShowAddInput = () => {
    setShowAddInput(true);
    setAddTitle("");
    requestAnimationFrame(() => addInputRef.current?.focus());
  };

  const handleAddSubmit = () => {
    const title = addTitle.trim();
    if (!title) return;
    onAddTask({ title, deadline: "", description: "" });
    setAddTitle("");
    setShowAddInput(false);
  };

  const handleAddKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleAddSubmit();
    } else if (e.key === "Escape") {
      setAddTitle("");
      setShowAddInput(false);
    }
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
            onClick={handleShowAddInput}
            aria-label="タスクを追加"
          >
            <Plus className="size-4" />
          </Button>
        </div>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-1 p-2">
          {sortedActive.length === 0 && !showAddInput ? (
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

          {showAddInput && (
            <Input
              ref={addInputRef}
              value={addTitle}
              onChange={(e) => setAddTitle(e.target.value)}
              onKeyDown={handleAddKeyDown}
              onBlur={() => {
                if (!addTitle.trim()) setShowAddInput(false);
              }}
              placeholder="タスク名を入力… （Enter で追加）"
              className="h-8 text-sm"
              aria-label="新しいタスク名"
            />
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
                <Badge
                  variant="outline"
                  className="ml-auto h-5 px-1.5 text-[10px]"
                >
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

      <DeleteConfirmDialog
        open={deleteTargetId !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTargetId(null);
        }}
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
