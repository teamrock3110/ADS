"use client";

import { useState } from "react";
import { ChevronDown } from "lucide-react";

import { cn } from "@/lib/utils";
import { type Task, isLocalTask } from "@/lib/it/schema";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { ScrollArea } from "@/components/ui/scroll-area";

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
};

function TaskRow({
  task,
  selected,
  filled,
  onSelect,
}: {
  task: Task;
  selected: boolean;
  filled: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "flex w-full flex-col gap-1 rounded-md border-l-2 px-2 py-2 text-left transition-colors",
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
  );
}

export function TaskListPane({
  activeTasks,
  completedTasks,
  selectedTaskId,
  reportFilledByTaskId,
  onSelectTask,
  onRestoreTask,
}: TaskListPaneProps) {
  const [completedOpen, setCompletedOpen] = useState(false);
  const sortedActive = sortTasks(activeTasks);
  const sortedCompleted = sortTasks(completedTasks);

  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-border bg-sidebar">
      <div className="flex h-12 shrink-0 items-center justify-between border-b border-border px-3">
        <span className="text-sm font-medium">タスク</span>
        <Badge variant="secondary">{activeTasks.length}件</Badge>
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
    </aside>
  );
}
