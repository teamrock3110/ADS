"use client";

import { useState, type ReactNode } from "react";
import { ChevronDown, Pencil, Plus, Trash2 } from "lucide-react";

import { type Task, type TaskBucket, isLocalTask } from "@/lib/it/schema";
import { type WeeklyReportInput } from "@/lib/it/report";
import { cn } from "@/lib/utils";
import { InlineTextareaField } from "@/components/primitives/InlineTextareaField";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { ScrollArea } from "@/components/ui/scroll-area";
import { DeleteConfirmDialog } from "@/components/workspace/DeleteConfirmDialog";
import { TaskFormDialog } from "@/components/workspace/TaskFormDialog";

type TaskDetailPaneProps = {
  task: Task;
  delayed: boolean;
  onDelayedChange: (delayed: boolean) => void;
  workMemo: string;
  reportInput: WeeklyReportInput;
  onWorkMemoSave: (value: string) => void;
  onReportFieldSave: (
    field: keyof WeeklyReportInput,
    value: string,
  ) => void;
  onCompleteTask: () => void;
  onAddComment?: (body: string) => void;
  onEditTask?: (updates: { title?: string; deadline?: string; bucket?: TaskBucket; description?: string }) => void;
  onDeleteTask?: () => void;
};

function CollapsibleSection({
  title,
  defaultOpen = false,
  children,
}: {
  title: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger
        className={cn(
          "flex w-full items-center gap-2 rounded-md px-1 py-1 text-left",
          "hover:bg-muted/50",
        )}
      >
        <ChevronDown
          className={cn(
            "size-4 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-180",
          )}
        />
        <span className="text-xs font-medium text-muted-foreground">{title}</span>
      </CollapsibleTrigger>
      <CollapsibleContent className="pt-2">{children}</CollapsibleContent>
    </Collapsible>
  );
}

export function TaskDetailPane({
  task,
  delayed,
  onDelayedChange,
  workMemo,
  reportInput,
  onWorkMemoSave,
  onReportFieldSave,
  onCompleteTask,
  onAddComment,
  onEditTask,
  onDeleteTask,
}: TaskDetailPaneProps) {
  const [commentInput, setCommentInput] = useState("");
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const isLocal = isLocalTask(task);

  const handleAddComment = () => {
    const body = commentInput.trim();
    if (!body || !onAddComment) return;
    onAddComment(body);
    setCommentInput("");
  };
  return (
    <section className="flex min-w-[420px] flex-1 flex-col border-r border-border bg-background">
      <div className="flex h-12 shrink-0 items-center gap-2 border-b border-border px-4">
        <span className="text-xs text-muted-foreground">{task.id}</span>
        <Badge variant="outline">期限 {task.deadline}</Badge>
        {delayed && <Badge variant="destructive">遅延</Badge>}
        <div className="ml-auto flex items-center gap-2">
          {onEditTask && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-7 text-xs"
              onClick={() => setShowEditDialog(true)}
            >
              <Pencil className="mr-1 size-3" />
              編集
            </Button>
          )}
          {onDeleteTask && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-7 text-xs text-muted-foreground hover:text-destructive"
              onClick={() => setShowDeleteConfirm(true)}
            >
              <Trash2 className="mr-1 size-3" />
              削除
            </Button>
          )}
          <Button
            type="button"
            variant={delayed ? "secondary" : "ghost"}
            size="sm"
            className="h-7 text-xs"
            onClick={() => onDelayedChange(!delayed)}
          >
            {delayed ? "遅延を解除" : "遅延にする"}
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7 text-xs"
            onClick={onCompleteTask}
          >
            完了にする
          </Button>
        </div>
      </div>
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-base font-medium">{task.title}</h2>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-6 p-4">
          <CollapsibleSection title="概要・コメント">
            <div className="flex flex-col gap-4">
              {task.description && (
                <p className="whitespace-pre-line text-sm leading-relaxed">
                  {task.description}
                </p>
              )}
              {task.comments.length > 0 && (
                <div className="flex flex-col gap-2">
                  {task.comments.map((comment, i) => (
                    <div
                      key={i}
                      className="rounded-md bg-muted/50 px-3 py-2 text-sm text-muted-foreground"
                    >
                      {comment}
                    </div>
                  ))}
                </div>
              )}
              {isLocal && onAddComment && (
                <div className="flex gap-2">
                  <Input
                    value={commentInput}
                    onChange={(e) => setCommentInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && !e.shiftKey) {
                        e.preventDefault();
                        handleAddComment();
                      }
                    }}
                    placeholder="追記を入力… （Enter で追加）"
                    className="h-8 text-sm"
                  />
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-8 shrink-0"
                    onClick={handleAddComment}
                    disabled={!commentInput.trim()}
                  >
                    <Plus className="size-3.5" />
                  </Button>
                </div>
              )}
            </div>
          </CollapsibleSection>

          <CollapsibleSection title="作業メモ（備忘録）">
            <div className="flex flex-col gap-2">
              <p className="text-xs text-muted-foreground">
                調査メモ用。定例報告には含めません。
              </p>
              <InlineTextareaField
                key={`${task.id}-memo`}
                value={workMemo}
                onSave={onWorkMemoSave}
                ariaLabel={`${task.id} の作業メモ`}
                placeholder="手順・注意点・調査メモを記入..."
              />
            </div>
          </CollapsibleSection>

          <div className="flex flex-col gap-4 border-t border-border pt-4">
            <div className="flex flex-col gap-1">
              <span className="text-sm font-medium">定例報告の入力</span>
              <p className="text-xs text-muted-foreground">
                定例用の最新稿です。上書き保存され、右の週次報告書に反映されます。
              </p>
            </div>

            <div className="flex flex-col gap-2">
              <span className="text-xs font-medium text-muted-foreground">
                進捗
                <Badge variant="outline" className="ml-2 h-5 px-1.5 text-[10px]">
                  必須
                </Badge>
              </span>
              <InlineTextareaField
                key={`${task.id}-progress`}
                value={reportInput.progress}
                onSave={(v) => onReportFieldSave("progress", v)}
                ariaLabel={`${task.id} の進捗`}
                placeholder="例: Claude Codeの初期セットアップ完了"
              />
            </div>

            <div className="flex flex-col gap-2">
              <span className="text-xs font-medium text-muted-foreground">
                遅延理由・課題
                <Badge variant="secondary" className="ml-2 h-5 px-1.5 text-[10px]">
                  任意
                </Badge>
              </span>
              <InlineTextareaField
                key={`${task.id}-issues`}
                value={reportInput.issues}
                onSave={(v) => onReportFieldSave("issues", v)}
                ariaLabel={`${task.id} の遅延理由・課題`}
                placeholder="例: Claude CodeからGoogleDriveのファイルが閲覧できない事象が発生"
              />
            </div>

            <div className="flex flex-col gap-2">
              <span className="text-xs font-medium text-muted-foreground">
                相談・作業承認依頼
                <Badge variant="secondary" className="ml-2 h-5 px-1.5 text-[10px]">
                  任意
                </Badge>
              </span>
              <InlineTextareaField
                key={`${task.id}-consult`}
                value={reportInput.consult}
                onSave={(v) => onReportFieldSave("consult", v)}
                ariaLabel={`${task.id} の相談・作業承認依頼`}
                placeholder="例: GoogleWorkSpaceにClaudecodeの権限付与してもよろしいでしょうか。"
              />
            </div>
          </div>
        </div>
      </ScrollArea>

      {onEditTask && (
        <TaskFormDialog
          open={showEditDialog}
          onOpenChange={setShowEditDialog}
          mode="edit"
          initialValues={{
            title: task.title,
            deadline: task.deadline,
            bucket: task.bucket,
            description: task.description,
          }}
          onSubmit={(values) => onEditTask(values)}
        />
      )}

      {onDeleteTask && (
        <DeleteConfirmDialog
          open={showDeleteConfirm}
          onOpenChange={setShowDeleteConfirm}
          title="タスクを削除"
          itemName={task.title}
          description={`「${task.title}」を削除します。関連リンクや報告入力も失われます。`}
          onConfirm={onDeleteTask}
        />
      )}
    </section>
  );
}
