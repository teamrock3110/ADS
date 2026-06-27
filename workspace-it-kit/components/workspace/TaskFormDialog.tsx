"use client";

import { useEffect, useState } from "react";

import { type TaskBucket } from "@/lib/it/schema";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export type TaskFormValues = {
  title: string;
  deadline: string;
  bucket: TaskBucket;
  description: string;
};

const BUCKET_LABEL: Record<TaskBucket, string> = {
  today: "今日",
  week: "今週",
  backlog: "バックログ",
};

type TaskFormDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  mode: "add" | "edit";
  initialValues?: Partial<TaskFormValues>;
  onSubmit: (values: TaskFormValues) => void;
};

export function TaskFormDialog({
  open,
  onOpenChange,
  mode,
  initialValues,
  onSubmit,
}: TaskFormDialogProps) {
  const [title, setTitle] = useState(initialValues?.title ?? "");
  const [deadline, setDeadline] = useState(initialValues?.deadline ?? "");
  const [bucket, setBucket] = useState<TaskBucket>(initialValues?.bucket ?? "today");
  const [description, setDescription] = useState(initialValues?.description ?? "");

  useEffect(() => {
    if (open) {
      setTitle(initialValues?.title ?? "");
      setDeadline(initialValues?.deadline ?? "");
      setBucket(initialValues?.bucket ?? "today");
      setDescription(initialValues?.description ?? "");
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const handleSubmit = () => {
    if (!title.trim()) return;
    onSubmit({
      title: title.trim(),
      deadline: deadline.trim(),
      bucket,
      description: description.trim(),
    });
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{mode === "add" ? "タスクを追加" : "タスクを編集"}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3 py-2">
          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium">タイトル</label>
            <Input
              autoFocus
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) handleSubmit();
              }}
              placeholder="タスクのタイトル"
            />
          </div>
          <div className="flex gap-2">
            <div className="flex flex-1 flex-col gap-1.5">
              <label className="text-sm font-medium">期日</label>
              <Input
                value={deadline}
                onChange={(e) => setDeadline(e.target.value)}
                placeholder="7/15"
              />
            </div>
            <div className="flex flex-1 flex-col gap-1.5">
              <label className="text-sm font-medium">バケット</label>
              <Select value={bucket} onValueChange={(v) => setBucket(v as TaskBucket)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(["today", "week", "backlog"] as TaskBucket[]).map((b) => (
                    <SelectItem key={b} value={b}>
                      {BUCKET_LABEL[b]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium">概要（任意）</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="タスクの詳細説明"
              rows={3}
              className="w-full resize-none rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            キャンセル
          </Button>
          <Button onClick={handleSubmit} disabled={!title.trim()}>
            {mode === "add" ? "追加" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
