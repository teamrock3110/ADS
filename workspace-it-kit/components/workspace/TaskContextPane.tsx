"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  ChevronDown,
  ExternalLink,
  MoreHorizontal,
  Pencil,
  Plus,
  Trash2,
} from "lucide-react";

import { type ExecLink, type Task, isLocalTask } from "@/lib/it/schema";
import { execLinkHostname } from "@/lib/it/links";
import { cn } from "@/lib/utils";
import { InlineTextareaField } from "@/components/primitives/InlineTextareaField";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { DeleteConfirmDialog } from "@/components/workspace/DeleteConfirmDialog";

type TaskContextPaneProps = {
  task: Task;
  workMemo: string;
  onWorkMemoSave: (value: string) => void;
  onCompleteTask: () => void;
  onAddComment?: (body: string) => void;
  onEditTask?: (updates: {
    title?: string;
    deadline?: string;
    description?: string;
  }) => void;
  onDeleteTask?: () => void;
  links: ExecLink[];
  onAddLink: (link: Omit<ExecLink, "id">) => void;
  onDeleteLink: (linkId: string) => void;
  onEditLink: (linkId: string, updated: Omit<ExecLink, "id">) => void;
};

function CollapsibleSection({
  title,
  badge,
  defaultOpen = false,
  children,
}: {
  title: string;
  badge?: string;
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
        <span className="text-xs font-medium text-muted-foreground">
          {title}
        </span>
        {badge !== undefined && (
          <span className="ml-auto text-xs text-muted-foreground">{badge}</span>
        )}
      </CollapsibleTrigger>
      <CollapsibleContent className="pt-2">{children}</CollapsibleContent>
    </Collapsible>
  );
}

function InlineTitleField({
  value,
  onSave,
}: {
  value: string;
  onSave: (v: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setDraft(value);
  }, [value]);

  useEffect(() => {
    if (editing) inputRef.current?.focus();
  }, [editing]);

  const commit = () => {
    const trimmed = draft.trim();
    if (trimmed && trimmed !== value) onSave(trimmed);
    else setDraft(value);
    setEditing(false);
  };

  if (editing) {
    return (
      <Input
        ref={inputRef}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter" && !e.nativeEvent.isComposing) {
            e.preventDefault();
            commit();
          } else if (e.key === "Escape") {
            setDraft(value);
            setEditing(false);
          }
        }}
        className="h-9 text-base font-medium"
        aria-label="タスクタイトルを編集"
      />
    );
  }

  return (
    <h2
      role="button"
      tabIndex={0}
      onClick={() => setEditing(true)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") setEditing(true);
      }}
      className="cursor-text text-base font-medium hover:text-primary/80"
      title="クリックして編集"
    >
      {value}
    </h2>
  );
}

function InlineDeadlineField({
  value,
  onSave,
}: {
  value: string;
  onSave: (v: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setDraft(value);
  }, [value]);

  useEffect(() => {
    if (editing) inputRef.current?.focus();
  }, [editing]);

  const commit = () => {
    const trimmed = draft.trim();
    if (trimmed !== value) onSave(trimmed);
    else setDraft(value);
    setEditing(false);
  };

  if (editing) {
    return (
      <Input
        ref={inputRef}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter" && !e.nativeEvent.isComposing) {
            e.preventDefault();
            commit();
          } else if (e.key === "Escape") {
            setDraft(value);
            setEditing(false);
          }
        }}
        className="h-7 w-20 text-xs"
        placeholder="7/15"
        aria-label="期日を編集"
      />
    );
  }

  return (
    <Badge
      variant="outline"
      role="button"
      tabIndex={0}
      onClick={() => setEditing(true)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") setEditing(true);
      }}
      className="cursor-text hover:bg-accent"
      title="クリックして編集"
    >
      期限 {value || "未設定"}
    </Badge>
  );
}

type LinkEditState = { id: string; label: string; url: string };

export function TaskContextPane({
  task,
  workMemo,
  onWorkMemoSave,
  onCompleteTask,
  onAddComment,
  onEditTask,
  onDeleteTask,
  links,
  onAddLink,
  onDeleteLink,
  onEditLink,
}: TaskContextPaneProps) {
  const [commentInput, setCommentInput] = useState("");
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [linkLabel, setLinkLabel] = useState("");
  const [linkUrl, setLinkUrl] = useState("");
  const [linkEditing, setLinkEditing] = useState<LinkEditState | null>(null);
  const [linkAddError, setLinkAddError] = useState<string | null>(null);
  const [linkFormOpen, setLinkFormOpen] = useState(false);
  const isLocal = isLocalTask(task);

  const handleAddComment = () => {
    const body = commentInput.trim();
    if (!body || !onAddComment) return;
    onAddComment(body);
    setCommentInput("");
  };

  const closeLinkForm = () => {
    setLinkFormOpen(false);
    setLinkLabel("");
    setLinkUrl("");
    setLinkAddError(null);
  };

  const handleAddLink = () => {
    const trimmedLabel = linkLabel.trim();
    const trimmedUrl = linkUrl.trim();
    if (!trimmedUrl) {
      setLinkAddError("URLを入力してください");
      return;
    }
    try {
      new URL(trimmedUrl);
    } catch {
      setLinkAddError("正しいURL形式で入力してください（例: https://...）");
      return;
    }
    // リンク名は任意。省略時はホスト名で補完する
    onAddLink({
      label: trimmedLabel || execLinkHostname(trimmedUrl),
      url: trimmedUrl,
    });
    closeLinkForm();
  };

  const handleLinkInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") handleAddLink();
    if (e.key === "Escape") closeLinkForm();
  };

  const handleLinkEditSave = () => {
    if (!linkEditing) return;
    const trimmedLabel = linkEditing.label.trim();
    const trimmedUrl = linkEditing.url.trim();
    if (!trimmedLabel || !trimmedUrl) return;
    try {
      new URL(trimmedUrl);
    } catch {
      return;
    }
    onEditLink(linkEditing.id, { label: trimmedLabel, url: trimmedUrl });
    setLinkEditing(null);
  };

  return (
    <section className="flex min-w-[380px] flex-1 flex-col border-r border-border bg-background">
      <div className="flex h-12 shrink-0 items-center gap-2 border-b border-border px-4">
        <span className="text-xs text-muted-foreground">{task.id}</span>
        {onEditTask ? (
          <InlineDeadlineField
            value={task.deadline}
            onSave={(deadline) => onEditTask({ deadline })}
          />
        ) : (
          <Badge variant="outline">期限 {task.deadline || "未設定"}</Badge>
        )}
        <div className="ml-auto flex items-center gap-2">
          <Button
            type="button"
            variant="default"
            size="sm"
            className="h-7 text-xs"
            onClick={onCompleteTask}
          >
            完了にする
          </Button>
          {onDeleteTask && (
            <DropdownMenu>
              <DropdownMenuTrigger
                render={
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground"
                  >
                    <MoreHorizontal className="size-4" />
                  </Button>
                }
              />
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  variant="destructive"
                  onClick={() => setShowDeleteConfirm(true)}
                >
                  <Trash2 />
                  削除
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </div>

      <div className="border-b border-border px-4 py-3">
        {onEditTask ? (
          <InlineTitleField
            value={task.title}
            onSave={(title) => onEditTask({ title })}
          />
        ) : (
          <h2 className="text-base font-medium">{task.title}</h2>
        )}
      </div>

      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-6 p-4">
          <CollapsibleSection key={task.id} title="概要・コメント" defaultOpen>
            <div className="flex flex-col gap-4">
              {onEditTask ? (
                <InlineTextareaField
                  key={`${task.id}-description`}
                  value={task.description}
                  onSave={(description) => onEditTask({ description })}
                  ariaLabel={`${task.id} の概要`}
                  placeholder="タスクの詳細説明を入力..."
                />
              ) : task.description ? (
                <p className="text-sm leading-relaxed whitespace-pre-line">
                  {task.description}
                </p>
              ) : null}
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

          <CollapsibleSection
            key={`memo-${task.id}`}
            title="作業メモ（備忘録）"
          >
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

          <CollapsibleSection
            key={`links-${task.id}`}
            title="関連リンク"
            badge={`${links.length}件`}
            defaultOpen
          >
            <div className="flex flex-col gap-3">
              {links.length > 0 && (
                <div className="flex flex-col gap-2">
                  {links.map((link) =>
                    linkEditing?.id === link.id ? (
                      <div
                        key={link.id}
                        className="flex flex-col gap-2 rounded-lg border border-border bg-card p-3"
                      >
                        <Input
                          value={linkEditing.label}
                          onChange={(e) =>
                            setLinkEditing({
                              ...linkEditing,
                              label: e.target.value,
                            })
                          }
                          placeholder="リンク名"
                          aria-label="リンク名を編集"
                          autoFocus
                        />
                        <Input
                          value={linkEditing.url}
                          onChange={(e) =>
                            setLinkEditing({
                              ...linkEditing,
                              url: e.target.value,
                            })
                          }
                          type="url"
                          placeholder="https://..."
                          aria-label="URLを編集"
                        />
                        <div className="flex gap-2">
                          <Button
                            type="button"
                            size="sm"
                            onClick={handleLinkEditSave}
                            className="flex-1"
                          >
                            保存
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => setLinkEditing(null)}
                            className="flex-1"
                          >
                            キャンセル
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <div
                        key={link.id}
                        className="group flex items-center gap-2 rounded-lg border border-border bg-card p-3 transition-colors hover:bg-accent/40"
                      >
                        <a
                          href={link.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex min-w-0 flex-1 items-center gap-3"
                        >
                          <div className="min-w-0 flex-1">
                            <p className="truncate text-sm font-medium">
                              {link.label}
                            </p>
                            <p className="truncate text-xs text-muted-foreground">
                              {execLinkHostname(link.url)}
                            </p>
                          </div>
                          <ExternalLink className="size-4 shrink-0 text-muted-foreground" />
                        </a>
                        <div className="flex shrink-0 opacity-0 transition-opacity group-hover:opacity-100">
                          <button
                            type="button"
                            onClick={() =>
                              setLinkEditing({
                                id: link.id,
                                label: link.label,
                                url: link.url,
                              })
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground"
                            aria-label={`${link.label}を編集`}
                          >
                            <Pencil className="size-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => onDeleteLink(link.id)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive"
                            aria-label={`${link.label}を削除`}
                          >
                            <Trash2 className="size-3.5" />
                          </button>
                        </div>
                      </div>
                    ),
                  )}
                </div>
              )}
              {linkFormOpen ? (
                <div className="flex flex-col gap-2 rounded-lg border border-border bg-card p-3">
                  <Input
                    value={linkLabel}
                    onChange={(e) => setLinkLabel(e.target.value)}
                    onKeyDown={handleLinkInputKeyDown}
                    placeholder="例: 設定手順書（省略可）"
                    aria-label="リンク名"
                    autoFocus
                  />
                  <Input
                    value={linkUrl}
                    onChange={(e) => setLinkUrl(e.target.value)}
                    onKeyDown={handleLinkInputKeyDown}
                    type="url"
                    placeholder="https://..."
                    aria-label="リンクURL"
                  />
                  {linkAddError && (
                    <p className="text-xs text-destructive">{linkAddError}</p>
                  )}
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      size="sm"
                      onClick={handleAddLink}
                      className="flex-1"
                    >
                      追加
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={closeLinkForm}
                      className="flex-1"
                    >
                      キャンセル
                    </Button>
                  </div>
                </div>
              ) : (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="w-full"
                  onClick={() => setLinkFormOpen(true)}
                >
                  <Plus className="size-4" />
                  リンクを追加
                </Button>
              )}
            </div>
          </CollapsibleSection>
        </div>
      </ScrollArea>

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
