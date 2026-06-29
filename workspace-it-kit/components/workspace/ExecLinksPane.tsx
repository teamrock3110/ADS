"use client";

import { useState } from "react";
import { ExternalLink, Pencil, Plus, Trash2 } from "lucide-react";

import { type ExecLink } from "@/lib/it/schema";
import { execLinkHostname } from "@/lib/it/links";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";

type ExecLinksPaneProps = {
  links: ExecLink[];
  onAddLink: (link: Omit<ExecLink, "id">) => void;
  onDeleteLink: (linkId: string) => void;
  onEditLink: (linkId: string, updated: Omit<ExecLink, "id">) => void;
};

type EditState = {
  id: string;
  label: string;
  url: string;
};

export function ExecLinksPane({ links, onAddLink, onDeleteLink, onEditLink }: ExecLinksPaneProps) {
  const [label, setLabel] = useState("");
  const [url, setUrl] = useState("");
  const [editing, setEditing] = useState<EditState | null>(null);
  const [addError, setAddError] = useState<string | null>(null);

  const handleAdd = () => {
    const trimmedLabel = label.trim();
    const trimmedUrl = url.trim();
    if (!trimmedLabel) { setAddError("ラベルを入力してください"); return; }
    if (!trimmedUrl) { setAddError("URLを入力してください"); return; }
    try {
      new URL(trimmedUrl);
    } catch {
      setAddError("正しいURL形式で入力してください（例: https://...）");
      return;
    }
    setAddError(null);
    onAddLink({ label: trimmedLabel, url: trimmedUrl });
    setLabel("");
    setUrl("");
  };

  const startEdit = (link: ExecLink) => {
    setEditing({ id: link.id, label: link.label, url: link.url });
  };

  const handleEditSave = () => {
    if (!editing) return;
    const trimmedLabel = editing.label.trim();
    const trimmedUrl = editing.url.trim();
    if (!trimmedLabel || !trimmedUrl) return;
    try {
      new URL(trimmedUrl);
    } catch {
      return;
    }
    onEditLink(editing.id, { label: trimmedLabel, url: trimmedUrl });
    setEditing(null);
  };

  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-border bg-background">
      <div className="flex h-12 shrink-0 items-center justify-between border-b border-border px-3">
        <span className="text-sm font-medium">関連リンク</span>
        <span className="text-xs text-muted-foreground">{links.length}件</span>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-2 p-2">
          {links.length === 0 ? (
            <p className="px-2 py-4 text-sm text-muted-foreground">
              リンク未登録。下のフォームから追加できます。
            </p>
          ) : (
            links.map((link) =>
              editing?.id === link.id ? (
                <div
                  key={link.id}
                  className="flex flex-col gap-2 rounded-lg border border-border bg-card p-3"
                >
                  <Input
                    value={editing.label}
                    onChange={(e) => setEditing({ ...editing, label: e.target.value })}
                    placeholder="ラベル"
                    aria-label="ラベルを編集"
                    autoFocus
                  />
                  <Input
                    value={editing.url}
                    onChange={(e) => setEditing({ ...editing, url: e.target.value })}
                    type="url"
                    placeholder="https://..."
                    aria-label="URLを編集"
                  />
                  <div className="flex gap-2">
                    <Button type="button" size="sm" onClick={handleEditSave} className="flex-1">
                      保存
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => setEditing(null)}
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
                      <p className="truncate text-sm font-medium">{link.label}</p>
                      <p className="truncate text-xs text-muted-foreground">
                        {execLinkHostname(link.url)}
                      </p>
                    </div>
                    <ExternalLink className="size-4 shrink-0 text-muted-foreground" />
                  </a>
                  <div className="flex shrink-0 opacity-0 transition-opacity group-hover:opacity-100">
                    <button
                      type="button"
                      onClick={() => startEdit(link)}
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
              )
            )
          )}
        </div>
      </ScrollArea>
      <div className="flex shrink-0 flex-col gap-2 border-t border-border p-3">
        <span className="text-xs font-medium text-muted-foreground">
          <Plus className="mr-1 inline size-3" />
          リンク追加
        </span>
        <Input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") handleAdd(); }}
          placeholder="ラベルを入力…"
          aria-label="リンクラベル"
        />
        <Input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") handleAdd(); }}
          type="url"
          placeholder="https://..."
          aria-label="リンクURL"
        />
        {addError && (
          <p className="text-xs text-destructive">{addError}</p>
        )}
        <Button type="button" variant="secondary" size="sm" onClick={handleAdd}>
          追加
        </Button>
      </div>
    </aside>
  );
}
