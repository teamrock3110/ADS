"use client";

import { useState } from "react";
import { ExternalLink, Plus, Trash2 } from "lucide-react";

import { type ExecLink, type ExecLinkKind } from "@/lib/it/schema";
import {
  EXEC_LINK_KIND_LABEL,
  execLinkHostname,
} from "@/lib/it/links";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const KINDS: ExecLinkKind[] = ["slack", "slides", "sheet", "doc", "other"];

type ExecLinksPaneProps = {
  links: ExecLink[];
  onAddLink: (link: Omit<ExecLink, "id">) => void;
  onDeleteLink: (linkId: string) => void;
};

export function ExecLinksPane({ links, onAddLink, onDeleteLink }: ExecLinksPaneProps) {
  const [label, setLabel] = useState("");
  const [url, setUrl] = useState("");
  const [kind, setKind] = useState<ExecLinkKind>("other");

  const handleAdd = () => {
    const trimmedLabel = label.trim();
    const trimmedUrl = url.trim();
    if (!trimmedLabel || !trimmedUrl) return;
    try {
      new URL(trimmedUrl);
    } catch {
      return;
    }
    onAddLink({ kind, label: trimmedLabel, url: trimmedUrl });
    setLabel("");
    setUrl("");
    setKind("other");
  };

  return (
    <aside className="flex w-80 shrink-0 flex-col border-r border-border bg-background">
      <div className="flex h-12 shrink-0 items-center justify-between border-b border-border px-3">
        <span className="text-sm font-medium">関連リンク</span>
        <Badge variant="outline">{links.length}件</Badge>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-2 p-2">
          {links.length === 0 ? (
            <p className="px-2 py-4 text-sm text-muted-foreground">
              リンク未登録。下のフォームから追加できます。
            </p>
          ) : (
            links.map((link) => (
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
                  <Badge variant="secondary" className="shrink-0">
                    {EXEC_LINK_KIND_LABEL[link.kind]}
                  </Badge>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{link.label}</p>
                    <p className="truncate text-xs text-muted-foreground">
                      {execLinkHostname(link.url)}
                    </p>
                  </div>
                  <ExternalLink className="size-4 shrink-0 text-muted-foreground" />
                </a>
                <button
                  type="button"
                  onClick={() => onDeleteLink(link.id)}
                  className="shrink-0 rounded p-1 text-muted-foreground opacity-0 transition-opacity hover:text-destructive group-hover:opacity-100"
                  aria-label={`${link.label}を削除`}
                >
                  <Trash2 className="size-3.5" />
                </button>
              </div>
            ))
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
          placeholder="ラベル（例: 依頼 Slack）"
          aria-label="リンクラベル"
        />
        <Input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          type="url"
          placeholder="https://..."
          aria-label="リンクURL"
        />
        <Select value={kind} onValueChange={(v) => setKind(v as ExecLinkKind)}>
          <SelectTrigger size="sm">
            <SelectValue placeholder="種類" />
          </SelectTrigger>
          <SelectContent>
            {KINDS.map((k) => (
              <SelectItem key={k} value={k}>
                {EXEC_LINK_KIND_LABEL[k]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button type="button" variant="secondary" size="sm" onClick={handleAdd}>
          追加
        </Button>
      </div>
    </aside>
  );
}
