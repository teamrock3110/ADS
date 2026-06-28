"use client";

import { Badge } from "@/components/ui/badge";

type ItGlobalHeaderProps = {
  workspaceName: string;
  assignee: string;
  selectedTaskTitle: string;
};

export function ItGlobalHeader({
  workspaceName,
  assignee,
  selectedTaskTitle,
}: ItGlobalHeaderProps) {
  return (
    <header className="flex h-12 shrink-0 items-center gap-3 border-b border-border bg-background px-4">
      <span className="text-sm font-semibold">{workspaceName}</span>
      <span className="text-muted-foreground">/</span>
      <span className="truncate text-sm text-muted-foreground">
        {selectedTaskTitle}
      </span>
      <div className="ml-auto flex items-center gap-2">
        <span className="text-xs text-muted-foreground">担当: {assignee}</span>
        <Badge variant="outline">ブラウザに保存</Badge>
      </div>
    </header>
  );
}
