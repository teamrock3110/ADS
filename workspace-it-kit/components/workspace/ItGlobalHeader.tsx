"use client";

type ItGlobalHeaderProps = {
  workspaceName: string;
  selectedTaskTitle: string;
};

export function ItGlobalHeader({
  workspaceName,
  selectedTaskTitle,
}: ItGlobalHeaderProps) {
  return (
    <header className="flex h-12 shrink-0 items-center gap-3 border-b border-border bg-background px-4">
      <span className="text-sm font-semibold">{workspaceName}</span>
      <span className="text-muted-foreground">/</span>
      <span className="truncate text-sm text-muted-foreground">
        {selectedTaskTitle}
      </span>
    </header>
  );
}
