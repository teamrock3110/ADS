"use client";

import { useState } from "react";
import { AlertTriangle, Check, ChevronLeft, ChevronRight, Copy } from "lucide-react";

import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

type ReportPaneProps = {
  reportText: string;
  warnings: string[];
  open: boolean;
  onToggle: () => void;
  progressSummary?: string;
};

export function ReportPane({
  reportText,
  warnings,
  open,
  onToggle,
  progressSummary,
}: ReportPaneProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(reportText);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  };

  if (!open) {
    return (
      <aside className="flex w-10 shrink-0 flex-col border-l border-border bg-background">
        <Tooltip>
          <TooltipTrigger
            render={
              <Button
                variant="ghost"
                size="icon-sm"
                className="mx-auto mt-3 size-8"
                onClick={onToggle}
                aria-label="週次報告書ペインを開く"
              >
                <ChevronLeft />
              </Button>
            }
          />
          <TooltipContent side="left">週次報告書を表示</TooltipContent>
        </Tooltip>
        <span
          className="mt-4 select-none text-center text-xs font-medium text-muted-foreground [writing-mode:vertical-rl]"
          aria-hidden
        >
          週次報告
        </span>
      </aside>
    );
  }

  return (
    <aside className="flex w-72 shrink-0 flex-col bg-background">
      <div className="flex h-12 shrink-0 items-center gap-1 border-b border-border px-2">
        <Tooltip>
          <TooltipTrigger
            render={
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={onToggle}
                aria-label="週次報告書ペインを閉じる"
              >
                <ChevronRight />
              </Button>
            }
          />
          <TooltipContent side="bottom">ペインを閉じる</TooltipContent>
        </Tooltip>
        <span className="min-w-0 flex-1 truncate text-sm font-medium">
          週次報告書
          {progressSummary && (
            <span className="ml-2 text-xs font-normal text-muted-foreground">
              {progressSummary}
            </span>
          )}
        </span>
        <Button variant="ghost" size="sm" onClick={handleCopy}>
          {copied ? <Check /> : <Copy />}
          {copied ? "済" : "コピー"}
        </Button>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-3 p-3">
          {warnings.map((warning) => (
            <div
              key={warning}
              className="flex gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2"
              role="alert"
            >
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-destructive" />
              <p className="text-xs leading-relaxed text-destructive">{warning}</p>
            </div>
          ))}
          <pre className="whitespace-pre-wrap font-sans text-xs leading-relaxed text-muted-foreground">
            {reportText}
          </pre>
        </div>
      </ScrollArea>
    </aside>
  );
}
