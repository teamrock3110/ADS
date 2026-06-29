"use client";

import { useState } from "react";
import {
  AlertTriangle,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Loader2,
  Sparkles,
} from "lucide-react";

import { type Task } from "@/lib/it/schema";
import { type WeeklyReportInput } from "@/lib/it/report";
import { type MeetingType } from "@/lib/report-prompts";
import { type ReportTask } from "@/app/api/report/generate/route";
import { type AIProvider } from "@/lib/ai/types";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  allTasks: Task[];
  reportInputs: Record<string, WeeklyReportInput>;
  activeTask?: Task;
};

const AI_MULTI_TABS: { value: Extract<MeetingType, "月" | "金">; label: string }[] = [
  { value: "月", label: "月曜（センター）" },
  { value: "金", label: "金曜（PJ定例）" },
];

function buildReportTasks(
  tasks: Task[],
  reportInputs: Record<string, WeeklyReportInput>,
): ReportTask[] {
  return tasks.map((t) => ({
    id: t.id,
    title: t.title,
    deadline: t.deadline,
    delayed: t.delayed,
    description: t.description,
    comments: t.comments,
    progress: reportInputs[t.id]?.progress,
    issues: reportInputs[t.id]?.issues,
    consult: reportInputs[t.id]?.consult,
  }));
}

export function ReportPane({
  reportText,
  warnings,
  open,
  onToggle,
  progressSummary,
  allTasks,
  reportInputs,
  activeTask,
}: ReportPaneProps) {
  const [aiProvider, setAiProvider] = useState<AIProvider>("claude");
  const [aiReports, setAiReports] = useState<Partial<Record<MeetingType, string>>>({});
  const [aiLoading, setAiLoading] = useState<Partial<Record<MeetingType, boolean>>>({});
  const [aiCopied, setAiCopied] = useState<Partial<Record<MeetingType, boolean>>>({});

  const handleAiGenerate = async (meetingType: MeetingType) => {
    const tasks = activeTask
      ? [buildReportTasks([activeTask], reportInputs)[0]]
      : [];

    if (!tasks.length) return;

    setAiLoading((prev) => ({ ...prev, [meetingType]: true }));
    setAiReports((prev) => ({ ...prev, [meetingType]: "" }));
    try {
      const res = await fetch("/api/report/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ meetingType, tasks, provider: aiProvider }),
      });
      const data = await res.json();
      setAiReports((prev) => ({
        ...prev,
        [meetingType]: data.report ?? data.error ?? "エラーが発生しました",
      }));
    } catch {
      setAiReports((prev) => ({ ...prev, [meetingType]: "通信エラーが発生しました" }));
    } finally {
      setAiLoading((prev) => ({ ...prev, [meetingType]: false }));
    }
  };

  const handleAiCopy = async (meetingType: MeetingType) => {
    const text = aiReports[meetingType];
    if (!text) return;
    await navigator.clipboard.writeText(text);
    setAiCopied((prev) => ({ ...prev, [meetingType]: true }));
    window.setTimeout(() => setAiCopied((prev) => ({ ...prev, [meetingType]: false })), 2000);
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
      {/* ヘッダー */}
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
          会議レポート
          {progressSummary && (
            <span className="ml-2 text-xs font-normal text-muted-foreground">
              {progressSummary}
            </span>
          )}
        </span>
        <div className="flex shrink-0 items-center gap-0.5 rounded border border-border bg-muted px-0.5 py-0.5">
          {(["claude", "gemini"] as const).map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => setAiProvider(p)}
              className={[
                "rounded px-1.5 py-0.5 text-[10px] leading-none transition-colors",
                aiProvider === p
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground",
              ].join(" ")}
            >
              {p === "claude" ? "Claude" : "Gemini"}
            </button>
          ))}
        </div>
      </div>

      {/* タブ */}
      <Tabs defaultValue="火" className="flex min-h-0 flex-1 flex-col">
        <div className="shrink-0 border-b border-border px-2 pt-2">
          <TabsList variant="line" className="w-full justify-start">
            <TabsTrigger value="火" className="text-xs">火曜（PJ個別）</TabsTrigger>
            <TabsTrigger value="月" className="text-xs">月曜</TabsTrigger>
            <TabsTrigger value="金" className="text-xs">金曜</TabsTrigger>
          </TabsList>
        </div>

        {/* 全タブ共通：AI生成 UI */}
        {(["火", "月", "金"] as MeetingType[]).map((value) => (
          <TabsContent
            key={value}
            value={value}
            className="flex min-h-0 flex-1 flex-col gap-0"
          >
            <div className="flex shrink-0 items-center gap-2 border-b border-border px-2 py-1">
              <Button
                size="sm"
                onClick={() => handleAiGenerate(value)}
                disabled={!!aiLoading[value] || !activeTask}
                className="h-7 gap-1 text-xs"
              >
                {aiLoading[value] ? (
                  <Loader2 className="size-3 animate-spin" />
                ) : (
                  <Sparkles className="size-3" />
                )}
                {aiLoading[value] ? "生成中..." : "AI生成"}
              </Button>
              {aiReports[value] && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => handleAiCopy(value)}
                  className="h-7 gap-1 px-2 text-xs"
                >
                  {aiCopied[value] ? <Check className="size-3" /> : <Copy className="size-3" />}
                  {aiCopied[value] ? "済" : "コピー"}
                </Button>
              )}
            </div>

            {aiReports[value] ? (
              <Textarea
                value={aiReports[value]}
                onChange={(e) =>
                  setAiReports((prev) => ({ ...prev, [value]: e.target.value }))
                }
                className="min-h-0 flex-1 resize-none rounded-none border-0 font-mono text-xs focus-visible:ring-0"
              />
            ) : value === "火" ? (
              /* 火曜：AI未生成時はテンプレートを表示 */
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
            ) : (
              <div className="flex flex-1 items-center justify-center">
                <p className="text-xs text-muted-foreground">「AI生成」を押してください</p>
              </div>
            )}
          </TabsContent>
        ))}
      </Tabs>
    </aside>
  );
}
