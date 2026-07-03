"use client";

import { Info } from "lucide-react";

import { type Task } from "@/lib/it/schema";
import { type WeeklyReportInput } from "@/lib/it/report";
import { InlineTextareaField } from "@/components/primitives/InlineTextareaField";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

type ReportInputPaneProps = {
  task: Task;
  reportInput: WeeklyReportInput;
  onReportFieldSave: (field: keyof WeeklyReportInput, value: string) => void;
};

export function ReportInputPane({
  task,
  reportInput,
  onReportFieldSave,
}: ReportInputPaneProps) {
  return (
    <section className="flex w-96 shrink-0 flex-col border-r border-border bg-background">
      <div className="flex h-12 shrink-0 items-center gap-1.5 border-b border-border px-4">
        <span className="text-sm font-medium">定例報告の入力</span>
        <Tooltip>
          <TooltipTrigger
            render={
              <button
                type="button"
                className="text-muted-foreground hover:text-foreground"
              >
                <Info className="size-3.5" />
              </button>
            }
          />
          <TooltipContent>
            定例用の最新稿です。上書き保存され、右の週次報告書に反映されます。
          </TooltipContent>
        </Tooltip>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-4 p-4">
          <div className="flex flex-col gap-2">
            <span className="text-sm font-medium">
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
              placeholder="今週の進捗を記入…"
            />
          </div>

          <div className="flex flex-col gap-2">
            <span className="text-sm font-medium">
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
              placeholder="遅延・課題があれば記入…"
            />
          </div>

          <div className="flex flex-col gap-2">
            <span className="text-sm font-medium">
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
              placeholder="相談・承認依頼があれば記入…"
            />
          </div>
        </div>
      </ScrollArea>
    </section>
  );
}
