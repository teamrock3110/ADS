import Anthropic from "@anthropic-ai/sdk";

import { REPORT_PROMPTS } from "@/lib/report-prompts";
import { type ReportGeneratorInput } from "./types";

export async function generateWithClaude({ meetingType, tasks }: ReportGeneratorInput): Promise<string> {
  const client = new Anthropic();
  const today = new Date().toLocaleDateString("ja-JP", { month: "numeric", day: "numeric" });

  const message = await client.messages.create({
    model: "claude-haiku-4-5",
    max_tokens: 2048,
    system: REPORT_PROMPTS[meetingType],
    messages: [
      {
        role: "user",
        content: `今日の日付: ${today}\n\nタスクデータ:\n${JSON.stringify(tasks, null, 2)}`,
      },
    ],
  });

  return message.content[0].type === "text" ? message.content[0].text : "";
}
