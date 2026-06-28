import Anthropic from "@anthropic-ai/sdk";
import { NextRequest, NextResponse } from "next/server";

import { type MeetingType, REPORT_PROMPTS } from "@/lib/report-prompts";

export type ReportTask = {
  id: string;
  title: string;
  deadline?: string;
  delayed?: boolean;
  bucket?: string;
  description?: string;
  comments?: string[];
  progress?: string;
  issues?: string;
  consult?: string;
};

export type ReportRequest = {
  meetingType: MeetingType;
  tasks: ReportTask[];
};

export async function POST(req: NextRequest) {
  const body: ReportRequest = await req.json();
  const { meetingType, tasks } = body;

  if (!meetingType || !tasks?.length) {
    return NextResponse.json({ error: "meetingType と tasks は必須です" }, { status: 400 });
  }

  const client = new Anthropic();

  const message = await client.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 2048,
    system: REPORT_PROMPTS[meetingType],
    messages: [
      {
        role: "user",
        content: `今日の日付: ${new Date().toLocaleDateString("ja-JP", { month: "numeric", day: "numeric" })}\n\nタスクデータ:\n${JSON.stringify(tasks, null, 2)}`,
      },
    ],
  });

  const text = message.content[0].type === "text" ? message.content[0].text : "";
  return NextResponse.json({ report: text });
}
