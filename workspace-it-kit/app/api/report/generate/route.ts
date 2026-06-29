import { NextRequest, NextResponse } from "next/server";

import { type MeetingType } from "@/lib/report-prompts";
import { type AIProvider } from "@/lib/ai/types";
import { generateWithClaude } from "@/lib/ai/claude";
import { generateWithGemini } from "@/lib/ai/gemini";

export type ReportTask = {
  id: string;
  title: string;
  deadline?: string;
  delayed?: boolean;
  description?: string;
  comments?: string[];
  progress?: string;
  issues?: string;
  consult?: string;
};

export type ReportRequest = {
  meetingType: MeetingType;
  tasks: ReportTask[];
  provider?: AIProvider;
};

export async function POST(req: NextRequest) {
  const body: ReportRequest = await req.json();
  const { meetingType, tasks, provider = "claude" } = body;

  if (!meetingType || !tasks?.length) {
    return NextResponse.json({ error: "meetingType と tasks は必須です" }, { status: 400 });
  }

  const input = { meetingType, tasks };
  try {
    const report =
      provider === "gemini"
        ? await generateWithGemini(input)
        : await generateWithClaude(input);
    return NextResponse.json({ report });
  } catch (e) {
    console.error("[report/generate]", e);
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
