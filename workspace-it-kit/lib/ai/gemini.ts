import { GoogleGenAI } from "@google/genai";
import { REPORT_PROMPTS } from "@/lib/report-prompts";
import { type ReportGeneratorInput } from "./types";

export async function generateWithGemini({ meetingType, tasks }: ReportGeneratorInput): Promise<string> {
  const googleAuthOptions = process.env.GOOGLE_SERVICE_ACCOUNT_KEY
    ? { credentials: JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_KEY) }
    : {};

  const ai = new GoogleGenAI({
    vertexai: true,
    project: process.env.GOOGLE_CLOUD_PROJECT!,
    location: process.env.GOOGLE_CLOUD_LOCATION ?? "asia-northeast1",
    googleAuthOptions,
  });

  const today = new Date().toLocaleDateString("ja-JP", { month: "numeric", day: "numeric" });

  const result = await ai.models.generateContent({
    model: "gemini-2.5-flash",
    contents: [
      {
        role: "user",
        parts: [{ text: `今日の日付: ${today}\n\nタスクデータ:\n${JSON.stringify(tasks, null, 2)}` }],
      },
    ],
    config: {
      systemInstruction: REPORT_PROMPTS[meetingType],
    },
  });

  return result.text ?? "";
}
