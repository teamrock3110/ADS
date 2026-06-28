import { REPORT_PROMPTS } from "@/lib/report-prompts";
import { type ReportGeneratorInput } from "./types";

export async function generateWithGemini({ meetingType, tasks }: ReportGeneratorInput): Promise<string> {
  const { VertexAI } = await import("@google-cloud/vertexai");

  const vertexAI = new VertexAI({
    project: process.env.GOOGLE_CLOUD_PROJECT!,
    location: process.env.GOOGLE_CLOUD_LOCATION ?? "asia-northeast1",
  });

  const model = vertexAI.getGenerativeModel({ model: "gemini-2.5-flash" });
  const today = new Date().toLocaleDateString("ja-JP", { month: "numeric", day: "numeric" });

  const result = await model.generateContent({
    systemInstruction: REPORT_PROMPTS[meetingType],
    contents: [
      {
        role: "user",
        parts: [{ text: `今日の日付: ${today}\n\nタスクデータ:\n${JSON.stringify(tasks, null, 2)}` }],
      },
    ],
  });

  return result.response.candidates?.[0]?.content?.parts?.[0]?.text ?? "";
}
