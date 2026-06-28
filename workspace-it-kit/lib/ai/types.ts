import { type MeetingType } from "@/lib/report-prompts";
import { type ReportTask } from "@/app/api/report/generate/route";

export type AIProvider = "claude" | "gemini";

export interface ReportGeneratorInput {
  meetingType: MeetingType;
  tasks: ReportTask[];
}
