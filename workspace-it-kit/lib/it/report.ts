export type WeeklyReportInput = {
  /** 直近1週間の進捗（必須） */
  progress: string;
  /** 直近1週間の遅延理由・課題（任意） */
  issues: string;
  /** 本番作業の相談・承認依頼（任意） */
  consult: string;
};

export type WeeklyReportResult = {
  text: string;
  warnings: string[];
};

const SECTION_PROGRESS = "■ 進行中のアクションアイテム（期限・遅延の有無）";
const SECTION_ISSUES = "■ 遅延理由・課題";
const SECTION_CONSULT = "■ 相談・作業承認依頼";

function formatSection(header: string, body: string): string {
  return body ? `${header}\n${body}` : header;
}

export function generateWeeklyReport(
  input: WeeklyReportInput,
): WeeklyReportResult {
  const warnings: string[] = [];
  const progress = input.progress.trim();
  const issues = input.issues.trim();
  const consult = input.consult.trim();

  if (!progress) {
    warnings.push(
      "「今週の進捗」が未入力です。定例報告には進捗の記載が必須です。",
    );
  }

  const text = [
    formatSection(SECTION_PROGRESS, progress || "進捗ありません"),
    formatSection(SECTION_ISSUES, issues),
    formatSection(SECTION_CONSULT, consult),
  ].join("\n\n");

  return { text, warnings };
}

export const EMPTY_WEEKLY_REPORT_INPUT: WeeklyReportInput = {
  progress: "",
  issues: "",
  consult: "",
};
