import { describe, expect, it } from "vitest";

import { generateWeeklyReport } from "@/lib/it/report";

describe("generateWeeklyReport", () => {
  it("uses company section headers and P2 field content", () => {
    const { text, warnings } = generateWeeklyReport({
      progress: "6G非対応PC向け 接続設定配布完了 [5/8]",
      issues: "MDM未登録端末が想定以上に多い",
      consult: "本番トークン無効化の承認をお願いします",
    });

    expect(text).toContain("■ 進行中のアクションアイテム（期限・遅延の有無）");
    expect(text).toContain("6G非対応PC向け 接続設定配布完了 [5/8]");
    expect(text).toContain("■ 遅延理由・課題");
    expect(text).toContain("MDM未登録端末が想定以上に多い");
    expect(text).toContain("■ 相談・作業承認依頼");
    expect(text).toContain("本番トークン無効化の承認をお願いします");
    expect(warnings).toHaveLength(0);
  });

  it("warns when progress is empty", () => {
    const { text, warnings } = generateWeeklyReport({
      progress: "",
      issues: "",
      consult: "承認依頼のみ",
    });

    expect(warnings).toHaveLength(1);
    expect(text).toContain("進捗ありません");
    expect(text).toContain("■ 遅延理由・課題");
    expect(text).toContain("■ 相談・作業承認依頼");
    expect(text).toContain("承認依頼のみ");
    expect(text).not.toContain("なし");
  });

  it("keeps optional section headers without なし when empty", () => {
    const { text } = generateWeeklyReport({
      progress: "進捗あり",
      issues: "  ",
      consult: "",
    });

    expect(text).toContain("進捗あり");
    expect(text).toContain("■ 遅延理由・課題");
    expect(text).toContain("■ 相談・作業承認依頼");
    expect(text).not.toContain("なし");
    expect(text).not.toMatch(/■ 遅延理由・課題\n[^\n■]/s);
  });
});
