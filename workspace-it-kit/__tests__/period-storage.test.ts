import { describe, expect, it } from "vitest";

import {
  createEmptyStorage,
  hasReportProgress,
  parseWorkspaceStorage,
} from "@/lib/it/storage";

describe("parseWorkspaceStorage", () => {
  it("creates empty storage when raw is null", () => {
    expect(parseWorkspaceStorage(null)).toEqual(createEmptyStorage());
  });

  it("loads v2 format", () => {
    const data = {
      reportInputs: {
        "CIT-201": { progress: "進捗", issues: "", consult: "" },
      },
      workMemos: {},
      taskLinks: {},
      delayedOverrides: {},
      completedTaskIds: ["CIT-142"],
    };
    expect(parseWorkspaceStorage(data)).toEqual(data);
  });

  it("migrates legacy v1 fields without rollover", () => {
    const legacy = {
      periodStart: "2025-05-20",
      reportInputs: {
        "CIT-201": { progress: "残す", issues: "", consult: "" },
      },
      previousPeriod: null,
      workMemos: { "CIT-201": "メモ" },
      taskLinks: {},
      delayedOverrides: { "CIT-201": true },
    };

    expect(parseWorkspaceStorage(legacy)).toEqual({
      reportInputs: legacy.reportInputs,
      workMemos: legacy.workMemos,
      taskLinks: {},
      delayedOverrides: legacy.delayedOverrides,
      completedTaskIds: [],
    });
  });
});

describe("hasReportProgress", () => {
  it("detects non-empty progress", () => {
    expect(hasReportProgress({ progress: "  ok ", issues: "", consult: "" })).toBe(
      true,
    );
    expect(hasReportProgress({ progress: "", issues: "x", consult: "" })).toBe(
      false,
    );
  });
});
