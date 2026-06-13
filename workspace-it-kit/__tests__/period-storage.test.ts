import { describe, expect, it } from "vitest";

import {
  createEmptyStorage,
  hasReportProgress,
  workspaceStorageSchema,
} from "@/lib/it/storage";

describe("workspaceStorageSchema", () => {
  it("creates empty storage when raw is null", () => {
    const result = workspaceStorageSchema.safeParse(null);
    expect(result.success).toBe(false);
    expect(createEmptyStorage()).toEqual({
      reportInputs: {},
      workMemos: {},
      taskLinks: {},
      delayedOverrides: {},
      completedTaskIds: [],
      selectedTaskId: null,
      localTasks: [],
    });
  });

  it("loads v2 format with defaults for new fields", () => {
    const data = {
      reportInputs: {
        "CIT-201": { progress: "進捗", issues: "", consult: "" },
      },
      workMemos: {},
      taskLinks: {},
      delayedOverrides: {},
      completedTaskIds: ["CIT-142"],
    };
    const result = workspaceStorageSchema.safeParse(data);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.reportInputs["CIT-201"]?.progress).toBe("進捗");
      expect(result.data.completedTaskIds).toContain("CIT-142");
      expect(result.data.selectedTaskId).toBeNull();
    }
  });

  it("accepts selectedTaskId when present", () => {
    const data = {
      reportInputs: {},
      workMemos: {},
      taskLinks: {},
      delayedOverrides: {},
      completedTaskIds: [],
      selectedTaskId: "CIT-201",
    };
    const result = workspaceStorageSchema.safeParse(data);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.selectedTaskId).toBe("CIT-201");
    }
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
