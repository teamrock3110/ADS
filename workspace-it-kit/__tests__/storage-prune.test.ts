import { describe, expect, it } from "vitest";

import {
  createEmptyStorage,
  pruneOrphanLocalData,
  type WorkspaceStorage,
} from "@/lib/it/storage";

const liveLocalTask = {
  id: "LOCAL-100",
  title: "生きているローカルタスク",
  deadline: "7/15",
  description: "",
  comments: [],
  delayed: false,
};

function storageWithOrphans(): WorkspaceStorage {
  return {
    ...createEmptyStorage(),
    localTasks: [liveLocalTask],
    reportInputs: {
      "ITDX-142": { progress: "a", issues: "", consult: "" },
      "LOCAL-100": { progress: "b", issues: "", consult: "" },
      "LOCAL-999": { progress: "orphan", issues: "", consult: "" },
    },
    workMemos: { "LOCAL-999": "orphan memo", "CIT-128": "json memo" },
    taskLinks: {
      "LOCAL-999": [{ id: "lnk-1", label: "x", url: "https://example.com" }],
    },
    completedTaskIds: ["ITDX-142", "LOCAL-999", "LOCAL-100"],
    selectedTaskId: "LOCAL-999",
  };
}

describe("pruneOrphanLocalData", () => {
  it("removes overlay entries for LOCAL ids without a task entity", () => {
    const pruned = pruneOrphanLocalData(storageWithOrphans());

    expect(pruned.reportInputs).not.toHaveProperty("LOCAL-999");
    expect(pruned.workMemos).not.toHaveProperty("LOCAL-999");
    expect(pruned.taskLinks).not.toHaveProperty("LOCAL-999");
    expect(pruned.completedTaskIds).not.toContain("LOCAL-999");
    expect(pruned.selectedTaskId).toBeNull();
  });

  it("keeps entries for live LOCAL tasks and JSON tasks (soft delete)", () => {
    const pruned = pruneOrphanLocalData(storageWithOrphans());

    expect(pruned.reportInputs).toHaveProperty("LOCAL-100");
    expect(pruned.reportInputs).toHaveProperty("ITDX-142");
    expect(pruned.workMemos).toHaveProperty("CIT-128");
    expect(pruned.completedTaskIds).toEqual(["ITDX-142", "LOCAL-100"]);
  });

  it("keeps selectedTaskId when it points to a live task", () => {
    const data = { ...storageWithOrphans(), selectedTaskId: "LOCAL-100" };
    expect(pruneOrphanLocalData(data).selectedTaskId).toBe("LOCAL-100");
  });
});
