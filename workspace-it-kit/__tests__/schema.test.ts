import { describe, expect, it } from "vitest";

import relatedTicketsData from "@/data/related-tickets.json";
import taskLinksData from "@/data/task-links.json";
import tasksData from "@/data/tasks.json";
import workspaceData from "@/data/workspace.json";
import {
  execLinksMapSchema,
  relatedTicketsMapSchema,
  taskSchema,
  tasksSchema,
  workspaceMetaSchema,
} from "@/lib/it/schema";

describe("data/*.json schema validation", () => {
  it("data/tasks.json は tasksSchema を満たす", () => {
    expect(tasksSchema.safeParse(tasksData).success).toBe(true);
  });

  it("data/task-links.json は execLinksMapSchema を満たす", () => {
    expect(execLinksMapSchema.safeParse(taskLinksData).success).toBe(true);
  });

  it("data/workspace.json は workspaceMetaSchema を満たす", () => {
    expect(workspaceMetaSchema.safeParse(workspaceData).success).toBe(true);
  });

  it("data/related-tickets.json は relatedTicketsMapSchema を満たす（未使用・参考）", () => {
    expect(relatedTicketsMapSchema.safeParse(relatedTicketsData).success).toBe(
      true,
    );
  });
});

describe("taskSchema rejects invalid data", () => {
  it("bucket が不正なら不可", () => {
    expect(
      taskSchema.safeParse({
        id: "X",
        title: "t",
        deadline: "1/1",
        delayed: false,
        bucket: "invalid",
        description: "",
        comments: [],
      }).success,
    ).toBe(false);
  });
});
