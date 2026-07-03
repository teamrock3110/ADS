import { describe, expect, it } from "vitest";

import {
  applyWorkspaceStoragePatch,
  createEmptyStorage,
  diffWorkspaceStorage,
} from "@/lib/it/storage";

describe("diffWorkspaceStorage", () => {
  it("returns an empty patch when nothing changed", () => {
    const base = createEmptyStorage();
    expect(diffWorkspaceStorage(base, { ...base })).toEqual({});
  });

  it("includes only the top-level keys that actually changed", () => {
    const base = createEmptyStorage();
    const current = { ...base, workMemos: { "ITDX-1": "memo" } };

    const patch = diffWorkspaceStorage(base, current);

    expect(Object.keys(patch)).toEqual(["workMemos"]);
    expect(patch.workMemos).toEqual({ "ITDX-1": "memo" });
  });
});

describe("applyWorkspaceStoragePatch (key-level merge)", () => {
  it("reproduces the fixed incident: a save from one client no longer wipes another client's untouched keys", () => {
    // タブA（例: 本番）が最後に見ていた状態
    const clientABaseline = createEmptyStorage();

    // タブB（例: dev）がローカルタスクを作成して先に保存した後の DB 状態
    const dbAfterClientBSave = {
      ...createEmptyStorage(),
      localTasks: [
        {
          id: "LOCAL-1",
          title: "devタブで作ったタスク",
          deadline: "",
          description: "",
          comments: [],
          delayed: false,
        },
      ],
    };

    // タブAは localTasks に触れず、自分が編集した workMemos だけを保存しようとする
    const clientACurrent = {
      ...clientABaseline,
      workMemos: { "ITDX-1": "タブAのメモ" },
    };
    const patchFromClientA = diffWorkspaceStorage(clientABaseline, clientACurrent);

    expect(patchFromClientA).not.toHaveProperty("localTasks");

    const merged = applyWorkspaceStoragePatch(dbAfterClientBSave, patchFromClientA);

    // タブBが作ったローカルタスクは消えず、タブAの変更も反映されている
    expect(merged.localTasks).toHaveLength(1);
    expect(merged.localTasks[0].id).toBe("LOCAL-1");
    expect(merged.workMemos).toEqual({ "ITDX-1": "タブAのメモ" });
  });

  it("still lets a client overwrite a key it explicitly changed", () => {
    const existing = { ...createEmptyStorage(), selectedTaskId: "ITDX-1" };
    const merged = applyWorkspaceStoragePatch(existing, { selectedTaskId: "ITDX-2" });
    expect(merged.selectedTaskId).toBe("ITDX-2");
  });
});
