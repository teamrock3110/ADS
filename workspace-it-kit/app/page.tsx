import { Workspace } from "@/components/workspace/Workspace";
import taskLinksData from "@/data/task-links.json";
import tasksData from "@/data/tasks.json";
import workspaceData from "@/data/workspace.json";
import {
  execLinksMapSchema,
  tasksSchema,
  workspaceMetaSchema,
} from "@/lib/it/schema";

export default function Page() {
  const tasksResult = tasksSchema.safeParse(tasksData);
  const linksResult = execLinksMapSchema.safeParse(taskLinksData);
  const wsResult = workspaceMetaSchema.safeParse(workspaceData);

  if (!tasksResult.success || !linksResult.success || !wsResult.success) {
    const errors = [
      !tasksResult.success &&
        `tasks.json: ${tasksResult.error.issues[0]?.message}`,
      !linksResult.success &&
        `task-links.json: ${linksResult.error.issues[0]?.message}`,
      !wsResult.success &&
        `workspace.json: ${wsResult.error.issues[0]?.message}`,
    ].filter(Boolean);
    throw new Error(`データの形式が正しくありません:\n${errors.join("\n")}`);
  }

  return (
    <Workspace
      initialTasks={tasksResult.data}
      initialExecLinks={linksResult.data}
      workspace={wsResult.data}
    />
  );
}
