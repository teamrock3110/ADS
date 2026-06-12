import { Workspace } from "@/components/workspace/Workspace";
import positionsData from "@/data/positions.json";
import candidatesData from "@/data/candidates.json";
import workspaceData from "@/data/workspace.json";
import {
  departmentsSchema,
  candidatesSchema,
  workspaceSchema,
} from "@/lib/schema";

export default function Page() {
  const deptResult = departmentsSchema.safeParse(positionsData);
  const candResult = candidatesSchema.safeParse(candidatesData);
  const wsResult = workspaceSchema.safeParse(workspaceData);

  if (!deptResult.success || !candResult.success || !wsResult.success) {
    const errors = [
      !deptResult.success &&
        `positions.json: ${deptResult.error.issues[0]?.message}`,
      !candResult.success &&
        `candidates.json: ${candResult.error.issues[0]?.message}`,
      !wsResult.success &&
        `workspace.json: ${wsResult.error.issues[0]?.message}`,
    ].filter(Boolean);
    throw new Error(`データの形式が正しくありません:\n${errors.join("\n")}`);
  }

  return (
    <Workspace
      initialDepartments={deptResult.data}
      initialCandidates={candResult.data}
      workspace={wsResult.data}
    />
  );
}
