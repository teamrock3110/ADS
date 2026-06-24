import { getDb } from "@/lib/db";
import {
  createEmptyStorage,
  workspaceStorageSchema,
  type WorkspaceStorage,
} from "@/lib/it/storage";

const WORKSPACE_ID = "default";

export async function loadOverlayFromDb(): Promise<WorkspaceStorage | null> {
  const sql = getDb();
  const rows = await sql`
    SELECT data FROM workspace_overlay
    WHERE workspace_id = ${WORKSPACE_ID}
    LIMIT 1
  `;

  if (rows.length === 0) return null;

  const parsed = workspaceStorageSchema.safeParse(rows[0].data);
  return parsed.success ? parsed.data : createEmptyStorage();
}

export async function saveOverlayToDb(data: WorkspaceStorage): Promise<void> {
  const sql = getDb();
  await sql`
    INSERT INTO workspace_overlay (workspace_id, data, updated_at)
    VALUES (${WORKSPACE_ID}, ${data}, now())
    ON CONFLICT (workspace_id)
    DO UPDATE SET data = EXCLUDED.data, updated_at = now()
  `;
}
