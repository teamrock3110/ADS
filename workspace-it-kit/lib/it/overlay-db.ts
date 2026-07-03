import { getDb } from "@/lib/db";
import {
  applyWorkspaceStoragePatch,
  createEmptyStorage,
  workspaceStorageSchema,
  type WorkspaceStorage,
  type WorkspaceStoragePatch,
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

/**
 * 既存データに patch のキーだけを上書きして保存する（キー単位マージ）。
 * 読み込み→マージ→書き込みの間に別クライアントの書き込みが割り込む
 * 小さなレース窓は残るが、同一ユーザーの複数タブ／複数端末という想定用途では
 * 実質的に無視できるリスクであり、「未変更キーごと消える」全文上書きより
 * 大幅に安全。
 */
export async function mergeOverlayIntoDb(patch: WorkspaceStoragePatch): Promise<void> {
  const existing = (await loadOverlayFromDb()) ?? createEmptyStorage();
  await saveOverlayToDb(applyWorkspaceStoragePatch(existing, patch));
}
