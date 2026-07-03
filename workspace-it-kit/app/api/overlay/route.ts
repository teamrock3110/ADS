import fs from "fs/promises";
import path from "path";

import { NextResponse } from "next/server";

import { hasDatabaseUrl } from "@/lib/db";
import { loadOverlayFromDb, mergeOverlayIntoDb, saveOverlayToDb } from "@/lib/it/overlay-db";
import {
  applyWorkspaceStoragePatch,
  createEmptyStorage,
  workspaceStorageSchema,
  workspaceStoragePatchSchema,
} from "@/lib/it/storage";

const OVERLAY_PATH = path.join(process.cwd(), "data", "overlay.json");

async function loadFromFile(): Promise<ReturnType<typeof createEmptyStorage>> {
  try {
    const raw = await fs.readFile(OVERLAY_PATH, "utf-8");
    const parsed = workspaceStorageSchema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : createEmptyStorage();
  } catch {
    return createEmptyStorage();
  }
}

async function saveToFile(data: ReturnType<typeof createEmptyStorage>): Promise<void> {
  await fs.writeFile(OVERLAY_PATH, JSON.stringify(data, null, 2), "utf-8");
}

function isEmptyStorage(data: ReturnType<typeof createEmptyStorage>): boolean {
  return (
    Object.keys(data.reportInputs).length === 0 &&
    Object.keys(data.workMemos).length === 0 &&
    Object.keys(data.taskLinks).length === 0 &&
    data.completedTaskIds.length === 0 &&
    data.localTasks.length === 0
  );
}

/** overlay.json にデータがあれば Neon へ一括移行 */
async function migrateFileToDbIfNeeded(): Promise<void> {
  const fileData = await loadFromFile();
  if (isEmptyStorage(fileData)) return;

  await saveOverlayToDb(fileData);
  await fs.unlink(OVERLAY_PATH).catch(() => undefined);
}

export async function GET() {
  try {
    if (hasDatabaseUrl()) {
      let data = await loadOverlayFromDb();
      if (data === null || isEmptyStorage(data)) {
        await migrateFileToDbIfNeeded();
        data = (await loadOverlayFromDb()) ?? createEmptyStorage();
      }
      return NextResponse.json(data);
    }

    return NextResponse.json(await loadFromFile());
  } catch (err) {
    console.error("[overlay] read failed:", err);
    return NextResponse.json(createEmptyStorage());
  }
}

export async function PUT(request: Request) {
  try {
    const raw: unknown = await request.json();
    const parsed = workspaceStoragePatchSchema.safeParse(raw);
    if (!parsed.success) {
      return NextResponse.json({ ok: false, error: "invalid payload" }, { status: 400 });
    }
    const patch = parsed.data;

    if (hasDatabaseUrl()) {
      await mergeOverlayIntoDb(patch);
    } else {
      const current = await loadFromFile();
      await saveToFile(applyWorkspaceStoragePatch(current, patch));
    }

    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error("[overlay] write failed:", err);
    return NextResponse.json({ ok: false }, { status: 500 });
  }
}
