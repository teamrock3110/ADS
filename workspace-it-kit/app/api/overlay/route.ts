import fs from "fs/promises";
import path from "path";
import { NextResponse } from "next/server";

import { createEmptyStorage } from "@/lib/it/storage";

const OVERLAY_PATH = path.join(process.cwd(), "data", "overlay.json");

export async function GET() {
  try {
    const raw = await fs.readFile(OVERLAY_PATH, "utf-8");
    return NextResponse.json(JSON.parse(raw));
  } catch {
    return NextResponse.json(createEmptyStorage());
  }
}

export async function PUT(request: Request) {
  try {
    const data = await request.json();
    await fs.writeFile(OVERLAY_PATH, JSON.stringify(data, null, 2), "utf-8");
    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error("[overlay] write failed:", err);
    return NextResponse.json({ ok: false }, { status: 500 });
  }
}
