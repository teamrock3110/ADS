import { config } from "dotenv";

config({ path: ".env.local" });

import { neon } from "@neondatabase/serverless";

async function migrate() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error("DATABASE_URL is not set. Add it to .env.local");
    process.exit(1);
  }

  const sql = neon(url);

  await sql`
    CREATE TABLE IF NOT EXISTS workspace_overlay (
      workspace_id TEXT PRIMARY KEY DEFAULT 'default',
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `;

  console.log("Migration complete: workspace_overlay table is ready.");
}

migrate().catch((err) => {
  console.error("Migration failed:", err);
  process.exit(1);
});
