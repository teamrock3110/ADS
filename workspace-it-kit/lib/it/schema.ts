import { z } from "zod";

export const taskSchema = z.object({
  id: z.string(),
  title: z.string(),
  deadline: z.string(),
  delayed: z.boolean(),
  description: z.string(),
  comments: z.array(z.string()),
});

export const tasksSchema = z.array(taskSchema);

export const execLinkSchema = z.object({
  id: z.string(),
  label: z.string(),
  url: z.string().url(),
});

export const execLinksMapSchema = z.record(z.string(), z.array(execLinkSchema));

export type ExecLink = z.infer<typeof execLinkSchema>;

export const relatedTicketSchema = z.object({
  id: z.string(),
  title: z.string(),
  status: z.string(),
  summary: z.string().optional(),
});

export const relatedTicketsMapSchema = z.record(
  z.string(),
  z.array(relatedTicketSchema),
);

export const workspaceMetaSchema = z.object({
  name: z.string(),
});

export type Task = z.infer<typeof taskSchema>;
export type RelatedTicket = z.infer<typeof relatedTicketSchema>;

/** LOCAL タスク（アプリから追加）。Task と同じ型で表示・処理できる */
export const localTaskSchema = z.object({
  id: z.string(),           // "LOCAL-<epoch ms>" 形式（Workspace の handleAddTask が Date.now() で採番）
  title: z.string(),
  deadline: z.string(),     // "6/15" 形式
  description: z.string().default(""),
  comments: z.array(z.string()).default([]),
  delayed: z.boolean().default(false),
});

export type LocalTask = z.infer<typeof localTaskSchema>;

/** Task が LOCAL 由来かどうか */
export function isLocalTask(task: Pick<Task, "id">): boolean {
  return task.id.startsWith("LOCAL-");
}
