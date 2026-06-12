import { z } from "zod";

export const taskBucketSchema = z.enum(["today", "week", "backlog"]);

export const taskSchema = z.object({
  id: z.string(),
  title: z.string(),
  deadline: z.string(),
  delayed: z.boolean(),
  bucket: taskBucketSchema,
  description: z.string(),
  comments: z.array(z.string()),
});

export const tasksSchema = z.array(taskSchema);

export const execLinkKindSchema = z.enum([
  "slack",
  "slides",
  "sheet",
  "doc",
  "other",
]);

export const execLinkSchema = z.object({
  id: z.string(),
  kind: execLinkKindSchema,
  label: z.string(),
  url: z.string().url(),
});

export const execLinksMapSchema = z.record(z.string(), z.array(execLinkSchema));

export type ExecLinkKind = z.infer<typeof execLinkKindSchema>;
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
  assignee: z.string(),
});

export type TaskBucket = z.infer<typeof taskBucketSchema>;
export type Task = z.infer<typeof taskSchema>;
export type RelatedTicket = z.infer<typeof relatedTicketSchema>;
