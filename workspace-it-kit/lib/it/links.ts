import { type ExecLinkKind } from "@/lib/it/schema";

export const EXEC_LINK_KIND_LABEL: Record<ExecLinkKind, string> = {
  slack: "Slack",
  slides: "Slides",
  sheet: "Sheet",
  doc: "Doc",
  other: "Link",
};

export function execLinkHostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}
