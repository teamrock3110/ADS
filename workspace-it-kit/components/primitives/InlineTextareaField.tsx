"use client";

/**
 * InlineTextareaField — 複数行 textarea プリミティブ。
 * blur / アンマウント時に onSave。Cmd+Enter で blur、Esc でキャンセル。
 */

import { useEffect, useRef } from "react";

import { Textarea } from "@/components/ui/textarea";

export type InlineTextareaFieldProps = {
  value: string;
  onSave: (v: string) => void;
  ariaLabel: string;
  placeholder?: string;
  readOnly?: boolean;
};

export function InlineTextareaField({
  value,
  onSave,
  ariaLabel,
  placeholder,
  readOnly = false,
}: InlineTextareaFieldProps) {
  const savedValueRef = useRef(value);
  const draftRef = useRef(value);

  useEffect(() => {
    savedValueRef.current = value;
    draftRef.current = value;
  }, [value]);

  useEffect(() => {
    return () => {
      if (readOnly) return;
      if (draftRef.current !== savedValueRef.current) {
        onSave(draftRef.current);
      }
    };
  }, [onSave, readOnly]);

  const commit = (next: string) => {
    draftRef.current = next;
    if (next !== savedValueRef.current) {
      onSave(next);
    }
  };

  if (readOnly) {
    return (
      <div className="min-h-16 rounded-md border border-border bg-muted/30 px-3 py-2 text-sm leading-relaxed whitespace-pre-line text-muted-foreground">
        {value || "（未入力）"}
      </div>
    );
  }

  return (
    <Textarea
      defaultValue={value}
      placeholder={placeholder ?? "未設定"}
      aria-label={ariaLabel}
      onChange={(e) => {
        draftRef.current = e.target.value;
      }}
      onBlur={(e) => {
        commit(e.target.value);
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
          (e.target as HTMLTextAreaElement).blur();
        } else if (e.key === "Escape") {
          (e.target as HTMLTextAreaElement).value = savedValueRef.current;
          draftRef.current = savedValueRef.current;
          (e.target as HTMLTextAreaElement).blur();
        }
      }}
      className="min-h-16 bg-card leading-relaxed whitespace-pre-line"
    />
  );
}

/** タスク切替前にフォーカス中 textarea を blur する */
export function flushActiveTextarea(): void {
  const el = document.activeElement;
  if (el instanceof HTMLTextAreaElement) {
    el.blur();
  }
}
