import type { ReactNode } from "react";

type BadgeVariant = "low" | "medium" | "high" | "critical" | "neutral" | "success";

interface BadgeProps {
  variant: BadgeVariant;
  children: ReactNode;
}

export function Badge({ variant, children }: BadgeProps) {
  return <span className={`badge badge-${variant}`}>{children}</span>;
}
