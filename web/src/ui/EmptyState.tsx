import type { ReactNode } from "react";

interface EmptyStateProps {
  title: string;
  description?: string;
  action?: ReactNode;
}

export function EmptyState({ title, description, action }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <div style={{ fontWeight: 600, color: "var(--text-secondary)", marginBottom: description ? 6 : 0 }}>
        {title}
      </div>
      {description && <div>{description}</div>}
      {action && <div style={{ marginTop: 14 }}>{action}</div>}
    </div>
  );
}
