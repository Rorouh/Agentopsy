import type { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode; // CTAs de flujo entre pantallas (ver onNavigate en App.tsx)
}

export function PageHeader({ title, subtitle, actions }: PageHeaderProps) {
  return (
    <div className="page-header">
      <div className="page-header-top">
        <div>
          <h2 className="system-title">{title}</h2>
          {subtitle && <p className="system-subtitle">{subtitle}</p>}
        </div>
        {actions && <div className="page-header-actions">{actions}</div>}
      </div>
    </div>
  );
}
