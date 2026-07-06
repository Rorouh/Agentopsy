import type { ReactNode } from "react";

interface CardProps {
  fullWidth?: boolean;
  children: ReactNode;
}

export function Card({ fullWidth, children }: CardProps) {
  return (
    <div className={fullWidth ? "status-card full-width" : "status-card"}>
      {children}
    </div>
  );
}
