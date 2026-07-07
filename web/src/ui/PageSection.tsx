import type { ReactNode } from "react";
import { Card } from "./Card";

interface PageSectionProps {
  title: string;
  children: ReactNode;
  fullWidth?: boolean;
}

// Envoltorio fino sobre Card para secciones con título dentro de una página.
// Reduce el patrón repetido <Card><h3>...</h3>...</Card> en varias páginas.
export function PageSection({ title, children, fullWidth = true }: PageSectionProps) {
  return (
    <Card fullWidth={fullWidth}>
      <h3>{title}</h3>
      {children}
    </Card>
  );
}
