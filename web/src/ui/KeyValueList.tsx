import type { ReactNode } from "react";

interface KeyValueItem {
  label: string;
  value: ReactNode;
}

interface KeyValueListProps {
  items: KeyValueItem[];
}

// Reutiliza las clases .status-card-body/.status-row ya validadas visualmente
// en SystemStatusPage, para no duplicar estilos de "lista de pares clave-valor".
export function KeyValueList({ items }: KeyValueListProps) {
  return (
    <div className="status-card-body">
      {items.map((item) => (
        <div className="status-row" key={item.label}>
          <span className="status-row-label">{item.label}</span>
          <span className="status-row-value">{item.value}</span>
        </div>
      ))}
    </div>
  );
}
