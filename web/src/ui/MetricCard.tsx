type MetricVariant = "neutral" | "success" | "warning" | "danger";

interface MetricCardProps {
  label: string;
  value: string;
  hint?: string;
  variant?: MetricVariant;
}

const VARIANT_COLOR: Record<MetricVariant, string> = {
  neutral: "var(--text-primary)",
  success: "var(--success)",
  warning: "var(--warning)",
  danger: "var(--danger)",
};

export function MetricCard({ label, value, hint, variant = "neutral" }: MetricCardProps) {
  return (
    <div className="metric-card">
      <div className="metric-label">{label}</div>
      <div className="metric-value" style={{ color: VARIANT_COLOR[variant] }}>{value}</div>
      {hint && <div className="metric-hint">{hint}</div>}
    </div>
  );
}
