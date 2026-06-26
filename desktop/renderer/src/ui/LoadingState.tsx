interface LoadingStateProps {
  label?: string;
}

export function LoadingState({ label = "Cargando…" }: LoadingStateProps) {
  return (
    <div className="loading-state">
      <span className="spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}
