import { useT } from "../i18n";

interface LoadingStateProps {
  label?: string;
}

// El rótulo por defecto NO puede ser un literal del parámetro: depende del
// idioma, así que se resuelve dentro, y quien quiera otro lo pasa ya traducido.
export function LoadingState({ label }: LoadingStateProps) {
  const t = useT();
  return (
    <div className="loading-state">
      <span className="spinner" aria-hidden="true" />
      <span>{label ?? t("ui.loading")}</span>
    </div>
  );
}
