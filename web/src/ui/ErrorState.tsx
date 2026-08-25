import { useT } from "../i18n";

interface ErrorStateProps {
  message: string;
}

export function ErrorState({ message }: ErrorStateProps) {
  const t = useT();
  return (
    <div className="error-state">
      {/* El RÓTULO se traduce; el `message` viene del api o del transporte y se
          pinta tal cual, que es lo que hace falta para poder actuar sobre él. */}
      <strong>{t("ui.connectionError")}</strong> {message}
    </div>
  );
}
