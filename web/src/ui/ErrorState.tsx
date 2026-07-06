interface ErrorStateProps {
  message: string;
}

export function ErrorState({ message }: ErrorStateProps) {
  return (
    <div className="error-state">
      <strong>Error de conexión:</strong> {message}
    </div>
  );
}
