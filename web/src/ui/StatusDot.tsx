interface StatusDotProps {
  online: boolean;
}

export function StatusDot({ online }: StatusDotProps) {
  return <span className={online ? "status-dot" : "status-dot offline"} />;
}
