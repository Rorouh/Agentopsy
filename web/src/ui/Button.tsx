import type { ButtonHTMLAttributes } from "react";

type Variant = "chip" | "icon";

const VARIANT_CLASS: Record<Variant, string> = {
  chip: "chip",
  icon: "send-btn",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant: Variant;
}

export function Button({ variant, className, ...props }: ButtonProps) {
  const base = VARIANT_CLASS[variant];
  return <button className={className ? `${base} ${className}` : base} {...props} />;
}
