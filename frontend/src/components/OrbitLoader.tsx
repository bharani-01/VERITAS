import React from "react";

interface Props {
  size?: "sm" | "md" | "lg";
  className?: string;
  style?: React.CSSProperties;
}

export function OrbitLoader({ size, className = "", style }: Props) {
  const sizeClass = size ? `orbit-loader-${size}` : "";
  return (
    <span
      className={`orbit-loader ${sizeClass} ${className}`.trim()}
      role="status"
      aria-label="Loading"
      style={style}
    />
  );
}
