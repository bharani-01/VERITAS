type BrandMarkProps = {
  /** Visual size variant */
  size?: "sm" | "md" | "lg";
  className?: string;
};

const SIZE = {
  sm: 22,
  md: 28,
  lg: 40,
} as const;

/** VERITAS V mark — used in nav, auth, and compact headers. */
export function BrandMark({ size = "md", className = "" }: BrandMarkProps) {
  const px = SIZE[size];
  return (
    <span className={`brand-mark brand-mark-${size} ${className}`.trim()} aria-hidden="true">
      <img src="/brand/veritas-mark.png" alt="" width={px} height={px} decoding="async" />
    </span>
  );
}

/** Full stacked lockup: mark + VERITAS + tagline (auth / splash). */
export function BrandLockup({ className = "" }: { className?: string }) {
  return (
    <img
      className={`brand-lockup ${className}`.trim()}
      src="/brand/veritas-lockup.png"
      alt="VERITAS — Vulnerability Scanner"
      width={280}
      height={280}
      decoding="async"
    />
  );
}
