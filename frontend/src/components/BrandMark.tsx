type BrandMarkProps = {
  size?: "sm" | "md" | "lg";
  className?: string;
};

const SIZE = {
  sm: 22,
  md: 28,
  lg: 40,
} as const;

/** Compact V mark cropped from the stacked brand lockup. */
export function BrandMark({ size = "md", className = "" }: BrandMarkProps) {
  const px = SIZE[size];
  return (
    <span className={`brand-mark brand-mark-${size} ${className}`.trim()} aria-hidden="true">
      <img
        src="/brand/veritas-mark.png"
        alt=""
        width={px}
        height={px}
        decoding="async"
        className="brand-mark-img"
      />
    </span>
  );
}

/** Stacked lockup: V + VERITAS + Vulnerability Scanner (auth / splash). */
export function BrandLockup({ className = "" }: { className?: string }) {
  return (
    <img
      className={`brand-lockup ${className}`.trim()}
      src="/brand/veritas-lockup.png"
      alt="VERITAS — Vulnerability Scanner"
      width={320}
      height={213}
      decoding="async"
    />
  );
}
