import { DotLottieReact } from "@lottiefiles/dotlottie-react";
import { useEffect, useState } from "react";
import loadingSrc from "../assets/loading.lottie?url";
import scanLoadingSrc from "../assets/scan-loading.lottie?url";

type Props = {
  label?: string;
  size?: "xs" | "sm" | "md" | "lg";
  fullPage?: boolean;
  /** Compact scan-table spinner (user-provided Lottie). */
  variant?: "default" | "scan";
};

const SIZES = { xs: 56, sm: 120, md: 200, lg: 280 } as const;

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const sync = () => setReduced(mq.matches);
    sync();
    mq.addEventListener("change", sync);
    return () => mq.removeEventListener("change", sync);
  }, []);
  return reduced;
}

/** Shared Lottie loading mark for shells, page fetches, and in-table scan wait states. */
export function LoadingMark({
  label = "Loading…",
  size = "md",
  fullPage = false,
  variant = "default",
}: Props) {
  const px = SIZES[size];
  const src = variant === "scan" ? scanLoadingSrc : loadingSrc;
  const showLabel = Boolean(label);
  const reduceMotion = usePrefersReducedMotion();
  const mark = (
    <div
      className={`loading-mark loading-mark-${size}${variant === "scan" ? " loading-mark-scan" : ""}`}
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label={showLabel ? undefined : "Loading"}
    >
      {reduceMotion ? (
        <span className="loading-mark-static" style={{ width: px, height: px }} aria-hidden="true" />
      ) : (
        <DotLottieReact src={src} loop autoplay style={{ width: px, height: px }} />
      )}
      {showLabel ? <p className="loading-mark-label">{label}</p> : null}
    </div>
  );

  if (fullPage) {
    return <div className="loading-screen">{mark}</div>;
  }

  return mark;
}
