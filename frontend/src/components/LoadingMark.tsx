import { DotLottieReact } from "@lottiefiles/dotlottie-react";
import loadingSrc from "../assets/loading.lottie?url";

type Props = {
  label?: string;
  size?: "sm" | "md" | "lg";
  fullPage?: boolean;
};

const SIZES = { sm: 120, md: 200, lg: 280 } as const;

/** Shared Lottie loading mark for shells and page fetches. */
export function LoadingMark({ label = "Loading…", size = "md", fullPage = false }: Props) {
  const px = SIZES[size];
  const mark = (
    <div className={`loading-mark loading-mark-${size}`} role="status" aria-live="polite" aria-busy="true">
      <DotLottieReact src={loadingSrc} loop autoplay style={{ width: px, height: px }} />
      {label ? <p className="loading-mark-label">{label}</p> : null}
    </div>
  );

  if (fullPage) {
    return <div className="loading-screen">{mark}</div>;
  }

  return mark;
}
