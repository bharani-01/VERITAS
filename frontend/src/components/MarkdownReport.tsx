import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

type Props = {
  source: string;
  className?: string;
};

/** Renders AI / exported markdown safely as React elements (no raw HTML). */
export function MarkdownReport({ source, className }: Props) {
  const md = source.trim();
  if (!md) return null;

  return (
    <div className={`md-report ${className || ""}`.trim()}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ href, children }) => (
            <a href={href} target="_blank" rel="noopener noreferrer">
              {children}
            </a>
          ),
        }}
      >
        {md}
      </ReactMarkdown>
    </div>
  );
}
