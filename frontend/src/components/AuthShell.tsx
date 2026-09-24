import { Link } from "react-router-dom";
import { BrandLockup } from "./BrandMark";

type AuthShellProps = {
  title: string;
  lede: string;
  eyebrow: string;
  children: React.ReactNode;
};

export function AuthShell({ title, lede, eyebrow, children }: AuthShellProps) {
  return (
    <main className="auth-shell">
      <section className="brand-pane">
        <div className="brand brand-lockup-wrap">
          <BrandLockup />
        </div>
        <div className="brand-copy">
          <h1>Trusted access, before anything else.</h1>
          <p>Accounts are verified and approved before they can enter the workspace.</p>
        </div>
        <div className="brand-note">
          <span>Verified identity</span>
          <span>Governed approval</span>
          <span>Auditable by design</span>
        </div>
      </section>
      <section className="form-pane">
        <div className="auth-panel">
          <div className="eyebrow">{eyebrow}</div>
          <h2>{title}</h2>
          <p className="lede">{lede}</p>
          {children}
        </div>
      </section>
    </main>
  );
}

export function AuthLinks({ children }: { children: React.ReactNode }) {
  return <div className="links">{children}</div>;
}

export { Link };
