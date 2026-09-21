import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AuthLinks, AuthShell, Link } from "../components/AuthShell";
import { api } from "../lib/api";

export function VerifyPage() {
  const [params] = useSearchParams();
  const [notice, setNotice] = useState<{ message: string; type: string }>({ message: "Verifying…", type: "" });

  useEffect(() => {
    const token = params.get("token");
    if (!token) {
      setNotice({ message: "This verification link is invalid or expired.", type: "error" });
      return;
    }
    api<{ message: string }>("/auth/verify-email", {
      method: "POST",
      body: JSON.stringify({ token }),
    })
      .then((data) => setNotice({ message: data.message, type: "success" }))
      .catch((error: Error) => setNotice({ message: error.message, type: "error" }));
  }, [params]);

  return (
    <AuthShell eyebrow="Verification" title="Confirm your email" lede="We are validating your verification link.">
      <div className={`notice ${notice.type}`} role="status">
        {notice.message}
      </div>
      <AuthLinks>
        <Link to="/">Return to sign in</Link>
      </AuthLinks>
    </AuthShell>
  );
}
