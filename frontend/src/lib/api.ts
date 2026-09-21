export type User = {
  id: string;
  display_name: string;
  username: string | null;
  avatar: string;
  email: string;
  role: "admin" | "user" | string;
  status: string;
  email_verified_at?: string | null;
  force_password_reset?: boolean;
  last_login_at?: string | null;
};

export async function api<T = Record<string, unknown>>(path: string, options: RequestInit = {}): Promise<T> {
  const { headers: extraHeaders, ...rest } = options;
  const response = await fetch(path, {
    credentials: "same-origin",
    ...rest,
    headers: {
      "Content-Type": "application/json",
      ...(extraHeaders || {}),
    },
  });
  if (response.status === 204) return {} as T;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = (data as { detail?: unknown }).detail;
    const message = Array.isArray(detail)
      ? detail.map((item: { msg?: string } | string) => (typeof item === "string" ? item : item.msg || String(item))).join(" ")
      : (detail as string) || "Something went wrong.";
    throw new Error(message);
  }
  return data as T;
}
