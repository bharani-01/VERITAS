const $ = (s) => document.querySelector(s);

const show = (message, type = "success") => {
  const notice = $(".notice");
  if (!notice) return;
  notice.textContent = message;
  notice.className = `notice ${type}`;
};

async function api(path, options = {}) {
  const { headers: extraHeaders, ...rest } = options;
  const response = await fetch(path, {
    ...rest,
    headers: { "Content-Type": "application/json", ...(extraHeaders || {}) },
  });
  if (response.status === 204) return {};
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data.detail;
    const message = Array.isArray(detail)
      ? detail.map((item) => item.msg || item).join(" ")
      : detail || "Something went wrong.";
    throw new Error(message);
  }
  return data;
}

const submitWithFeedback = (form, workingLabel, action) =>
  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector('button[type="submit"], button:not([type])');
    if (!button) return;
    button.disabled = true;
    const label = button.textContent;
    button.textContent = workingLabel;
    try {
      await action(event);
    } catch (error) {
      show(error.message, "error");
    } finally {
      button.disabled = false;
      button.textContent = label;
    }
  });

submitWithFeedback($("#signupForm"), "Creating account…", async (event) => {
  const data = await api("/auth/signup", {
    method: "POST",
    body: JSON.stringify(Object.fromEntries(new FormData(event.target))),
  });
  show(data.message);
  event.target.reset();
});

submitWithFeedback($("#loginForm"), "Signing in…", async (event) => {
  const data = await api("/auth/login", {
    method: "POST",
    body: JSON.stringify(Object.fromEntries(new FormData(event.target))),
  });
  location.href = data.user.role === "admin" ? "/admin/" : "/user/";
});

submitWithFeedback($("#resetRequestForm"), "Sending link…", async (event) => {
  const data = await api("/auth/password-reset/request", {
    method: "POST",
    body: JSON.stringify(Object.fromEntries(new FormData(event.target))),
  });
  show(data.message);
});

submitWithFeedback($("#resetConfirmForm"), "Updating password…", async (event) => {
  const payload = Object.fromEntries(new FormData(event.target));
  payload.token = new URLSearchParams(location.search).get("token");
  const data = await api("/auth/password-reset/confirm", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  show(data.message);
  setTimeout(() => {
    location.href = "/";
  }, 900);
});

async function verify() {
  const token = new URLSearchParams(location.search).get("token");
  if (!token || !$(".notice")) return;
  try {
    const data = await api("/auth/verify-email", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
    show(data.message);
  } catch (error) {
    show(error.message, "error");
  }
}
verify();
