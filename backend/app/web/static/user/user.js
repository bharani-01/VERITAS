const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];

const formatStatus = (status) => (status || "").replace(/_/g, " ");
const escapeHtml = (value) =>
  String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

const AVATARS = [
  { id: "slate", label: "Kai", seed: "Kai" },
  { id: "forest", label: "Noa", seed: "Noa" },
  { id: "ocean", label: "Remy", seed: "Remy" },
  { id: "amber", label: "Sage", seed: "Sage" },
  { id: "rose", label: "Quinn", seed: "Quinn" },
  { id: "violet", label: "Ari", seed: "Ari" },
  { id: "graphite", label: "Blake", seed: "Blake" },
  { id: "mint", label: "Rowan", seed: "Rowan" },
];

function avatarMeta(id) {
  return AVATARS.find((item) => item.id === id) || AVATARS[0];
}

function avatarUrl(id) {
  const { seed } = avatarMeta(id);
  return `https://api.dicebear.com/9.x/notionists/svg?seed=${encodeURIComponent(seed)}&backgroundColor=e8eef2,e7f0ec,efe8f4,f3ece4,e8eef8`;
}

function avatarPortrait(id) {
  const meta = avatarMeta(id);
  return `<img class="avatar-art" src="${avatarUrl(meta.id)}" alt="${meta.label}" width="80" height="80" loading="lazy" decoding="async" />`;
}

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

const NAV_KEY = "veritas.user.navCollapsed";

function mountUserNav(role) {
  const host = $("#appNav");
  const frame = $("#appFrame");
  if (!host || !frame) return;

  let collapsed = false;
  try {
    collapsed = localStorage.getItem(NAV_KEY) === "1";
  } catch (_) {}
  frame.classList.toggle("nav-collapsed", collapsed);

  const adminLink =
    role === "admin"
      ? `<a class="nav-link" href="/admin/">
          <svg class="icon" viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" /></svg>
          <span class="nav-link-text">Admin</span>
        </a>`
      : "";

  host.innerHTML = `
    <div class="nav-top">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 5h14L12 19 5 5Z" /></svg>
        </span>
        <span class="brand-text">VERITAS</span>
      </div>
      <button type="button" class="nav-toggle" id="navToggle" aria-label="${collapsed ? "Expand navigation" : "Collapse navigation"}" aria-expanded="${collapsed ? "false" : "true"}">
        <svg class="icon icon-collapse" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M9 4v16" /><path d="M14 9l-3 3 3 3" /></svg>
        <svg class="icon icon-expand" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M9 4v16" /><path d="M12 9l3 3-3 3" /></svg>
      </button>
    </div>
    <p class="nav-label">Account</p>
    ${adminLink}
    <a class="nav-link active" href="/user/">
      <svg class="icon" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
      <span class="nav-link-text">My profile</span>
    </a>
    <button type="button" class="nav-link nav-logout" id="navLogout">
      <svg class="icon" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="M16 17l5-5-5-5" /><path d="M21 12H9" /></svg>
      <span class="nav-link-text">Sign out</span>
    </button>
    <div class="app-nav-footer">Manage your VERITAS identity settings.</div>
  `;

  const toggle = $("#navToggle");
  const apply = (value, animate) => {
    frame.classList.toggle("nav-ready", animate);
    frame.classList.toggle("nav-collapsed", value);
    document.documentElement.classList.toggle("nav-pref-collapsed", value);
    toggle.setAttribute("aria-expanded", String(!value));
    try {
      localStorage.setItem(NAV_KEY, value ? "1" : "0");
    } catch (_) {}
  };
  apply(collapsed, false);
  requestAnimationFrame(() => frame.classList.add("nav-ready"));
  toggle.addEventListener("click", () => apply(!frame.classList.contains("nav-collapsed"), true));

  $("#navLogout").addEventListener("click", async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch (_) {}
    location.href = "/";
  });
}

async function main() {
  const root = $("#profile");
  if (!root) return;

  try {
    const { user } = await api("/auth/me");
    mountUserNav(user.role);

    let selectedAvatar = user.avatar || "slate";

    const render = (current, notice) => {
      selectedAvatar = current.avatar || "slate";
      const handle = current.username ? `@${current.username}` : "No username yet";
      root.innerHTML = `
        <form id="profileForm" class="profile-shell" action="/auth/me" method="post" onsubmit="return false;">
          <div class="notice ${notice ? notice.type || "success" : ""}" role="status">${notice ? escapeHtml(notice.message) : ""}</div>
          <section class="profile-banner">
            <div class="avatar-preview" id="avatarPreview">${avatarPortrait(selectedAvatar)}</div>
            <div class="profile-banner-copy">
              <h2>${escapeHtml(current.display_name)}</h2>
              <p>${escapeHtml(handle)} · ${escapeHtml(current.email)}</p>
              <span class="badge ${escapeHtml(current.status)}">${formatStatus(current.status)}</span>
            </div>
            <div class="profile-banner-meta">
              <div><span>Role</span><strong>${escapeHtml(current.role)}</strong></div>
              <div><span>Last login</span><strong>${current.last_login_at ? new Date(current.last_login_at).toLocaleString() : "—"}</strong></div>
            </div>
          </section>
          <section class="profile-card">
            <div class="profile-card-head">
              <h3>Profile photo</h3>
              <p>Choose an avatar for the directory and account views.</p>
            </div>
            <div class="avatar-grid">
              ${AVATARS.map(
                (item) => `
                <button type="button" class="avatar-option ${item.id === selectedAvatar ? "selected" : ""}" data-avatar="${item.id}" aria-label="${item.label}" aria-pressed="${item.id === selectedAvatar}" title="${item.label}">
                  ${avatarPortrait(item.id)}
                </button>`
              ).join("")}
            </div>
          </section>
          <section class="profile-card">
            <div class="profile-card-head">
              <h3>Public details</h3>
              <p>Name and username appear across VERITAS.</p>
            </div>
            <div class="profile-form-grid three-col">
              <div class="field">
                <label for="display_name">Display name</label>
                <input id="display_name" name="display_name" required maxlength="120" value="${escapeHtml(current.display_name)}" autocomplete="name" />
              </div>
              <div class="field">
                <label for="username">Username</label>
                <input id="username" name="username" required minlength="3" maxlength="32" pattern="[a-z][a-z0-9_]{2,31}" value="${escapeHtml(current.username || "")}" autocomplete="username" placeholder="your_handle" />
                <p class="hint">Lowercase letters, numbers, underscores.</p>
              </div>
              <div class="field">
                <label for="email">Email</label>
                <input id="email" name="email" type="email" value="${escapeHtml(current.email)}" disabled />
                <p class="hint">Verified email is locked.</p>
              </div>
            </div>
            <div class="profile-actions">
              <button type="submit" id="saveProfile">Save changes</button>
              <a class="btn secondary" href="/forgot">Change password</a>
            </div>
          </section>
        </form>
      `;

      if (!notice) $(".notice", root).className = "notice";

      $$("[data-avatar]", root).forEach((button) => {
        button.addEventListener("click", () => {
          selectedAvatar = button.dataset.avatar;
          $$("[data-avatar]", root).forEach((item) => {
            const active = item.dataset.avatar === selectedAvatar;
            item.classList.toggle("selected", active);
            item.setAttribute("aria-pressed", String(active));
          });
          $("#avatarPreview").innerHTML = avatarPortrait(selectedAvatar);
        });
      });

      $("#profileForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        const button = $("#saveProfile");
        button.disabled = true;
        const label = button.textContent;
        button.textContent = "Saving…";
        try {
          const data = await api("/auth/me", {
            method: "POST",
            body: JSON.stringify({
              display_name: $("#display_name").value.trim(),
              username: $("#username").value.trim(),
              avatar: selectedAvatar,
            }),
          });
          render(data.user, { message: data.message || "Profile updated.", type: "success" });
        } catch (error) {
          const noticeNode = $(".notice", root);
          noticeNode.textContent = error.message;
          noticeNode.className = "notice error";
          button.disabled = false;
          button.textContent = label;
        }
      });
    };

    render(user);
  } catch (_) {
    location.href = "/";
  }
}

main();
