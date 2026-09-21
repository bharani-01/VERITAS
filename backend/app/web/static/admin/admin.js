const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];

const formatStatus = (status) => (status || "").replace(/_/g, " ");
const escapeHtml = (value) =>
  String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

const iconMore = `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="5" r="1.4" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/><circle cx="12" cy="19" r="1.4" fill="currentColor" stroke="none"/></svg>`;

const AVATARS = [
  { id: "slate", seed: "Kai" },
  { id: "forest", seed: "Noa" },
  { id: "ocean", seed: "Remy" },
  { id: "amber", seed: "Sage" },
  { id: "rose", seed: "Quinn" },
  { id: "violet", seed: "Ari" },
  { id: "graphite", seed: "Blake" },
  { id: "mint", seed: "Rowan" },
];

function avatarUrl(id) {
  const meta = AVATARS.find((item) => item.id === id) || AVATARS[0];
  return `https://api.dicebear.com/9.x/notionists/svg?seed=${encodeURIComponent(meta.seed)}&backgroundColor=e8eef2,e7f0ec,efe8f4,f3ece4,e8eef8`;
}

function avatarPortrait(id) {
  const meta = AVATARS.find((item) => item.id === id) || AVATARS[0];
  return `<img class="avatar-art" src="${avatarUrl(meta.id)}" alt="" width="80" height="80" loading="lazy" decoding="async" />`;
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

const NAV_KEY = "veritas.admin.navCollapsed";

function mountAdminNav() {
  const host = $("#appNav");
  const frame = $("#appFrame");
  if (!host || !frame) return;

  let collapsed = false;
  try {
    collapsed = localStorage.getItem(NAV_KEY) === "1";
  } catch (_) {}
  frame.classList.toggle("nav-collapsed", collapsed);

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
    <p class="nav-label">Admin</p>
    <a class="nav-link active" href="/admin/">
      <svg class="icon" viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" /></svg>
      <span class="nav-link-text">Users</span>
    </a>
    <a class="nav-link" href="/user/">
      <svg class="icon" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
      <span class="nav-link-text">My account</span>
    </a>
    <button type="button" class="nav-link nav-logout" id="navLogout">
      <svg class="icon" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="M16 17l5-5-5-5" /><path d="M21 12H9" /></svg>
      <span class="nav-link-text">Sign out</span>
    </button>
    <div class="app-nav-footer">Administrator console for account access.</div>
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

function positionMenuPanel(menu) {
  const trigger = $(".menu-trigger", menu);
  const panel = $(".menu-panel", menu);
  if (!trigger || !panel) return;
  panel.style.visibility = "hidden";
  const triggerRect = trigger.getBoundingClientRect();
  const panelRect = panel.getBoundingClientRect();
  const gap = 4;
  let top = triggerRect.bottom + gap;
  let left = triggerRect.right - panelRect.width;
  if (left < 8) left = 8;
  if (left + panelRect.width > window.innerWidth - 8) left = Math.max(8, window.innerWidth - panelRect.width - 8);
  if (top + panelRect.height > window.innerHeight - 8) top = Math.max(8, triggerRect.top - panelRect.height - gap);
  panel.style.top = `${top}px`;
  panel.style.left = `${left}px`;
  panel.style.right = "auto";
  panel.style.visibility = "";
}

function closeAllMenus() {
  $$(".menu.open").forEach((menu) => {
    menu.classList.remove("open");
    const panel = $(".menu-panel", menu);
    if (panel) {
      panel.style.top = "";
      panel.style.left = "";
      panel.style.visibility = "";
    }
  });
}

function bindMenus(items, onAction) {
  $$(".menu").forEach((menu) => {
    $(".menu-trigger", menu).addEventListener("click", (event) => {
      event.stopPropagation();
      const willOpen = !menu.classList.contains("open");
      closeAllMenus();
      if (willOpen) {
        menu.classList.add("open");
        positionMenuPanel(menu);
      }
    });
    $$("[data-a]", menu).forEach((button) => {
      button.addEventListener("click", async (event) => {
        event.stopPropagation();
        menu.classList.remove("open");
        await onAction(button.dataset.a, button.dataset.id, items);
      });
    });
  });
}

document.addEventListener("click", closeAllMenus);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeAllMenus();
});
window.addEventListener("resize", closeAllMenus);
window.addEventListener("scroll", closeAllMenus, true);

function menuItemsFor(user) {
  const items = [
    { action: "edit", label: "Edit profile" },
    { action: "history", label: "View history" },
  ];
  if (user.status === "pending_approval") {
    items.push({ sep: true }, { action: "approve", label: "Approve" }, { action: "reject", label: "Reject", danger: true });
  }
  if (user.status === "active") items.push({ sep: true }, { action: "deactivate", label: "Deactivate", danger: true });
  if (user.status === "deactivated") items.push({ sep: true }, { action: "reactivate", label: "Reactivate" });
  return items
    .map((item) => {
      if (item.sep) return `<div class="menu-sep" role="separator"></div>`;
      return `<button type="button" class="${item.danger ? "danger" : ""}" data-a="${item.action}" data-id="${user.id}">${item.label}</button>`;
    })
    .join("");
}

async function main() {
  try {
    const { user } = await api("/auth/me");
    if (user.role !== "admin") return (location.href = "/user/");
    mountAdminNav();

    const runAction = async (action, id, items) => {
      try {
        if (action === "edit") {
          const current = items.find((x) => x.id === id);
          const display_name = prompt("Display name", current.display_name);
          if (display_name === null) return;
          const email = prompt("Email address", current.email);
          if (email === null) return;
          const role = prompt("Role: admin or user", current.role);
          if (role === null) return;
          await api(`/admin/users/${id}`, { method: "PATCH", body: JSON.stringify({ display_name, email, role }) });
        } else if (action === "history") {
          const details = await api(`/admin/users/${id}`);
          alert(details.audit_events.map((x) => `${new Date(x.created_at).toLocaleString()} — ${x.action}`).join("\n") || "No audit events yet.");
        } else {
          await api(`/admin/users/${id}/${action}`, { method: "POST" });
        }
        fetchUsers();
      } catch (error) {
        alert(error.message);
      }
    };

    const fetchUsers = async () => {
      const q = $("#search").value;
      const status = $("#statusFilter").value;
      const data = await api(`/admin/users?q=${encodeURIComponent(q)}&account_status=${encodeURIComponent(status)}`);
      if (!data.items.length) {
        $("#userRows").innerHTML = `<tr><td colspan="5"><div class="empty-state"><strong>No users match</strong>Adjust search or status filters.</div></td></tr>`;
        return;
      }
      $("#userRows").innerHTML = data.items
        .map((u) => {
          const activity = new Date(u.last_login_at || u.email_verified_at || Date.now()).toLocaleDateString();
          return `<tr>
            <td><div class="user-cell"><span class="user-avatar">${avatarPortrait(u.avatar)}</span><span><b>${escapeHtml(u.display_name)}</b><small>@${escapeHtml(u.username || "—")} · ${escapeHtml(u.email)}</small></span></div></td>
            <td>${escapeHtml(u.role)}</td>
            <td><span class="badge ${escapeHtml(u.status)}">${formatStatus(u.status)}</span></td>
            <td>${activity}</td>
            <td class="col-actions"><div class="menu"><button type="button" class="menu-trigger" aria-label="Manage ${escapeHtml(u.display_name)}" aria-haspopup="menu">${iconMore}</button><div class="menu-panel" role="menu">${menuItemsFor(u)}</div></div></td>
          </tr>`;
        })
        .join("");
      bindMenus(data.items, runAction);
    };

    $("#search").oninput = fetchUsers;
    $("#statusFilter").onchange = fetchUsers;
    fetchUsers();
  } catch (_) {
    location.href = "/";
  }
}

main();
