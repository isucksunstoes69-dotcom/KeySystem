/* MC License Manager - dashboard logic. Talks to the same-origin admin API. */
(function () {
  "use strict";

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));
  const TOKEN_KEY = "lic_admin_token";

  let TOKEN = sessionStorage.getItem(TOKEN_KEY) || "";
  let LICENSES = [];
  let FILTER = "all";
  let SEARCH = "";

  // ---- helpers ----------------------------------------------------------
  const esc = (s) =>
    String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  function icons() { if (window.lucide) lucide.createIcons(); }

  function toast(msg, type) {
    const box = $("#toast");
    const el = document.createElement("div");
    el.className = "toast" + (type ? " " + type : "");
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(() => el.remove(), 3000);
  }

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      const ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); } catch (_) {}
      ta.remove();
    }
    toast("Copied to clipboard", "ok");
  }

  function authHeaders(extra) {
    return Object.assign({ "X-Admin-Token": TOKEN }, extra || {});
  }

  function statusOf(l) {
    if (l.revoked) return "revoked";
    if (l.expiry && Date.now() >= l.expiry) return "expired";
    if (!l.hwid) return "unbound";
    return "active";
  }

  // ---- auth -------------------------------------------------------------
  async function doLogin() {
    const t = $("#token").value.trim();
    const err = $("#loginErr");
    if (!t) { err.textContent = "Enter your admin token."; return; }
    err.textContent = "Checking…";
    try {
      const r = await fetch("/api/admin/list?format=json", { headers: { "X-Admin-Token": t } });
      if (r.status === 401) { err.textContent = "Invalid admin token."; return; }
      if (!r.ok) { err.textContent = "Server error (" + r.status + ")."; return; }
      TOKEN = t; sessionStorage.setItem(TOKEN_KEY, t);
      LICENSES = await r.json();
      err.textContent = "";
      showDashboard();
    } catch (e) {
      err.textContent = "Cannot reach the license server. Is it running?";
    }
  }

  function logout() {
    TOKEN = ""; sessionStorage.removeItem(TOKEN_KEY);
    $("#dashboard-view").classList.add("hidden");
    $("#login-view").classList.remove("hidden");
    $("#token").value = "";
  }

  function showDashboard() {
    $("#login-view").classList.add("hidden");
    $("#dashboard-view").classList.remove("hidden");
    render();
  }

  async function refresh(quiet) {
    try {
      const r = await fetch("/api/admin/list?format=json", { headers: authHeaders() });
      if (r.status === 401) { logout(); return; }
      if (!r.ok) { toast("Failed to load (" + r.status + ")", "err"); return; }
      LICENSES = await r.json();
      render();
      if (!quiet) toast("Refreshed", "ok");
    } catch (e) {
      toast("Cannot reach server", "err");
    }
  }

  // ---- rendering --------------------------------------------------------
  function render() {
    let usable = 0, revoked = 0, expired = 0;
    LICENSES.forEach((l) => {
      const s = statusOf(l);
      if (s === "revoked") revoked++;
      else if (s === "expired") expired++;
      else usable++; // active or unbound
    });
    $("#stTotal").textContent = LICENSES.length;
    $("#stActive").textContent = usable;
    $("#stRevoked").textContent = revoked;
    $("#stExpired").textContent = expired;

    const q = SEARCH.toLowerCase();
    const rows = LICENSES.filter((l) => {
      const s = statusOf(l);
      const okFilter = FILTER === "all" || s === FILTER;
      const hay = (l.key + " " + l.product + " " + l.owner + " " + l.email).toLowerCase();
      return okFilter && (!q || hay.includes(q));
    });

    $("#grid").innerHTML = rows.map(cardHtml).join("");
    $("#emptyState").classList.toggle("hidden", rows.length > 0);
    icons();
  }

  function cardHtml(l) {
    const s = statusOf(l);
    const exp = l.expiry ? new Date(l.expiry).toLocaleDateString() : "Perpetual";
    const hwid = l.hwid ? esc(l.hwid.slice(0, 18)) + "…" : "—";
    return (
      '<li class="lcard" data-key="' + esc(l.key) + '">' +
        '<div class="lcard-top">' +
          '<div><div class="lcard-product">' + esc(l.product) + "</div>" +
          '<div class="lcard-owner">' + esc(l.owner || "—") + "</div></div>" +
          '<span class="badge ' + s + '">' + s + "</span>" +
        "</div>" +
        '<div class="keyrow"><code title="' + esc(l.key) + '">' + esc(l.key) + "</code>" +
          '<button class="mini copy" title="Copy key"><i data-lucide="copy"></i></button></div>' +
        '<div class="lcard-meta">' +
          '<span class="k">Email</span><span class="v" title="' + esc(l.email) + '">' + esc(l.email || "—") + "</span>" +
          '<span class="k">Expiry</span><span class="v">' + exp + "</span>" +
          '<span class="k">HWID</span><span class="v" title="' + esc(l.hwid || "") + '">' + hwid + "</span>" +
          '<span class="k">UID</span><span class="v">' + esc(l.uid) + "</span>" +
        "</div>" +
        '<div class="lcard-foot">' +
          '<button class="rebind"><i data-lucide="refresh-ccw"></i> Rebind</button>' +
          '<button class="revoke"><i data-lucide="ban"></i> Revoke</button>' +
        "</div>" +
      "</li>"
    );
  }

  // ---- license actions --------------------------------------------------
  async function post(path, body) {
    return fetch(path, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
      body: body,
    });
  }

  async function doRevoke(key) {
    try {
      const r = await post("/api/admin/revoke", "licenseKey=" + encodeURIComponent(key) + "&format=json");
      if (r.ok) { toast("License revoked", "ok"); refresh(true); }
      else toast("Revoke failed (" + r.status + ")", "err");
    } catch (e) { toast("Cannot reach server", "err"); }
  }

  async function doRebind(key) {
    try {
      const r = await post("/api/admin/rebind", "licenseKey=" + encodeURIComponent(key) + "&format=json");
      if (r.ok) { toast("HWID cleared — can activate on a new machine", "ok"); refresh(true); }
      else toast("Rebind failed (" + r.status + ")", "err");
    } catch (e) { toast("Cannot reach server", "err"); }
  }

  // ---- create modal -----------------------------------------------------
  function openModal() {
    resetCreateBtn();
    $("#createForm").reset();
    $("#createdKey").style.display = "none";
    $("#modal").classList.remove("hidden");
    icons();
  }
  function closeModal() { $("#modal").classList.add("hidden"); }
  function resetCreateBtn() { $("#createBtn").classList.remove("is-driving", "is-success"); }

  async function submitCreate(e) {
    e.preventDefault();
    const btn = $("#createBtn");
    if (btn.classList.contains("is-driving") || btn.classList.contains("is-success")) return;

    const fd = new FormData($("#createForm"));
    const p = new URLSearchParams();
    p.set("product", (fd.get("product") || "").trim());
    p.set("owner", (fd.get("owner") || "").trim());
    p.set("email", (fd.get("email") || "").trim());
    p.set("days", fd.get("days") || "0");
    p.set("format", "json");
    if (!p.get("product")) { toast("Product is required", "err"); return; }

    btn.classList.add("is-driving");
    try {
      const r = await post("/api/admin/create", p.toString());
      if (!r.ok) { resetCreateBtn(); toast("Create failed (" + r.status + ")", "err"); return; }
      const data = await r.json();
      // Let the truck finish its 2s drive, then reveal success + the key.
      setTimeout(() => {
        btn.classList.remove("is-driving");
        btn.classList.add("is-success");
        $("#createdKeyValue").textContent = data.key;
        $("#createdKey").style.display = "block";
        copy(data.key);
        refresh(true);
      }, 2050);
    } catch (err) {
      resetCreateBtn();
      toast("Cannot reach server", "err");
    }
  }

  // ---- filter wiring ----------------------------------------------------
  function setFilter(f) {
    showView("licenses");
    FILTER = f;
    $$(".chip").forEach((c) => c.classList.toggle("active", c.dataset.filter === f));
    $$(".nav-item[data-filter]").forEach((n) => n.classList.toggle("active", n.dataset.filter === f));
    render();
  }

  // ---- events -----------------------------------------------------------
  function wire() {
    $("#loginBtn").addEventListener("click", doLogin);
    $("#token").addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); });

    $("#refreshBtn").addEventListener("click", () => refresh(false));
    $("#newBtn").addEventListener("click", openModal);
    $("#navCreate").addEventListener("click", openModal);
    $("#navLogout").addEventListener("click", logout);
    $("#modalClose").addEventListener("click", closeModal);
    $("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });
    $("#createForm").addEventListener("submit", submitCreate);

    $("#searchInput").addEventListener("input", (e) => { SEARCH = e.target.value; render(); });

    $("#chips").addEventListener("click", (e) => {
      const c = e.target.closest(".chip"); if (c) setFilter(c.dataset.filter);
    });
    $$(".nav-item[data-filter]").forEach((n) =>
      n.addEventListener("click", () => setFilter(n.dataset.filter))
    );

    $("#grid").addEventListener("click", (e) => {
      const li = e.target.closest(".lcard"); if (!li) return;
      const key = li.dataset.key;
      if (e.target.closest(".copy")) copy(key);
      else if (e.target.closest(".rebind")) {
        if (confirm("Rebind " + key + "?\nThis clears its bound machine so it can activate on a new PC.")) doRebind(key);
      } else if (e.target.closest(".revoke")) {
        if (confirm("Revoke " + key + "?\nThis permanently disables the license.")) doRevoke(key);
      }
    });

    // resellers
    $("#navResellers").addEventListener("click", () => showView("resellers"));
    $("#newResellerBtn").addEventListener("click", openResellerModal);
    $("#resellerModalClose").addEventListener("click", closeResellerModal);
    $("#resellerModal").addEventListener("click", (e) => { if (e.target.id === "resellerModal") closeResellerModal(); });
    $("#doCreateReseller").addEventListener("click", createReseller);
    $("#resellerGrid").addEventListener("click", (e) => {
      const li = e.target.closest(".lcard"); if (!li) return;
      if (e.target.closest(".copyapi")) copy(li.dataset.apikey);
      else if (e.target.closest(".openpanel")) window.open("/reseller.html", "_blank");
    });

    // bans
    $("#navBans").addEventListener("click", () => showView("bans"));
    $("#addBanBtn").addEventListener("click", addBan);
    $("#banGrid").addEventListener("click", (e) => {
      const li = e.target.closest(".lcard"); if (!li) return;
      if (e.target.closest(".unban")) removeBan(li.dataset.type, li.dataset.value);
    });
  }

  // ---- resellers (super-admin) -----------------------------------------
  let RESELLERS = [];

  function showView(name) {
    $("#view-licenses").classList.toggle("hidden", name !== "licenses");
    $("#view-resellers").classList.toggle("hidden", name !== "resellers");
    $("#view-bans").classList.toggle("hidden", name !== "bans");
    $("#newBtn").classList.toggle("hidden", name !== "licenses");
    $("#newResellerBtn").classList.toggle("hidden", name !== "resellers");
    $("#navResellers").classList.toggle("active", name === "resellers");
    $("#navBans").classList.toggle("active", name === "bans");
    if (name !== "licenses") $$(".nav-item[data-filter]").forEach((n) => n.classList.remove("active"));
    if (name === "resellers") loadResellers();
    if (name === "bans") loadBans();
  }

  // ---- bans -------------------------------------------------------------
  let BANS = [];
  async function loadBans() {
    try {
      const r = await fetch("/api/admin/bans", { headers: authHeaders() });
      if (r.status === 401) { logout(); return; }
      BANS = await r.json();
      $("#banGrid").innerHTML = BANS.map(banCardHtml).join("");
      $("#banEmpty").classList.toggle("hidden", BANS.length > 0);
      icons();
    } catch (e) { toast("Failed to load bans", "err"); }
  }
  function banCardHtml(b) {
    return (
      '<li class="lcard" data-type="' + esc(b.type) + '" data-value="' + esc(b.value) + '">' +
        '<div class="lcard-top"><div><div class="lcard-product">' + esc(b.value) + "</div>" +
          '<div class="lcard-owner">' + esc(b.reason || "—") + "</div></div>" +
          '<span class="badge revoked">' + esc(b.type) + "</span></div>" +
        '<div class="lcard-foot"><button class="unban"><i data-lucide="shield-check"></i> Unban</button></div>' +
      "</li>"
    );
  }
  async function addBan() {
    const type = $("#banType").value, value = $("#banValue").value.trim(), reason = $("#banReason").value.trim();
    if (!value) { toast("Enter a value to ban", "err"); return; }
    try {
      const r = await post("/api/admin/ban", "type=" + encodeURIComponent(type) + "&value=" + encodeURIComponent(value) + "&reason=" + encodeURIComponent(reason));
      if (r.ok) { toast("Banned " + type + " " + value, "ok"); $("#banValue").value = ""; $("#banReason").value = ""; loadBans(); }
      else toast("Ban failed (" + r.status + ")", "err");
    } catch (e) { toast("Cannot reach server", "err"); }
  }
  async function removeBan(type, value) {
    try {
      const r = await post("/api/admin/unban", "type=" + encodeURIComponent(type) + "&value=" + encodeURIComponent(value));
      if (r.ok) { toast("Unbanned", "ok"); loadBans(); } else toast("Unban failed", "err");
    } catch (e) { toast("Cannot reach server", "err"); }
  }

  async function loadResellers() {
    try {
      const r = await fetch("/api/admin/reseller/list", { headers: authHeaders() });
      if (r.status === 401) { logout(); return; }
      RESELLERS = await r.json();
      $("#resellerGrid").innerHTML = RESELLERS.map(resellerCardHtml).join("");
      $("#resellerEmpty").classList.toggle("hidden", RESELLERS.length > 0);
      icons();
    } catch (e) { toast("Failed to load resellers", "err"); }
  }

  function resellerCardHtml(r) {
    return (
      '<li class="lcard" data-apikey="' + esc(r.apiKey) + '">' +
        '<div class="lcard-top"><div><div class="lcard-product">' + esc(r.name) + "</div>" +
          '<div class="lcard-owner">' + esc(r.id) + "</div></div>" +
          '<span class="badge active">' + esc(r.licenses) + " licenses</span></div>" +
        '<div class="keyrow"><code title="' + esc(r.apiKey) + '">' + esc(r.apiKey) + "</code>" +
          '<button class="mini copyapi" title="Copy API key"><i data-lucide="copy"></i></button></div>' +
        '<div class="lcard-foot"><button class="openpanel"><i data-lucide="external-link"></i> Open reseller panel</button></div>' +
      "</li>"
    );
  }

  function openResellerModal() {
    $("#resellerName").value = "";
    $("#createdReseller").style.display = "none";
    $("#resellerModal").classList.remove("hidden");
    icons();
  }
  function closeResellerModal() { $("#resellerModal").classList.add("hidden"); }

  async function createReseller() {
    const name = $("#resellerName").value.trim();
    if (!name) { toast("Enter a reseller name", "err"); return; }
    try {
      const r = await post("/api/admin/reseller/create", "name=" + encodeURIComponent(name));
      if (!r.ok) { toast("Create failed (" + r.status + ")", "err"); return; }
      const data = await r.json();
      $("#createdResellerKey").textContent = data.apiKey;
      $("#createdResellerId").textContent = "id: " + data.id;
      $("#createdReseller").style.display = "block";
      copy(data.apiKey);
      loadResellers();
    } catch (e) { toast("Cannot reach server", "err"); }
  }

  // ---- init -------------------------------------------------------------
  async function init() {
    wire();
    icons();
    if (TOKEN) {
      try {
        const r = await fetch("/api/admin/list?format=json", { headers: authHeaders() });
        if (r.ok) { LICENSES = await r.json(); showDashboard(); return; }
      } catch (e) { /* fall through to login */ }
      TOKEN = ""; sessionStorage.removeItem(TOKEN_KEY);
    }
    // default: login view is already visible
  }

  document.addEventListener("DOMContentLoaded", init);
})();
