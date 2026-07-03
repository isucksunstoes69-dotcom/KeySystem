/* Reseller panel - talks to /api/reseller/* with the reseller's API key. */
(function () {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));
  const KEY = "reseller_api_key";

  let APIKEY = sessionStorage.getItem(KEY) || "";
  let LICENSES = [];
  let SEARCH = "";

  const esc = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const icons = () => { if (window.lucide) lucide.createIcons(); };

  function toast(msg, type) {
    const el = document.createElement("div");
    el.className = "toast" + (type ? " " + type : "");
    el.textContent = msg;
    $("#toast").appendChild(el);
    setTimeout(() => el.remove(), 3200);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); }
    catch (e) { const t = document.createElement("textarea"); t.value = text; document.body.appendChild(t); t.select(); try { document.execCommand("copy"); } catch (_) {} t.remove(); }
    toast("Copied", "ok");
  }
  const hdr = () => ({ "X-Api-Key": APIKEY });
  function statusOf(l) {
    if (l.revoked) return "revoked";
    if (l.expiry && Date.now() >= l.expiry) return "expired";
    if (!l.hwid) return "unbound";
    return "active";
  }

  async function login() {
    const k = $("#apiKey").value.trim();
    const err = $("#loginErr");
    if (!k) { err.textContent = "Enter your API key."; return; }
    err.textContent = "Checking…";
    try {
      const r = await fetch("/api/reseller/me", { headers: { "X-Api-Key": k } });
      if (r.status === 401) { err.textContent = "Invalid API key."; return; }
      if (!r.ok) { err.textContent = "Server error (" + r.status + ")."; return; }
      APIKEY = k; sessionStorage.setItem(KEY, k);
      const me = await r.json();
      err.textContent = "";
      showPanel(me);
    } catch (e) { err.textContent = "Cannot reach the server."; }
  }

  function logout() { APIKEY = ""; sessionStorage.removeItem(KEY); $("#panel-view").classList.add("hidden"); $("#login-view").classList.remove("hidden"); $("#apiKey").value = ""; }

  async function showPanel(me) {
    $("#login-view").classList.add("hidden");
    $("#panel-view").classList.remove("hidden");
    $("#whoami").textContent = me.name + "  ·  " + me.id;
    $("#apiKeyShow").textContent = APIKEY;
    $("#snippet").textContent =
      'curl -X POST "' + location.origin + '/api/reseller/download?product=YOURPRODUCT&customer=ORDER_ID" -H "X-Api-Key: ' + APIKEY + '" -o mod.jar';
    await refresh(true);
    icons();
  }

  async function refresh(quiet) {
    try {
      const r = await fetch("/api/reseller/licenses", { headers: hdr() });
      if (r.status === 401) { logout(); return; }
      LICENSES = await r.json();
      render();
      if (!quiet) toast("Refreshed", "ok");
    } catch (e) { toast("Cannot reach server", "err"); }
  }

  function render() {
    let usable = 0, revoked = 0;
    const products = new Set();
    LICENSES.forEach((l) => {
      const s = statusOf(l);
      if (s === "revoked") revoked++; else usable++;
      if (l.product) products.add(l.product);
    });
    $("#stTotal").textContent = LICENSES.length;
    $("#stActive").textContent = usable;
    $("#stRevoked").textContent = revoked;
    $("#stProducts").textContent = products.size;

    const q = SEARCH.toLowerCase();
    const rows = LICENSES.filter((l) => !q || (l.key + " " + l.product + " " + l.customer).toLowerCase().includes(q));
    $("#grid").innerHTML = rows.map(cardHtml).join("");
    $("#emptyState").classList.toggle("hidden", rows.length > 0);
    icons();
  }

  function cardHtml(l) {
    const s = statusOf(l);
    const exp = l.expiry ? new Date(l.expiry).toLocaleDateString() : "Perpetual";
    const hwid = l.hwid ? esc(l.hwid.slice(0, 18)) + "…" : "not activated yet";
    return (
      '<li class="lcard" data-product="' + esc(l.product) + '" data-customer="' + esc(l.customer) + '">' +
        '<div class="lcard-top"><div><div class="lcard-product">' + esc(l.product) + "</div>" +
          '<div class="lcard-owner">' + esc(l.customer || "—") + "</div></div>" +
          '<span class="badge ' + s + '">' + s + "</span></div>" +
        '<div class="keyrow"><code title="' + esc(l.key) + '">' + esc(l.key) + "</code>" +
          '<button class="mini copy" title="Copy key"><i data-lucide="copy"></i></button></div>' +
        '<div class="lcard-meta">' +
          '<span class="k">Expiry</span><span class="v">' + exp + "</span>" +
          '<span class="k">Machine</span><span class="v" title="' + esc(l.hwid || "") + '">' + hwid + "</span>" +
        "</div>" +
        '<div class="lcard-foot"><button class="rebind"><i data-lucide="refresh-ccw"></i> Reset HWID</button></div>' +
      "</li>"
    );
  }

  async function resetHwid(product, customer) {
    try {
      const r = await fetch("/api/reseller/reset", {
        method: "POST", headers: Object.assign(hdr(), { "Content-Type": "application/x-www-form-urlencoded" }),
        body: "product=" + encodeURIComponent(product) + "&customer=" + encodeURIComponent(customer),
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok) { toast("HWID reset — customer can activate on a new PC", "ok"); refresh(true); }
      else if (r.status === 429) { toast("On cooldown — " + (data.daysLeft || "?") + " day(s) left", "err"); }
      else { toast("Reset failed (" + r.status + ")", "err"); }
    } catch (e) { toast("Cannot reach server", "err"); }
  }

  // upload
  function openUpload() { $("#modal").classList.remove("hidden"); $("#upErr").textContent = ""; icons(); }
  function closeUpload() { $("#modal").classList.add("hidden"); }
  async function doUpload() {
    const product = $("#upProduct").value.trim();
    const file = $("#upFile").files[0];
    const err = $("#upErr");
    if (!product) { err.textContent = "Enter a product name."; return; }
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(product)) { err.textContent = "Product name: letters, numbers, . _ - only."; return; }
    if (!file) { err.textContent = "Choose a .jar file."; return; }
    err.textContent = "Uploading…";
    try {
      const r = await fetch("/api/reseller/upload?product=" + encodeURIComponent(product), { method: "POST", headers: hdr(), body: file });
      if (!r.ok) { err.textContent = "Upload failed (" + r.status + ")."; return; }
      const data = await r.json();
      toast("Uploaded " + product + " (" + data.bytes + " bytes)", "ok");
      closeUpload();
      refresh(true);
    } catch (e) { err.textContent = "Cannot reach server."; }
  }

  function wire() {
    $("#loginBtn").addEventListener("click", login);
    $("#apiKey").addEventListener("keydown", (e) => { if (e.key === "Enter") login(); });
    $("#refreshBtn").addEventListener("click", () => refresh(false));
    $("#navLogout").addEventListener("click", logout);
    $("#uploadBtn").addEventListener("click", openUpload);
    $("#navUpload").addEventListener("click", openUpload);
    $("#modalClose").addEventListener("click", closeUpload);
    $("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeUpload(); });
    $("#doUpload").addEventListener("click", doUpload);
    $("#copyApiKey").addEventListener("click", () => copy(APIKEY));
    $("#copySnippet").addEventListener("click", () => copy($("#snippet").textContent));
    $("#searchInput").addEventListener("input", (e) => { SEARCH = e.target.value; render(); });
    $("#grid").addEventListener("click", (e) => {
      const li = e.target.closest(".lcard"); if (!li) return;
      if (e.target.closest(".copy")) copy(li.querySelector("code").getAttribute("title"));
      else if (e.target.closest(".rebind")) {
        if (confirm("Reset HWID for " + li.dataset.customer + "? They'll be able to activate on a new machine (limit: once per 7 days)."))
          resetHwid(li.dataset.product, li.dataset.customer);
      }
    });
  }

  async function init() {
    wire(); icons();
    if (APIKEY) {
      try {
        const r = await fetch("/api/reseller/me", { headers: hdr() });
        if (r.ok) { showPanel(await r.json()); return; }
      } catch (e) {}
      APIKEY = ""; sessionStorage.removeItem(KEY);
    }
  }
  document.addEventListener("DOMContentLoaded", init);
})();
