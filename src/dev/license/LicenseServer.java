package dev.license;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Self-contained license server built on the JDK's HttpServer - no web
 * framework, no dependencies. Also serves the admin dashboard (static files)
 * from the same origin, so the browser UI needs no CORS gymnastics.
 *
 * Public endpoint:
 *   POST /api/validate      (form: product, licenseKey, hwid, nonce)
 *
 * Admin endpoints (require header  X-Admin-Token: &lt;token&gt;):
 *   POST /api/admin/create  (form: product, owner, email, days, [hwid]; [format=json]) -> key
 *   POST /api/admin/revoke  (form: licenseKey)
 *   POST /api/admin/rebind  (form: licenseKey)
 *   GET  /api/admin/list    ([?format=json])
 *
 * Static:
 *   GET  /                   -> web/index.html and other files under LICENSE_WEB_DIR
 */
public final class LicenseServer {

    private final HttpServer http;
    private final LicenseAuthority authority;
    private final LicenseStore store;
    private final byte[] adminToken;
    private final Path webRoot;
    private final ResellerStore resellers;
    private final Path downloadsRoot;
    private UserAuthority userAuthority;  // optional, enabled via withAccounts()
    private Blacklist blacklist;
    private JarInjector injector;         // optional, enabled via withInjector()
    private String publicKeyB64 = "";
    private String publicUrl = "";

    public LicenseServer(int port, LicenseAuthority authority, LicenseStore store, String adminToken) throws IOException {
        this(port, authority, store, adminToken, null, null, null);
    }

    public LicenseServer(int port, LicenseAuthority authority, LicenseStore store, String adminToken, Path webRoot) throws IOException {
        this(port, authority, store, adminToken, webRoot, null, null);
    }

    public LicenseServer(int port, LicenseAuthority authority, LicenseStore store, String adminToken,
                         Path webRoot, ResellerStore resellers, Path downloadsRoot) throws IOException {
        this.authority = authority;
        this.store = store;
        this.adminToken = adminToken.getBytes(StandardCharsets.UTF_8);
        this.webRoot = webRoot == null ? null : webRoot.toAbsolutePath().normalize();
        this.resellers = resellers;
        this.downloadsRoot = downloadsRoot == null ? null : downloadsRoot.toAbsolutePath().normalize();
        this.http = HttpServer.create(new InetSocketAddress(port), 0);
        this.http.setExecutor(Executors.newFixedThreadPool(8));
        this.http.createContext("/api/validate", this::handleValidate);
        this.http.createContext("/api/admin/create", this::handleCreate);
        this.http.createContext("/api/admin/revoke", this::handleRevoke);
        this.http.createContext("/api/admin/rebind", this::handleRebind);
        this.http.createContext("/api/admin/list", this::handleList);
        if (this.resellers != null) {
            this.http.createContext("/api/admin/reseller/create", this::handleResellerCreate);
            this.http.createContext("/api/admin/reseller/list", this::handleResellerList);
            this.http.createContext("/api/reseller/me", this::handleResellerMe);
            this.http.createContext("/api/reseller/licenses", this::handleResellerLicenses);
            this.http.createContext("/api/reseller/upload", this::handleResellerUpload);
            this.http.createContext("/api/reseller/download", this::handleResellerDownload);
            this.http.createContext("/api/reseller/reset", this::handleResellerReset);
        }
        if (this.webRoot != null && Files.isDirectory(this.webRoot)) {
            this.http.createContext("/", this::handleStatic);
        }
    }

    public int start() { http.start(); return http.getAddress().getPort(); }
    public void stop() { http.stop(0); }

    /** Enable KeyAuth-style accounts (/api/auth) + admin ban endpoints. Call before start(). */
    public LicenseServer withAccounts(UserAuthority ua, Blacklist bl) {
        this.userAuthority = ua;
        this.blacklist = bl;
        this.http.createContext("/api/auth", this::handleAuth);
        this.http.createContext("/api/admin/ban", this::handleBan);
        this.http.createContext("/api/admin/unban", this::handleUnban);
        this.http.createContext("/api/admin/bans", this::handleBans);
        return this;
    }

    /** Enable auto-injection of the license client into uploaded Fabric jars. */
    public LicenseServer withInjector(JarInjector inj, String publicKeyB64, String publicUrl) {
        this.injector = inj;
        this.publicKeyB64 = publicKeyB64 == null ? "" : publicKeyB64;
        this.publicUrl = publicUrl == null ? "" : publicUrl;
        return this;
    }

    // ---- API handlers -----------------------------------------------------

    private void handleValidate(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { send(ex, 405, "method not allowed"); return; }
        Map<String, String> form = Form.decode(readBody(ex));
        LicenseRequest req = LicenseRequest.fromForm(form);
        LicenseResponse resp = authority.validate(req);
        sendForm(ex, 200, resp.toForm());
    }

    private void handleCreate(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (!requireAdmin(ex)) return;
        Map<String, String> form = Form.decode(readBody(ex));
        String product = form.getOrDefault("product", "");
        if (product.isEmpty()) { send(ex, 400, "product required"); return; }
        int days = parseInt(form.getOrDefault("days", "0"));
        String key = store.create(product,
                form.getOrDefault("owner", ""),
                form.getOrDefault("email", ""),
                days,
                form.getOrDefault("hwid", ""));
        if (wantsJson(ex, form)) {
            sendJson(ex, 200, "{\"key\":\"" + jsonEsc(key) + "\"}");
        } else {
            send(ex, 200, "created " + key + "\n");
        }
    }

    private void handleRevoke(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (!requireAdmin(ex)) return;
        Map<String, String> form = Form.decode(readBody(ex));
        String key = form.getOrDefault("licenseKey", "");
        store.revoke(key);
        if (wantsJson(ex, form)) sendJson(ex, 200, "{\"ok\":true,\"key\":\"" + jsonEsc(key) + "\"}");
        else send(ex, 200, "revoked " + key + "\n");
    }

    private void handleRebind(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (!requireAdmin(ex)) return;
        Map<String, String> form = Form.decode(readBody(ex));
        String key = form.getOrDefault("licenseKey", "");
        store.rebind(key);
        if (wantsJson(ex, form)) sendJson(ex, 200, "{\"ok\":true,\"key\":\"" + jsonEsc(key) + "\"}");
        else send(ex, 200, "rebound " + key + " (hwid cleared)\n");
    }

    private void handleList(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (!requireAdmin(ex)) return;
        if ("json".equalsIgnoreCase(queryParam(ex, "format"))) {
            sendJson(ex, 200, licensesJson());
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (String k : store.listKeys()) {
            sb.append(k)
              .append("  product=").append(store.product(k))
              .append("  owner=").append(store.owner(k))
              .append("  expiry=").append(store.expiry(k) == 0 ? "never" : store.expiry(k))
              .append("  revoked=").append(store.revoked(k))
              .append("  hwid=").append(store.boundHwid(k).isEmpty() ? "(unbound)" : store.boundHwid(k))
              .append('\n');
        }
        send(ex, 200, sb.toString());
    }

    // ---- static dashboard -------------------------------------------------

    private void handleStatic(HttpExchange ex) throws IOException {
        cors(ex);
        String method = ex.getRequestMethod();
        if ("OPTIONS".equalsIgnoreCase(method)) { ex.sendResponseHeaders(204, -1); return; }
        boolean head = "HEAD".equalsIgnoreCase(method);
        if (!head && !"GET".equalsIgnoreCase(method)) { send(ex, 405, "method not allowed"); return; }

        String path = ex.getRequestURI().getPath();
        if (path.equals("/") || path.isEmpty()) path = "/index.html";
        Path file = webRoot.resolve(path.substring(1)).normalize();
        if (!file.startsWith(webRoot) || !Files.exists(file) || Files.isDirectory(file)) {
            if (head) ex.sendResponseHeaders(404, -1); else send(ex, 404, "not found");
            return;
        }
        byte[] bytes = Files.readAllBytes(file);
        ex.getResponseHeaders().set("Content-Type", contentType(file));
        if (head) {
            ex.sendResponseHeaders(200, -1); // headers only, no body
            return;
        }
        ex.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    // ---- helpers ----------------------------------------------------------

    private boolean requireAdmin(HttpExchange ex) throws IOException {
        String provided = ex.getRequestHeaders().getFirst("X-Admin-Token");
        byte[] p = provided == null ? new byte[0] : provided.getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(p, adminToken)) {
            send(ex, 401, "unauthorized");
            return false;
        }
        return true;
    }

    /** Answer CORS preflight and set CORS headers. Returns true if the request is fully handled. */
    private boolean preflight(HttpExchange ex) throws IOException {
        cors(ex);
        if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
            ex.sendResponseHeaders(204, -1);
            return true;
        }
        return false;
    }

    private static void cors(HttpExchange ex) {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "X-Admin-Token, Content-Type");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    }

    private boolean wantsJson(HttpExchange ex, Map<String, String> form) {
        return "json".equalsIgnoreCase(form.getOrDefault("format", queryParam(ex, "format")));
    }

    private String licensesJson() { return licensesJson(null); }

    private String licensesJson(String resellerFilter) {
        StringBuilder sb = new StringBuilder("[");
        List<String> keys = (resellerFilter == null) ? store.listKeys() : store.listKeys(resellerFilter);
        for (int i = 0; i < keys.size(); i++) {
            String k = keys.get(i);
            if (i > 0) sb.append(',');
            sb.append('{')
              .append("\"key\":\"").append(jsonEsc(k)).append("\",")
              .append("\"product\":\"").append(jsonEsc(store.product(k))).append("\",")
              .append("\"owner\":\"").append(jsonEsc(store.owner(k))).append("\",")
              .append("\"email\":\"").append(jsonEsc(store.email(k))).append("\",")
              .append("\"customer\":\"").append(jsonEsc(store.customer(k))).append("\",")
              .append("\"reseller\":\"").append(jsonEsc(store.reseller(k))).append("\",")
              .append("\"uid\":").append(store.uid(k)).append(',')
              .append("\"expiry\":").append(store.expiry(k)).append(',')
              .append("\"revoked\":").append(store.revoked(k)).append(',')
              .append("\"hwid\":\"").append(jsonEsc(store.boundHwid(k))).append("\"")
              .append('}');
        }
        return sb.append(']').toString();
    }

    private static String queryParam(HttpExchange ex, String name) {
        String q = ex.getRequestURI().getQuery();
        if (q == null) return "";
        for (String pair : q.split("&")) {
            int i = pair.indexOf('=');
            String k = i < 0 ? pair : pair.substring(0, i);
            if (k.equals(name)) return i < 0 ? "" : URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8);
        }
        return "";
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void sendForm(HttpExchange ex, int code, Map<String, String> form) throws IOException {
        cors(ex);
        byte[] out = Form.encode(form).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/x-www-form-urlencoded");
        ex.sendResponseHeaders(code, out.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(out); }
    }

    private static void sendJson(HttpExchange ex, int code, String json) throws IOException {
        cors(ex);
        byte[] out = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, out.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(out); }
    }

    private static void send(HttpExchange ex, int code, String text) throws IOException {
        cors(ex);
        byte[] out = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, out.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(out); }
    }

    private static String contentType(Path p) {
        String n = p.getFileName().toString().toLowerCase();
        if (n.endsWith(".html")) return "text/html; charset=utf-8";
        if (n.endsWith(".css"))  return "text/css; charset=utf-8";
        if (n.endsWith(".js"))   return "application/javascript; charset=utf-8";
        if (n.endsWith(".json")) return "application/json; charset=utf-8";
        if (n.endsWith(".png"))  return "image/png";
        if (n.endsWith(".svg"))  return "image/svg+xml";
        if (n.endsWith(".ico"))  return "image/x-icon";
        if (n.endsWith(".woff2"))return "font/woff2";
        return "application/octet-stream";
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    private static int parseInt(String s) { try { return Integer.parseInt(s.trim()); } catch (Exception e) { return 0; } }

    // ---- reseller (tenant) endpoints -------------------------------------

    /** Super-admin: create a reseller account. */
    private void handleResellerCreate(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (!requireAdmin(ex)) return;
        Map<String, String> form = Form.decode(readBody(ex));
        String name = form.getOrDefault("name", "").trim();
        if (name.isEmpty()) { send(ex, 400, "name required"); return; }
        String[] r = resellers.create(name);
        sendJson(ex, 200, "{\"id\":\"" + jsonEsc(r[0]) + "\",\"apiKey\":\"" + jsonEsc(r[1])
                + "\",\"name\":\"" + jsonEsc(name) + "\"}");
    }

    /** Super-admin: list all resellers. */
    private void handleResellerList(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (!requireAdmin(ex)) return;
        StringBuilder sb = new StringBuilder("[");
        List<String> ids = resellers.listIds();
        for (int i = 0; i < ids.size(); i++) {
            String id = ids.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"id\":\"").append(jsonEsc(id))
              .append("\",\"name\":\"").append(jsonEsc(resellers.name(id)))
              .append("\",\"apiKey\":\"").append(jsonEsc(resellers.apiKey(id)))
              .append("\",\"licenses\":").append(store.listKeys(id).size()).append('}');
        }
        sendJson(ex, 200, sb.append(']').toString());
    }

    /** Reseller: who am I (used by the panel to confirm the API key). */
    private void handleResellerMe(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        String id = requireReseller(ex); if (id == null) return;
        sendJson(ex, 200, "{\"id\":\"" + jsonEsc(id) + "\",\"name\":\"" + jsonEsc(resellers.name(id)) + "\"}");
    }

    /** Reseller: list only my own licenses. */
    private void handleResellerLicenses(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        String id = requireReseller(ex); if (id == null) return;
        sendJson(ex, 200, licensesJson(id));
    }

    /** Reseller: upload/replace the .jar for one of my products (jar bytes = request body). */
    private void handleResellerUpload(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        String id = requireReseller(ex); if (id == null) return;
        if (downloadsRoot == null) { send(ex, 500, "downloads dir not configured"); return; }
        String product = queryParam(ex, "product").trim();
        if (product.isEmpty()) { send(ex, 400, "product query param required"); return; }
        if (!safeName(product)) { send(ex, 400, "invalid product name"); return; }
        byte[] jar;
        try (InputStream in = ex.getRequestBody()) { jar = in.readAllBytes(); }
        if (jar.length == 0) { send(ex, 400, "empty body — send the .jar as the raw request body"); return; }
        Path dir = downloadsRoot.resolve(id);
        Files.createDirectories(dir);
        Path base = dir.resolve(product + ".jar");
        Files.write(base, jar);

        // Optional: inject the license client under the reseller's package so the mod self-enforces.
        Path injectedFile = dir.resolve(product + ".injected.jar");
        Files.deleteIfExists(injectedFile);
        String pkg = queryParam(ex, "package").trim();
        String extra = "";
        if (!pkg.isEmpty()) {
            if (injector == null) { send(ex, 400, "injection unavailable (server must run on a JDK with a public key)"); return; }
            try {
                JarInjector.Config cfg = new JarInjector.Config();
                cfg.baseUrl = publicUrl; cfg.publicKeyB64 = publicKeyB64; cfg.product = product;
                Files.write(injectedFile, injector.inject(base, pkg, cfg));
                extra = ",\"injected\":true,\"package\":\"" + jsonEsc(pkg) + "\"";
            } catch (Exception e) {
                send(ex, 400, "injection failed: " + e.getMessage()); return;
            }
        }
        sendJson(ex, 200, "{\"ok\":true,\"product\":\"" + jsonEsc(product) + "\",\"bytes\":" + jar.length + extra + "}");
    }

    /**
     * Reseller download API - the core. Idempotent per (reseller, product, customer):
     * first call mints a license, the same customer re-downloading gets the same key.
     * The key is baked into the product jar and returned as an attachment.
     */
    private void handleResellerDownload(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        String id = requireReseller(ex); if (id == null) return;
        if (downloadsRoot == null) { send(ex, 500, "downloads dir not configured"); return; }
        Map<String, String> form = Form.decode(readBody(ex));
        String product = firstNonEmpty(form.get("product"), queryParam(ex, "product")).trim();
        String customer = firstNonEmpty(form.get("customer"), queryParam(ex, "customer")).trim();
        if (product.isEmpty() || customer.isEmpty()) { send(ex, 400, "product and customer are required"); return; }
        if (!safeName(product)) { send(ex, 400, "invalid product name"); return; }

        // Prefer the injected (self-enforcing) jar if one exists.
        Path injectedFile = downloadsRoot.resolve(id).resolve(product + ".injected.jar");
        Path plainFile = downloadsRoot.resolve(id).resolve(product + ".jar");
        Path jarFile;
        boolean injected;
        if (Files.exists(injectedFile)) { jarFile = injectedFile; injected = true; }
        else if (Files.exists(plainFile)) { jarFile = plainFile; injected = false; }
        else { send(ex, 404, "no jar uploaded for product '" + product + "'"); return; }

        String key = store.findKey(id, product, customer);
        if (key == null) {
            key = store.create(product, customer, customer, 0, "", id, customer);
        }
        byte[] stamped;
        if (injected) {
            String pkgPath = JarInjector.readPackagePath(jarFile);
            String entry = (pkgPath == null || pkgPath.isEmpty() ? "" : pkgPath + "/") + "license.key";
            stamped = JarStamper.stamp(jarFile, entry, key.getBytes(StandardCharsets.UTF_8));
        } else {
            stamped = JarStamper.stampKey(jarFile, key);
        }
        cors(ex);
        ex.getResponseHeaders().set("Content-Type", "application/java-archive");
        ex.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + product + ".jar\"");
        ex.getResponseHeaders().set("X-License-Key", key);
        ex.sendResponseHeaders(200, stamped.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(stamped); }
    }

    /** Reseller-exposed customer HWID self-reset, limited to once per 7 days. */
    private void handleResellerReset(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        String id = requireReseller(ex); if (id == null) return;
        Map<String, String> form = Form.decode(readBody(ex));
        String product = firstNonEmpty(form.get("product"), queryParam(ex, "product")).trim();
        String customer = firstNonEmpty(form.get("customer"), queryParam(ex, "customer")).trim();
        if (product.isEmpty() || customer.isEmpty()) { send(ex, 400, "product and customer are required"); return; }
        String key = store.findKey(id, product, customer);
        if (key == null) { send(ex, 404, "no license for that customer/product"); return; }

        final long cooldown = 7L * 24 * 3600 * 1000;
        long last = store.lastReset(key);
        long since = System.currentTimeMillis() - last;
        if (last != 0 && since < cooldown) {
            long daysLeft = (cooldown - since) / (24 * 3600 * 1000) + 1;
            sendJson(ex, 429, "{\"ok\":false,\"reason\":\"COOLDOWN\",\"daysLeft\":" + daysLeft + "}");
            return;
        }
        store.rebind(key);                                   // clear bound HWID
        store.setLastReset(key, System.currentTimeMillis());
        sendJson(ex, 200, "{\"ok\":true,\"key\":\"" + jsonEsc(key) + "\"}");
    }

    /** Resolve a reseller from the X-Api-Key header (or ?apiKey=), or 401. */
    private String requireReseller(HttpExchange ex) throws IOException {
        String key = ex.getRequestHeaders().getFirst("X-Api-Key");
        if (key == null || key.isEmpty()) key = queryParam(ex, "apiKey");
        String id = resellers.resolveApiKey(key);
        if (id == null) { send(ex, 401, "invalid api key"); return null; }
        return id;
    }

    private static String firstNonEmpty(String a, String b) {
        if (a != null && !a.isEmpty()) return a;
        return b == null ? "" : b;
    }

    private static boolean safeName(String s) {
        return s != null && s.matches("[A-Za-z0-9._-]{1,64}") && !s.contains("..");
    }

    // ---- KeyAuth-style accounts (/api/auth) ------------------------------

    private void handleAuth(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (userAuthority == null) { send(ex, 404, "accounts disabled"); return; }
        Map<String, String> f = Form.decode(readBody(ex));
        String type = firstNonEmpty(f.get("type"), queryParam(ex, "type")).toLowerCase();
        String hwid = f.getOrDefault("hwid", "");
        String pass = firstNonEmpty(f.get("pass"), f.getOrDefault("password", ""));
        String ip = clientIp(ex);

        switch (type) {
            case "init":
                sendJson(ex, 200, "{\"success\":true,\"message\":\"initialized\",\"sessionid\":\"" + Crypto.newNonce() + "\"}");
                return;
            case "check":
                sendJson(ex, 200, "{\"success\":true,\"message\":\"valid\"}");
                return;
            case "license":
                sendJson(ex, 200, authJson(userAuthority.license(f.getOrDefault("key", ""), hwid, ip)));
                return;
            case "register":
                sendJson(ex, 200, authJson(userAuthority.register(f.getOrDefault("username", ""), pass, f.getOrDefault("key", ""), hwid, ip)));
                return;
            case "login":
                sendJson(ex, 200, authJson(userAuthority.login(f.getOrDefault("username", ""), pass, hwid, ip)));
                return;
            default:
                send(ex, 400, "unknown auth type '" + type + "'");
        }
    }

    private String authJson(UserAuthority.Result r) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"success\":").append(r.success)
          .append(",\"status\":\"").append(jsonEsc(r.status)).append('"')
          .append(",\"message\":\"").append(jsonEsc(r.message)).append('"');
        if (r.username != null) sb.append(",\"username\":\"").append(jsonEsc(r.username)).append('"');
        if (r.license != null) sb.append(",\"license\":").append(licenseObj(r.license));
        return sb.append('}').toString();
    }

    private String licenseObj(LicenseResponse l) {
        return "{"
            + "\"valid\":" + l.valid + ","
            + "\"reason\":\"" + jsonEsc(l.reason) + "\","
            + "\"product\":\"" + jsonEsc(l.product) + "\","
            + "\"licenseKey\":\"" + jsonEsc(l.licenseKey) + "\","
            + "\"hwid\":\"" + jsonEsc(l.hwid) + "\","
            + "\"expiry\":" + l.expiry + ","
            + "\"uid\":" + l.uid + ","
            + "\"username\":\"" + jsonEsc(l.username) + "\","
            + "\"email\":\"" + jsonEsc(l.email) + "\","
            + "\"nonce\":\"" + jsonEsc(l.nonce) + "\","
            + "\"issuedAt\":" + l.issuedAt + ","
            + "\"signature\":\"" + jsonEsc(l.signature) + "\""
            + "}";
    }

    // ---- ban management (super-admin) ------------------------------------

    private void handleBan(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (!requireAdmin(ex)) return;
        Map<String, String> f = Form.decode(readBody(ex));
        String btype = f.getOrDefault("type", "").toLowerCase();
        String value = f.getOrDefault("value", "");
        if (value.isEmpty() || !(btype.equals("user") || btype.equals("hwid") || btype.equals("ip"))) {
            send(ex, 400, "type must be user|hwid|ip and value required"); return;
        }
        blacklist.ban(btype, value, f.getOrDefault("reason", ""));
        sendJson(ex, 200, "{\"ok\":true,\"type\":\"" + jsonEsc(btype) + "\",\"value\":\"" + jsonEsc(value) + "\"}");
    }

    private void handleUnban(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (!requireAdmin(ex)) return;
        Map<String, String> f = Form.decode(readBody(ex));
        blacklist.unban(f.getOrDefault("type", ""), f.getOrDefault("value", ""));
        sendJson(ex, 200, "{\"ok\":true}");
    }

    private void handleBans(HttpExchange ex) throws IOException {
        if (preflight(ex)) return;
        if (!requireAdmin(ex)) return;
        StringBuilder sb = new StringBuilder("[");
        List<String[]> bans = blacklist.list();
        for (int i = 0; i < bans.size(); i++) {
            String[] b = bans.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"type\":\"").append(jsonEsc(b[0]))
              .append("\",\"value\":\"").append(jsonEsc(b[1]))
              .append("\",\"reason\":\"").append(jsonEsc(b[2])).append("\"}");
        }
        sendJson(ex, 200, sb.append(']').toString());
    }

    private static String clientIp(HttpExchange ex) {
        try {
            java.net.InetSocketAddress a = ex.getRemoteAddress();
            return a == null ? "" : a.getAddress().getHostAddress();
        } catch (Exception e) { return ""; }
    }

    // ---- entry point ------------------------------------------------------

    public static void main(String[] args) throws Exception {
        int port          = intEnv("LICENSE_PORT", 8080);
        Path privateFile  = Paths.get(env("LICENSE_PRIVATE_KEY_FILE", "privatekey.txt"));
        Path webDir       = Paths.get(env("LICENSE_WEB_DIR", "web"));
        Path downloadsDir = Paths.get(env("LICENSE_DOWNLOADS_DIR", "downloads"));
        Path dbFile       = Paths.get(env("LICENSE_DB", "data/license.db"));
        String adminToken = env("LICENSE_ADMIN_TOKEN", "");

        if (adminToken.isEmpty()) {
            adminToken = Crypto.newNonce() + Crypto.newNonce();
            System.out.println("[!] LICENSE_ADMIN_TOKEN not set. Generated one for this run:");
            System.out.println("    " + adminToken);
            System.out.println("    Set LICENSE_ADMIN_TOKEN in the environment to keep it stable.");
        }

        // Private key: prefer the LICENSE_PRIVATE_KEY env var (cloud secret), else the file.
        String privB64 = env("LICENSE_PRIVATE_KEY", "");
        if (privB64.isEmpty()) {
            if (!Files.exists(privateFile)) {
                System.err.println("No private key. Set LICENSE_PRIVATE_KEY (base64) or provide " + privateFile);
                System.err.println("Generate one:  java -cp \"out;lib/*\" dev.license.KeyGen");
                System.exit(1);
            }
            privB64 = Files.readString(privateFile).trim();
        }
        PrivateKey priv = Crypto.privateKeyFromBase64(privB64);
        Db db = new Db(dbFile);
        LicenseStore store = new LicenseStore(db);
        LicenseAuthority authority = new LicenseAuthority(store, priv);
        ResellerStore resellers = new ResellerStore(db);
        Files.createDirectories(downloadsDir);
        UserStore users = new UserStore(db);
        Blacklist blacklist = new Blacklist(db);
        UserAuthority userAuthority = new UserAuthority(users, store, authority, blacklist);

        LicenseServer server = new LicenseServer(port, authority, store, adminToken, webDir, resellers, downloadsDir)
                .withAccounts(userAuthority, blacklist);

        // Auto-injection of the license client into uploaded Fabric jars (needs a JDK + public key).
        Path publicKeyFile = Paths.get(env("LICENSE_PUBLIC_KEY_FILE", "publickey.txt"));
        String publicKeyB64 = env("LICENSE_PUBLIC_KEY", "");
        if (publicKeyB64.isEmpty() && Files.exists(publicKeyFile)) publicKeyB64 = Files.readString(publicKeyFile).trim();
        String publicUrl = env("LICENSE_PUBLIC_URL", "http://localhost:" + port);
        boolean injectOn = false;
        if (JarInjector.compilerAvailable() && !publicKeyB64.isEmpty()) {
            Path clientSrc = Paths.get(env("LICENSE_CLIENT_SRC", "src/dev/license"));
            if (Files.isDirectory(clientSrc)) {
                server.withInjector(new JarInjector(clientSrc), publicKeyB64, publicUrl);
                injectOn = true;
            }
        }

        int bound = server.start();
        System.out.println("License API  : http://localhost:" + bound + "/api/validate");
        System.out.println("Injection    : " + (injectOn ? "ON (callback " + publicUrl + ")" : "OFF (need JDK + publickey.txt + client src)"));
        System.out.println("Auth API     : http://localhost:" + bound + "/api/auth  (init/register/login/license)");
        System.out.println("Reseller API : http://localhost:" + bound + "/api/reseller/download");
        if (Files.isDirectory(webDir)) {
            System.out.println("Admin panel  : http://localhost:" + bound + "/");
            System.out.println("Reseller panel: http://localhost:" + bound + "/reseller.html");
        } else {
            System.out.println("(no web dir at " + webDir.toAbsolutePath() + " - dashboard disabled)");
        }
        System.out.println("Database     : " + dbFile.toAbsolutePath());
        System.out.println("Downloads    : " + downloadsDir.toAbsolutePath());
    }

    private static String env(String k, String def) { String v = System.getenv(k); return v == null || v.isEmpty() ? def : v; }
    private static int intEnv(String k, int def)     { try { return Integer.parseInt(env(k, Integer.toString(def))); } catch (Exception e) { return def; } }
}
