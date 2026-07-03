package dev.license;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * KeyAuth-style Java SDK. Wraps /api/auth with init / register / login /
 * license and STILL verifies the Ed25519-signed license inside every response,
 * so a spoofed server can't fake a login.
 *
 *   KeyAuthClient auth = new KeyAuthClient(baseUrl, PUBLIC_KEY, 300_000L);
 *   auth.init("MyMod", "1.0");
 *   KeyAuthClient.AuthResult r = auth.login("bob", "secret");   // or register / license
 *   if (r.ok) { ... r.session.getUsername() ... }
 */
public final class KeyAuthClient {

    private final String baseUrl;
    private final PublicKey publicKey;
    private final long freshnessMillis;
    private final String hwid;
    private final HttpClient http;
    private String sessionId = "";

    public KeyAuthClient(String baseUrl, String publicKeyB64, long freshnessMillis) {
        this(baseUrl, publicKeyB64, freshnessMillis, HWIDGrabber.getHWID());
    }

    /** hwid override (tests / custom fingerprints). */
    public KeyAuthClient(String baseUrl, String publicKeyB64, long freshnessMillis, String hwid) {
        try {
            this.baseUrl = baseUrl.replaceAll("/+$", "");
            this.publicKey = Crypto.publicKeyFromBase64(publicKeyB64);
            this.freshnessMillis = freshnessMillis;
            this.hwid = hwid;
            this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8))
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad public key: " + e.getMessage(), e);
        }
    }

    public String hwid() { return hwid; }
    public String sessionId() { return sessionId; }

    public static final class AuthResult {
        public boolean ok;
        public String status = "";
        public String message = "";
        public String username = "";
        public Session session; // non-null when a valid license was granted
    }

    public AuthResult init(String appName, String version) {
        Map<String, String> p = base("init");
        p.put("name", appName); p.put("ver", version);
        AuthResult r = call(p);
        if (r.ok && !sessionId.isEmpty()) { /* keep */ }
        return r;
    }

    public AuthResult license(String key) {
        Map<String, String> p = base("license");
        p.put("key", key);
        return call(p);
    }

    public AuthResult register(String username, String password, String key) {
        Map<String, String> p = base("register");
        p.put("username", username); p.put("pass", password); p.put("key", key);
        return call(p);
    }

    public AuthResult login(String username, String password) {
        Map<String, String> p = base("login");
        p.put("username", username); p.put("pass", password);
        return call(p);
    }

    // -----------------------------------------------------------------------

    private Map<String, String> base(String type) {
        Map<String, String> p = new LinkedHashMap<>();
        p.put("type", type);
        p.put("hwid", hwid);
        if (!sessionId.isEmpty()) p.put("sessionid", sessionId);
        return p;
    }

    private AuthResult call(Map<String, String> params) {
        AuthResult res = new AuthResult();
        String json;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/api/auth"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(Form.encode(params))).build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) { res.status = "HTTP_" + resp.statusCode(); res.message = "server error"; return res; }
            json = resp.body();
        } catch (Exception e) {
            res.status = "NETWORK_ERROR"; res.message = "cannot reach server"; return res;
        }

        boolean success = jbool(json, "success");
        res.status = nz(jstr(json, "status"));
        res.message = nz(jstr(json, "message"));
        res.username = nz(jstr(json, "username"));
        String sid = jstr(json, "sessionid");
        if (sid != null && !sid.isEmpty()) this.sessionId = sid;

        String lic = licenseObject(json);
        if (lic != null) {
            boolean valid = jbool(lic, "valid");
            String product = nz(jstr(lic, "product"));
            String licenseKey = nz(jstr(lic, "licenseKey"));
            String h = nz(jstr(lic, "hwid"));
            String reason = nz(jstr(lic, "reason"));
            String un = nz(jstr(lic, "username"));
            String em = nz(jstr(lic, "email"));
            String nonce = nz(jstr(lic, "nonce"));
            String sig = nz(jstr(lic, "signature"));
            long expiry = jlong(lic, "expiry");
            long issuedAt = jlong(lic, "issuedAt");
            int uid = (int) jlong(lic, "uid");

            String canonical = Canonical.message(product, licenseKey, h, valid, reason, expiry, uid, un, em, nonce, issuedAt);
            if (!Crypto.verify(publicKey, canonical, sig)) { res.ok = false; res.status = "BAD_SIGNATURE"; return res; }
            if (!hwid.equals(h)) { res.ok = false; res.status = "ECHO_HWID"; return res; }
            if (Math.abs(System.currentTimeMillis() - issuedAt) > freshnessMillis) { res.ok = false; res.status = "STALE_RESPONSE"; return res; }
            if (valid) res.session = new Session(uid, un, em, licenseKey, h, expiry);
            res.ok = success && valid;
            return res;
        }

        res.ok = success;
        return res;
    }

    // ---- tiny JSON helpers (our own flat shape) ---------------------------

    private static String licenseObject(String json) {
        Matcher m = Pattern.compile("\"license\"\\s*:\\s*(\\{[^}]*\\})").matcher(json);
        return m.find() ? m.group(1) : null;
    }
    private static String jstr(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"").matcher(json);
        return m.find() ? unescape(m.group(1)) : null;
    }
    private static boolean jbool(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(true|false)").matcher(json);
        return m.find() && m.group(1).equals("true");
    }
    private static long jlong(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : 0L;
    }
    private static String unescape(String s) {
        return s.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t");
    }
    private static String nz(String s) { return s == null ? "" : s; }
}
