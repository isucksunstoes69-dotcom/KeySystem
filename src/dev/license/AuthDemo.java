package dev.license;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

/**
 * End-to-end test of the KeyAuth-style accounts + ban system, driven through
 * the real HTTP server via the {@link KeyAuthClient} SDK.
 *
 *   java -cp out dev.license.AuthDemo
 */
public final class AuthDemo {

    private static int passed = 0, failed = 0;
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    public static void main(String[] args) throws Exception {
        KeyPair kp = Crypto.generateKeyPair();
        String pub = Crypto.encodeKey(kp.getPublic());

        Path tmp = Files.createTempDirectory("auth");
        Db db = new Db(tmp.resolve("license.db"));
        LicenseStore store = new LicenseStore(db);
        LicenseAuthority authority = new LicenseAuthority(store, kp.getPrivate());
        UserStore users = new UserStore(db);
        Blacklist bl = new Blacklist(db);
        UserAuthority ua = new UserAuthority(users, store, authority, bl);
        String adminToken = "admintok";

        LicenseServer server = new LicenseServer(0, authority, store, adminToken).withAccounts(ua, bl);
        int port = server.start();
        String base = "http://127.0.0.1:" + port;
        String HW = "HWID-DEMO-1";

        try {
            String keyA = store.create("DemoMod", "Owner A", "a@x.com", 0, "");
            String keyB = store.create("DemoMod", "Owner B", "b@x.com", 0, "");
            String keyC = store.create("DemoMod", "Owner C", "c@x.com", 0, "");

            KeyAuthClient auth = new KeyAuthClient(base, pub, 300_000L, HW);

            KeyAuthClient.AuthResult ini = auth.init("DemoMod", "1.0");
            check("init ok + sessionid issued", ini.ok && !auth.sessionId().isEmpty());

            KeyAuthClient.AuthResult lic = auth.license(keyA);
            check("license(key) ok with verified session", lic.ok && lic.session != null && "Owner A".equals(lic.session.getUsername()));

            KeyAuthClient.AuthResult reg = auth.register("bob", "secret", keyB);
            check("register ok", reg.ok && "bob".equals(reg.username) && reg.session != null);

            KeyAuthClient.AuthResult dup = auth.register("bob", "secret", keyC);
            check("duplicate username rejected", !dup.ok && "USERNAME_TAKEN".equals(dup.status));

            KeyAuthClient.AuthResult used = auth.register("charlie", "secret", keyB);
            check("already-registered key rejected", !used.ok && "KEY_ALREADY_USED".equals(used.status));

            KeyAuthClient.AuthResult weak = auth.register("dave", "xx", keyC);
            check("weak password rejected", !weak.ok && "WEAK_PASSWORD".equals(weak.status));

            KeyAuthClient.AuthResult log = auth.login("bob", "secret");
            check("login ok with verified session", log.ok && log.session != null);

            KeyAuthClient.AuthResult badpw = auth.login("bob", "nope");
            check("wrong password rejected", !badpw.ok && "INVALID_CREDENTIALS".equals(badpw.status));

            adminBan(base, adminToken, "user", "bob", "cheating");
            KeyAuthClient.AuthResult banned = auth.login("bob", "secret");
            check("banned user refused", !banned.ok && "BANNED".equals(banned.status));

            adminUnban(base, adminToken, "user", "bob");
            check("unban restores login", auth.login("bob", "secret").ok);

            adminBan(base, adminToken, "hwid", HW, "hwid ban");
            KeyAuthClient.AuthResult hwidBan = auth.license(keyA);
            check("banned hwid refused", !hwidBan.ok && "BANNED".equals(hwidBan.status));
            adminUnban(base, adminToken, "hwid", HW);
            check("license ok after hwid unban", auth.license(keyA).ok);

            String bans = get(base + "/api/admin/bans", adminToken);
            check("bans list reads back as json", bans.trim().startsWith("["));

        } finally {
            server.stop();
        }

        System.out.println();
        System.out.println("==== " + passed + " passed, " + failed + " failed ====");
        System.exit(failed == 0 ? 0 : 1);
    }

    private static void check(String name, boolean ok) {
        if (ok) { passed++; System.out.println("[PASS] " + name); }
        else    { failed++; System.out.println("[FAIL] " + name); }
    }

    private static void adminBan(String base, String tok, String type, String val, String reason) throws Exception {
        post(base + "/api/admin/ban", tok, "type=" + type + "&value=" + enc(val) + "&reason=" + enc(reason));
    }
    private static void adminUnban(String base, String tok, String type, String val) throws Exception {
        post(base + "/api/admin/unban", tok, "type=" + type + "&value=" + enc(val));
    }
    private static String post(String url, String tok, String body) throws Exception {
        HttpRequest r = HttpRequest.newBuilder(URI.create(url))
                .header("X-Admin-Token", tok).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return HTTP.send(r, HttpResponse.BodyHandlers.ofString()).body();
    }
    private static String get(String url, String tok) throws Exception {
        HttpRequest r = HttpRequest.newBuilder(URI.create(url)).header("X-Admin-Token", tok).GET().build();
        return HTTP.send(r, HttpResponse.BodyHandlers.ofString()).body();
    }
    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
}
