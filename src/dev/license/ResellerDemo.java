package dev.license;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * End-to-end test of the multi-tenant reseller / download API. Spins up the real
 * server, creates a reseller, uploads a jar, downloads a keyed jar, and checks
 * the baked-in key actually validates - plus idempotency, tenant isolation, and
 * the reset cooldown.
 *
 *   java -cp out dev.license.ResellerDemo
 */
public final class ResellerDemo {

    private static int passed = 0, failed = 0;
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    public static void main(String[] args) throws Exception {
        KeyPair kp = Crypto.generateKeyPair();
        String pub = Crypto.encodeKey(kp.getPublic());

        Path tmp = Files.createTempDirectory("resell");
        Db db = new Db(tmp.resolve("license.db"));
        LicenseStore store = new LicenseStore(db);
        LicenseAuthority auth = new LicenseAuthority(store, kp.getPrivate());
        ResellerStore resellers = new ResellerStore(db);
        Path downloads = tmp.resolve("downloads");
        Files.createDirectories(downloads);
        String adminToken = "admintok";

        LicenseServer server = new LicenseServer(0, auth, store, adminToken, null, resellers, downloads);
        int port = server.start();
        String base = "http://127.0.0.1:" + port;

        try {
            // 1. super-admin creates a reseller
            String created = postForm(base + "/api/admin/reseller/create", "X-Admin-Token", adminToken, "name=Cheat Co");
            String rid = jsonField(created, "id");
            String apiKey = jsonField(created, "apiKey");
            check("reseller created (id + apiKey)", rid.startsWith("rs_") && apiKey.startsWith("rk_"));

            // 2. reseller uploads a base jar for product "TestMod"
            byte[] baseJar = makeJar();
            String up = postBytes(base + "/api/reseller/upload?product=TestMod", "X-Api-Key", apiKey, baseJar);
            check("jar uploaded", up.contains("\"ok\":true"));

            // 3. download for customer alice -> keyed jar
            HttpResponse<byte[]> d1 = downloadJar(base, apiKey, "TestMod", "alice@x.com");
            String hdrKey1 = d1.headers().firstValue("X-License-Key").orElse("");
            String bakedKey1 = readEntry(d1.body(), JarStamper.LICENSE_ENTRY);
            check("download returned a jar with license.key", bakedKey1 != null && !bakedKey1.isEmpty());
            check("X-License-Key header matches baked key", hdrKey1.equals(bakedKey1));
            check("base jar entries preserved in stamped jar", readEntry(d1.body(), "com/example/Mod.class") != null);

            // 4. the baked key actually validates (as the mod would)
            AuthClient client = new AuthClient(base, pub, "TestMod", "1.0", 300_000L);
            LicenseResult r = client.validate(bakedKey1, "HWID-ALICE");
            check("baked key validates as a real license", r.ok && "OK".equals(r.reason));

            // 5. idempotent: same customer re-download -> same key
            HttpResponse<byte[]> d1b = downloadJar(base, apiKey, "TestMod", "alice@x.com");
            String bakedKey1b = readEntry(d1b.body(), JarStamper.LICENSE_ENTRY);
            check("same customer re-download keeps same key", bakedKey1.equals(bakedKey1b));

            // 6. different customer -> different key
            HttpResponse<byte[]> d2 = downloadJar(base, apiKey, "TestMod", "bob@x.com");
            String bakedKey2 = readEntry(d2.body(), JarStamper.LICENSE_ENTRY);
            check("different customer gets a different key", bakedKey2 != null && !bakedKey2.equals(bakedKey1));

            // 7. reseller sees only their own licenses (2 of them)
            String mine = getWith(base + "/api/reseller/licenses", "X-Api-Key", apiKey);
            int count = mine.split("\"key\":").length - 1;
            check("reseller licenses list shows 2", count == 2);

            // 8. wrong api key -> 401
            int code = statusGet(base + "/api/reseller/licenses", "X-Api-Key", "rk_wrong");
            check("invalid api key rejected (401)", code == 401);

            // 9. missing product jar -> 404
            int code2 = statusDownload(base, apiKey, "NoSuchMod", "alice@x.com");
            check("download of unknown product -> 404", code2 == 404);

            // 10. reset cooldown: first ok, second within 7 days -> 429
            String reset1 = postForm(base + "/api/reseller/reset", "X-Api-Key", apiKey, "product=TestMod&customer=alice@x.com");
            check("first HWID reset ok", reset1.contains("\"ok\":true"));
            int resetCode2 = statusPostForm(base + "/api/reseller/reset", "X-Api-Key", apiKey, "product=TestMod&customer=alice@x.com");
            check("second reset within 7 days -> 429 cooldown", resetCode2 == 429);

            // 11. super-admin sees all licenses across tenants (2)
            String all = getWith(base + "/api/admin/list?format=json", "X-Admin-Token", adminToken);
            int allCount = all.split("\"key\":").length - 1;
            check("admin sees all tenant licenses (2)", allCount == 2);

        } finally {
            server.stop();
        }

        System.out.println();
        System.out.println("==== " + passed + " passed, " + failed + " failed ====");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ---- helpers ----------------------------------------------------------

    private static void check(String name, boolean ok) {
        if (ok) { passed++; System.out.println("[PASS] " + name); }
        else    { failed++; System.out.println("[FAIL] " + name); }
    }

    private static byte[] makeJar() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            z.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
            z.write("Manifest-Version: 1.0\n".getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
            z.putNextEntry(new ZipEntry("com/example/Mod.class"));
            z.write(new byte[]{ (byte)0xCA, (byte)0xFE, (byte)0xBA, (byte)0xBE });
            z.closeEntry();
        }
        return bos.toByteArray();
    }

    private static String readEntry(byte[] jar, String name) throws Exception {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(jar))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.getName().equals(name)) return new String(zis.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static HttpResponse<byte[]> downloadJar(String base, String apiKey, String product, String customer) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(base + "/api/reseller/download?product=" + enc(product) + "&customer=" + enc(customer)))
                .header("X-Api-Key", apiKey).POST(HttpRequest.BodyPublishers.noBody()).build();
        return HTTP.send(req, HttpResponse.BodyHandlers.ofByteArray());
    }

    private static int statusDownload(String base, String apiKey, String product, String customer) throws Exception {
        return downloadJar(base, apiKey, product, customer).statusCode();
    }

    private static String postForm(String url, String hName, String hVal, String body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header(hName, hVal).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return HTTP.send(req, HttpResponse.BodyHandlers.ofString()).body();
    }

    private static int statusPostForm(String url, String hName, String hVal, String body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header(hName, hVal).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return HTTP.send(req, HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    private static String postBytes(String url, String hName, String hVal, byte[] body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header(hName, hVal).POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
        return HTTP.send(req, HttpResponse.BodyHandlers.ofString()).body();
    }

    private static String getWith(String url, String hName, String hVal) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).header(hName, hVal).GET().build();
        return HTTP.send(req, HttpResponse.BodyHandlers.ofString()).body();
    }

    private static int statusGet(String url, String hName, String hVal) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).header(hName, hVal).GET().build();
        return HTTP.send(req, HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    private static String jsonField(String json, String field) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"(.*?)\"").matcher(json);
        return m.find() ? m.group(1) : "";
    }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
}
