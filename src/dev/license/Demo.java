package dev.license;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * End-to-end self test. Spins up the real HTTP server on localhost, runs a real
 * client through it, and asserts the security properties. Run:
 *
 *   javac -d out src/dev/license/*.java
 *   java  -cp out dev.license.Demo
 *
 * Exit code 0 = all tests passed, 1 = a test failed.
 */
public final class Demo {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        final String PRODUCT = "DemoMod";
        final long FRESHNESS = 300_000L; // 5 min

        // --- key pair (server keeps private, mod embeds public) ---
        KeyPair kp = Crypto.generateKeyPair();
        String publicKeyB64 = Crypto.encodeKey(kp.getPublic());
        PrivateKey priv = kp.getPrivate();

        // --- server + store in a temp dir ---
        Path tmp = Files.createTempDirectory("mclicense");
        Db db = new Db(tmp.resolve("license.db"));
        LicenseStore store = new LicenseStore(db);
        LicenseAuthority authority = new LicenseAuthority(store, priv);
        String adminToken = "test-admin-token";
        LicenseServer server = new LicenseServer(0, authority, store, adminToken);
        int port = server.start();
        String baseUrl = "http://127.0.0.1:" + port;

        AuthClient client = new AuthClient(baseUrl, publicKeyB64, PRODUCT, "1.0.0", FRESHNESS);
        String hwidA = "HWID-AAAA-1111";
        String hwidB = "HWID-BBBB-2222";

        try {
            String key = store.create(PRODUCT, "Alice Buyer", "alice@example.com", 0, "");

            // 1. First activation auto-binds to hwidA and returns a session.
            LicenseResult r1 = client.validate(key, hwidA);
            check("valid activation (auto-bind)", r1.ok && "OK".equals(r1.reason));
            check("session uid populated", r1.session != null && r1.session.getUid() > 0);
            check("session username populated", r1.session != null && "Alice Buyer".equals(r1.session.getUsername()));

            // 2. Same key, different machine -> rejected (bound to hwidA).
            LicenseResult r2 = client.validate(key, hwidB);
            check("hwid mismatch rejected", !r2.ok && "HWID_MISMATCH".equals(r2.reason));

            // 3. Unknown key -> rejected.
            LicenseResult r3 = client.validate("ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ", hwidA);
            check("unknown key rejected", !r3.ok && "UNKNOWN_KEY".equals(r3.reason));

            // 4. Tampered signature -> rejected.
            LicenseRequest reqT = new LicenseRequest(PRODUCT, key, hwidA, Crypto.newNonce(), "1.0.0");
            LicenseResponse respT = client.fetch(reqT);
            check("pre-tamper response verifies", client.verify(reqT, respT).ok);
            respT.signature = flipSignature(respT.signature);
            check("tampered signature rejected", "BAD_SIGNATURE".equals(client.verify(reqT, respT).reason));

            // 5. Replay for a different nonce -> rejected (echo check).
            LicenseRequest reqN = new LicenseRequest(PRODUCT, key, hwidA, Crypto.newNonce(), "1.0.0");
            LicenseResponse respN = client.fetch(reqN);
            LicenseRequest replay = new LicenseRequest(PRODUCT, key, hwidA, Crypto.newNonce(), "1.0.0");
            check("replay with new nonce rejected", "ECHO_NONCE".equals(client.verify(replay, respN).reason));

            // 6. Fake license server (wrong signing key) -> rejected.
            KeyPair evil = Crypto.generateKeyPair();
            LicenseResponse forged = new LicenseResponse();
            forged.valid = true; forged.reason = "OK"; forged.product = PRODUCT;
            forged.licenseKey = key; forged.hwid = hwidA; forged.nonce = "deadbeef";
            forged.uid = 1; forged.issuedAt = System.currentTimeMillis();
            forged.signature = Crypto.sign(evil.getPrivate(), forged.canonical());
            LicenseRequest reqF = new LicenseRequest(PRODUCT, key, hwidA, "deadbeef", "1.0.0");
            check("forged (wrong-key) response rejected", "BAD_SIGNATURE".equals(client.verify(reqF, forged).reason));

            // 7. Stale response (old issuedAt) -> rejected.
            LicenseResponse stale = new LicenseResponse();
            stale.valid = true; stale.reason = "OK"; stale.product = PRODUCT;
            stale.licenseKey = key; stale.hwid = hwidA; stale.nonce = "n7";
            stale.uid = 1; stale.issuedAt = System.currentTimeMillis() - (FRESHNESS + 60_000L);
            stale.signature = Crypto.sign(priv, stale.canonical());
            LicenseRequest req7 = new LicenseRequest(PRODUCT, key, hwidA, "n7", "1.0.0");
            check("stale response rejected", "STALE_RESPONSE".equals(client.verify(req7, stale).reason));

            // 8. Expired (server-side) -> rejected.
            store.setExpiry(key, System.currentTimeMillis() - 1000L);
            LicenseResult r8 = client.validate(key, hwidA);
            check("expired license rejected", !r8.ok && "EXPIRED".equals(r8.reason));
            store.setExpiry(key, 0L); // restore

            // 9. Client-side expiry defence (server says valid but expiry passed).
            LicenseResponse exp = new LicenseResponse();
            exp.valid = true; exp.reason = "OK"; exp.product = PRODUCT;
            exp.licenseKey = key; exp.hwid = hwidA; exp.nonce = "n9";
            exp.uid = 1; exp.issuedAt = System.currentTimeMillis();
            exp.expiry = System.currentTimeMillis() - 1000L;
            exp.signature = Crypto.sign(priv, exp.canonical());
            LicenseRequest req9 = new LicenseRequest(PRODUCT, key, hwidA, "n9", "1.0.0");
            check("client-side expiry enforced", "EXPIRED".equals(client.verify(req9, exp).reason));

            // 10. Revoked -> rejected.
            store.revoke(key);
            LicenseResult r10 = client.validate(key, hwidA);
            check("revoked license rejected", !r10.ok && "REVOKED".equals(r10.reason));

            // 11. Wrong product for a real key -> rejected.
            String key2 = store.create("OtherMod", "Bob", "bob@example.com", 0, "");
            LicenseResult r11 = client.validate(key2, hwidA); // client product is DemoMod
            check("product mismatch rejected", !r11.ok && "PRODUCT_MISMATCH".equals(r11.reason));

            // 12. Network failure -> fail closed with NETWORK_ERROR.
            AuthClient dead = new AuthClient("http://127.0.0.1:1", publicKeyB64, PRODUCT, "1.0.0", FRESHNESS);
            LicenseResult r12 = dead.validate(key, hwidA);
            check("network error handled (fail closed)", !r12.ok && "NETWORK_ERROR".equals(r12.reason));

            // 13. Protection façade end-to-end on a fresh key.
            String key3 = store.create(PRODUCT, "Carol", "carol@example.com", 0, "");
            Protection.Config cfg = new Protection.Config();
            cfg.baseUrl = baseUrl; cfg.publicKeyB64 = publicKeyB64; cfg.product = PRODUCT;
            cfg.modVersion = "1.0.0"; cfg.licenseKey = key3; cfg.hwid = hwidA;
            LicenseResult r13 = Protection.enforce(cfg);
            check("Protection.enforce grants a valid license", r13.ok && Protection.isLicensed()
                    && Protection.getSession() != null && "Carol".equals(Protection.getSession().getUsername()));

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

    /** Decode base64, flip one byte, re-encode -> valid base64 but wrong signature. */
    private static String flipSignature(String b64) {
        byte[] sig = Base64.getDecoder().decode(b64);
        sig[0] ^= 0x01;
        return Base64.getEncoder().encodeToString(sig);
    }
}
