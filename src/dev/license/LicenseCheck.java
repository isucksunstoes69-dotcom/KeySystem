package dev.license;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Manual test client - pretends to be the mod and validates a real license key
 * against a running server. This is the end-to-end check between "I created a
 * key in the dashboard" and "a client actually accepts it".
 *
 *   java -cp out dev.license.LicenseCheck <baseUrl> <publicKeyFileOrB64> <product> <licenseKey>
 *
 * Example:
 *   java -cp out dev.license.LicenseCheck http://localhost:8080 server/publickey.txt MyMod ABCDE-FGHIJ-KLMNO-PQRST
 *
 * Prints the HWID it used and the verdict. Exit 0 = valid, 1 = invalid.
 */
public final class LicenseCheck {

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("usage: LicenseCheck <baseUrl> <publicKeyFileOrB64> <product> <licenseKey>");
            System.exit(2);
        }
        String baseUrl = args[0];
        String pub = args[1];
        String product = args[2];
        String key = args[3];

        // Accept either a path to publickey.txt or the base64 string itself.
        Path p = Paths.get(pub);
        if (Files.exists(p)) pub = Files.readString(p).trim();

        String hwid = HWIDGrabber.getHWID();
        System.out.println("Base URL : " + baseUrl);
        System.out.println("Product  : " + product);
        System.out.println("HWID     : " + hwid);
        System.out.println("Checking ...");

        AuthClient client = new AuthClient(baseUrl, pub, product, "test", 300_000L);
        LicenseResult r = client.validate(key, hwid);

        System.out.println();
        if (r.ok) {
            System.out.println("RESULT   : VALID");
            System.out.println("Licensed to " + r.session.getUsername()
                    + " (uid " + r.session.getUid() + ", "
                    + (r.session.isPerpetual() ? "perpetual" : "expires " + new java.util.Date(r.session.getExpiry())) + ")");
        } else {
            System.out.println("RESULT   : INVALID  (" + r.reason + ")");
        }
        System.exit(r.ok ? 0 : 1);
    }
}
