package dev.license;

/**
 * Builds the exact byte string that gets Ed25519-signed by the server and
 * re-verified by the client. Field order and separators are FIXED - if you
 * change anything here you must change it on both sides or every signature
 * will fail.
 *
 * Values are escaped so a field value can never inject the '|' separator.
 */
public final class Canonical {

    private Canonical() {}

    public static final String VERSION = "v1";

    public static String message(String product, String licenseKey, String hwid,
                                 boolean valid, String reason, long expiry,
                                 int uid, String username, String email,
                                 String nonce, long issuedAt) {
        return String.join("|",
                VERSION,
                esc(product),
                esc(licenseKey),
                esc(hwid),
                Boolean.toString(valid),
                esc(reason),
                Long.toString(expiry),
                Integer.toString(uid),
                esc(username),
                esc(email),
                esc(nonce),
                Long.toString(issuedAt));
    }

    /** Escape backslash and the '|' delimiter so values cannot forge fields. */
    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("|", "\\p");
    }
}
