package dev.license;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The server's signed answer. The {@link #signature} covers exactly the string
 * produced by {@link #canonical()} - the client rebuilds that string from these
 * fields and verifies it against the embedded public key.
 */
public final class LicenseResponse {

    public boolean valid;
    public String reason = "";
    public String product = "";
    public String licenseKey = "";
    public String hwid = "";
    public long expiry;      // epoch millis, 0 = perpetual
    public int uid;
    public String username = "";
    public String email = "";
    public String nonce = "";
    public long issuedAt;    // server clock, epoch millis
    public String signature = "";

    public String canonical() {
        return Canonical.message(product, licenseKey, hwid, valid, reason,
                expiry, uid, username, email, nonce, issuedAt);
    }

    public Map<String, String> toForm() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("valid", Boolean.toString(valid));
        m.put("reason", reason);
        m.put("product", product);
        m.put("licenseKey", licenseKey);
        m.put("hwid", hwid);
        m.put("expiry", Long.toString(expiry));
        m.put("uid", Integer.toString(uid));
        m.put("username", username);
        m.put("email", email);
        m.put("nonce", nonce);
        m.put("issuedAt", Long.toString(issuedAt));
        m.put("signature", signature);
        return m;
    }

    public static LicenseResponse fromForm(Map<String, String> f) {
        LicenseResponse r = new LicenseResponse();
        r.valid = "true".equalsIgnoreCase(get(f, "valid"));
        r.reason = get(f, "reason");
        r.product = get(f, "product");
        r.licenseKey = get(f, "licenseKey");
        r.hwid = get(f, "hwid");
        r.expiry = parseLong(get(f, "expiry"));
        r.uid = (int) parseLong(get(f, "uid"));
        r.username = get(f, "username");
        r.email = get(f, "email");
        r.nonce = get(f, "nonce");
        r.issuedAt = parseLong(get(f, "issuedAt"));
        r.signature = get(f, "signature");
        return r;
    }

    private static String get(Map<String, String> f, String k) {
        String v = f.get(k);
        return v == null ? "" : v;
    }

    private static long parseLong(String s) {
        try { return Long.parseLong(s.trim()); } catch (Exception e) { return 0L; }
    }
}
