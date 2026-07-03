package dev.license;

import java.util.LinkedHashMap;
import java.util.Map;

/** What the mod sends to POST /api/validate. */
public final class LicenseRequest {

    public final String product;
    public final String licenseKey;
    public final String hwid;
    public final String nonce;
    public final String modVersion; // informational only

    public LicenseRequest(String product, String licenseKey, String hwid, String nonce, String modVersion) {
        this.product = nn(product);
        this.licenseKey = nn(licenseKey);
        this.hwid = nn(hwid);
        this.nonce = nn(nonce);
        this.modVersion = nn(modVersion);
    }

    public Map<String, String> toForm() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("product", product);
        m.put("licenseKey", licenseKey);
        m.put("hwid", hwid);
        m.put("nonce", nonce);
        m.put("modVersion", modVersion);
        return m;
    }

    public static LicenseRequest fromForm(Map<String, String> f) {
        return new LicenseRequest(
                f.get("product"), f.get("licenseKey"), f.get("hwid"),
                f.get("nonce"), f.get("modVersion"));
    }

    private static String nn(String s) { return s == null ? "" : s; }
}
