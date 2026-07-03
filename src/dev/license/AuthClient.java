package dev.license;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Map;

/**
 * Client-side license checker. Pure JDK (java.net.http + Ed25519), so it works
 * unchanged inside a Fabric mod, a Bukkit plugin, or a plain test harness.
 *
 * Trust model: the ONLY thing baked into the client is {@code publicKeyB64}.
 * Every response is verified against it. Redirecting the license domain to a
 * fake server does not help an attacker because they cannot produce a valid
 * signature over the (hwid, nonce)-bound canonical message.
 */
public final class AuthClient {

    private final String baseUrl;
    private final PublicKey publicKey;
    private final String product;
    private final String modVersion;
    private final long freshnessMillis;
    private final HttpClient http;

    public AuthClient(String baseUrl, String publicKeyB64, String product, String modVersion, long freshnessMillis) {
        try {
            this.baseUrl = baseUrl.replaceAll("/+$", "");
            this.publicKey = Crypto.publicKeyFromBase64(publicKeyB64);
            this.product = product;
            this.modVersion = modVersion == null ? "" : modVersion;
            this.freshnessMillis = freshnessMillis;
            this.http = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(8))
                    .followRedirects(HttpClient.Redirect.NEVER) // do not silently follow to a spoof host
                    .build();
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad public key: " + e.getMessage(), e);
        }
    }

    /** Convenience: build request, call server, verify. */
    public LicenseResult validate(String licenseKey, String hwid) {
        LicenseRequest req = new LicenseRequest(product, licenseKey, hwid, Crypto.newNonce(), modVersion);
        LicenseResponse resp;
        try {
            resp = fetch(req);
        } catch (Exception e) {
            return LicenseResult.invalid("NETWORK_ERROR");
        }
        return verify(req, resp);
    }

    /** Raw network call, no verification (exposed so callers/tests can inspect). */
    public LicenseResponse fetch(LicenseRequest req) throws Exception {
        String body = Form.encode(req.toForm());
        HttpRequest httpReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/validate"))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> httpResp = http.send(httpReq, HttpResponse.BodyHandlers.ofString());
        if (httpResp.statusCode() != 200) {
            throw new IllegalStateException("HTTP " + httpResp.statusCode());
        }
        return LicenseResponse.fromForm(Form.decode(httpResp.body()));
    }

    /** All security checks. This is where a response is accepted or rejected. */
    public LicenseResult verify(LicenseRequest req, LicenseResponse resp) {
        // 1. The answer must be about exactly what we asked. This defeats
        //    replaying a captured "valid" response for a different key/hwid/nonce.
        if (!req.product.equals(resp.product))     return LicenseResult.invalid("ECHO_PRODUCT");
        if (!req.licenseKey.equals(resp.licenseKey))return LicenseResult.invalid("ECHO_KEY");
        if (!req.hwid.equals(resp.hwid))           return LicenseResult.invalid("ECHO_HWID");
        if (!req.nonce.equals(resp.nonce))         return LicenseResult.invalid("ECHO_NONCE");

        // 2. The signature must verify against our embedded public key.
        if (resp.signature == null || resp.signature.isEmpty()
                || !Crypto.verify(publicKey, resp.canonical(), resp.signature)) {
            return LicenseResult.invalid("BAD_SIGNATURE");
        }

        // 3. Freshness: bound replay window using the server clock.
        long skew = Math.abs(System.currentTimeMillis() - resp.issuedAt);
        if (skew > freshnessMillis) return LicenseResult.invalid("STALE_RESPONSE");

        // 4. The server's verdict.
        if (!resp.valid) return LicenseResult.invalid(resp.reason == null || resp.reason.isEmpty() ? "INVALID" : resp.reason);

        // 5. Expiry (defence in depth; the server already checked).
        if (resp.expiry != 0 && System.currentTimeMillis() >= resp.expiry) {
            return LicenseResult.invalid("EXPIRED");
        }

        Session session = new Session(resp.uid, resp.username, resp.email,
                resp.licenseKey, resp.hwid, resp.expiry);
        return LicenseResult.valid(session);
    }
}
