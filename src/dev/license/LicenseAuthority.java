package dev.license;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.List;

/**
 * Server-side validation + signing. This is the single source of truth for
 * "is this license valid" - both the HTTP server and the offline demo call it,
 * so they can never drift apart.
 */
public final class LicenseAuthority {

    private final LicenseStore store;
    private final PrivateKey privateKey;

    public LicenseAuthority(LicenseStore store, PrivateKey privateKey) {
        this.store = store;
        this.privateKey = privateKey;
    }

    /** Reasons are stable strings so the client can branch on them if it wants. */
    public LicenseResponse validate(LicenseRequest req) {
        LicenseResponse r = new LicenseResponse();
        // Echo the request identifiers so the signature binds the answer to
        // exactly this key + hwid + nonce.
        r.product = req.product;
        r.licenseKey = req.licenseKey;
        r.hwid = req.hwid;
        r.nonce = req.nonce;
        r.issuedAt = System.currentTimeMillis();
        r.valid = false;
        r.expiry = 0;

        String key = req.licenseKey;
        try {
            if (!store.exists(key)) {
                r.reason = "UNKNOWN_KEY";
            } else if (store.revoked(key)) {
                r.reason = "REVOKED";
            } else if (!store.product(key).equals(req.product)) {
                r.reason = "PRODUCT_MISMATCH";
            } else if (isExpired(store.expiry(key))) {
                r.reason = "EXPIRED";
                r.expiry = store.expiry(key);
            } else if (!hwidOk(key, req.hwid)) {
                r.reason = "HWID_MISMATCH";
            } else {
                r.valid = true;
                r.reason = "OK";
                r.uid = store.uid(key);
                r.username = store.owner(key);
                r.email = store.email(key);
                r.expiry = store.expiry(key);
            }
        } catch (IOException e) {
            r.valid = false;
            r.reason = "SERVER_ERROR";
        }

        sign(r);
        return r;
    }

    private boolean isExpired(long expiry) {
        return expiry != 0 && System.currentTimeMillis() >= expiry;
    }

    /**
     * HWID policy:
     *   - if a manual allowlist exists, hwid must be in it;
     *   - else auto-bind: the first hwid to activate is stored and locked in;
     *   - a bound license only accepts its bound hwid.
     */
    private boolean hwidOk(String key, String hwid) throws IOException {
        if (hwid == null || hwid.isEmpty()) return false;

        List<String> allow = store.allowedHwids(key);
        if (!allow.isEmpty()) {
            return allow.contains(hwid);
        }
        String bound = store.boundHwid(key);
        if (bound == null || bound.isEmpty()) {
            store.bindHwid(key, hwid); // auto-bind on first use
            return true;
        }
        return bound.equals(hwid);
    }

    private void sign(LicenseResponse r) {
        try {
            r.signature = Crypto.sign(privateKey, r.canonical());
        } catch (GeneralSecurityException e) {
            // Should never happen with a valid key; fail closed with empty sig.
            r.signature = "";
        }
    }
}
