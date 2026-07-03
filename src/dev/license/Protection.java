package dev.license;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * High-level façade the mod calls. Pure JDK - no Fabric imports - so it can be
 * unit-tested and reused on client, server, or proxy. The Fabric entrypoint is
 * a thin wrapper that just calls {@link #enforce(Config)} and reads the result.
 *
 * Enforcement is fail-closed: unless a signed, valid response comes back,
 * {@link #isLicensed()} stays false.
 */
public final class Protection {

    public static final class Config {
        public String baseUrl;
        public String publicKeyB64;
        public String product;
        public String modVersion = "";
        public String licenseKey;
        public String hwid;                    // null/empty -> auto-detect
        public long   freshnessMillis = 300_000L;
        public long   keepAliveMinutes = 0;    // 0 = no periodic re-check
        public Runnable onLicenseLost;         // called if a later keep-alive check fails
    }

    private static volatile boolean licensed = false;
    private static volatile Session session = null;
    private static volatile String lastReason = "NOT_CHECKED";
    private static ScheduledExecutorService keepAlive;

    private Protection() {}

    /** Perform the initial (blocking) license check. Safe to call once at startup. */
    public static synchronized LicenseResult enforce(Config c) {
        if (c == null || c.baseUrl == null || c.publicKeyB64 == null
                || c.product == null || c.licenseKey == null) {
            licensed = false; lastReason = "BAD_CONFIG"; session = null;
            return LicenseResult.invalid("BAD_CONFIG");
        }
        String hwid = (c.hwid != null && !c.hwid.isEmpty()) ? c.hwid : HWIDGrabber.getHWID();

        AuthClient client = new AuthClient(c.baseUrl, c.publicKeyB64, c.product, c.modVersion, c.freshnessMillis);
        LicenseResult r = client.validate(c.licenseKey, hwid);

        licensed = r.ok;
        session = r.session;
        lastReason = r.reason;

        if (r.ok && c.keepAliveMinutes > 0) {
            startKeepAlive(client, c.licenseKey, hwid, c.keepAliveMinutes, c.onLicenseLost);
        }
        return r;
    }

    private static void startKeepAlive(AuthClient client, String key, String hwid,
                                       long minutes, Runnable onLost) {
        stopKeepAlive();
        keepAlive = Executors.newSingleThreadScheduledExecutor(run -> {
            Thread t = new Thread(run, "license-keepalive");
            t.setDaemon(true);
            return t;
        });
        keepAlive.scheduleAtFixedRate(() -> {
            LicenseResult r = client.validate(key, hwid);
            // Only revoke access on a definitive negative from a *verified* server.
            // A transient NETWORK_ERROR does not flip an already-granted license,
            // so a brief outage will not kick a paying user mid-session.
            if (!r.ok && !"NETWORK_ERROR".equals(r.reason)) {
                licensed = false;
                session = null;
                lastReason = r.reason;
                if (onLost != null) {
                    try { onLost.run(); } catch (Throwable ignored) {}
                }
                stopKeepAlive();
            } else if (r.ok) {
                session = r.session;
                lastReason = "OK";
            }
        }, minutes, minutes, TimeUnit.MINUTES);
    }

    public static synchronized void stopKeepAlive() {
        if (keepAlive != null) { keepAlive.shutdownNow(); keepAlive = null; }
    }

    public static boolean isLicensed()   { return licensed; }
    public static Session getSession()   { return session; }
    public static String lastReason()    { return lastReason; }
}
