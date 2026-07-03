package dev.license;

import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Builds a stable hardware fingerprint (HWID) for the machine running the mod,
 * using only the JDK - no native calls, no external libraries.
 *
 * Sources (all stable across reboots):
 *   - MAC addresses of real (non-loopback, non-virtual) network interfaces
 *   - os.name, os.arch
 *   - the OS user name
 *   - the machine host name
 *
 * A change of network card / reinstall will change the HWID (expected). This is
 * fine for licensing: the customer just re-binds. Do NOT treat a HWID as a
 * secret - it only identifies a machine, it does not authenticate it. The
 * security comes from the signed server response, not from the HWID.
 */
public final class HWIDGrabber {

    private HWIDGrabber() {}

    public static String getHWID() {
        StringBuilder raw = new StringBuilder();
        raw.append("macs=").append(macFingerprint()).append(';');
        raw.append("os=").append(prop("os.name")).append(';');
        raw.append("arch=").append(prop("os.arch")).append(';');
        raw.append("user=").append(prop("user.name")).append(';');
        raw.append("host=").append(hostName()).append(';');
        return sha256Hex(raw.toString());
    }

    private static String macFingerprint() {
        List<String> macs = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
            while (nics != null && nics.hasMoreElements()) {
                NetworkInterface nic = nics.nextElement();
                try {
                    if (nic.isLoopback() || nic.isVirtual() || !nic.isUp()) continue;
                } catch (Exception ignored) {
                    // some platforms throw on isUp for down interfaces; skip them
                    continue;
                }
                byte[] mac = nic.getHardwareAddress();
                if (mac == null || mac.length == 0) continue;
                StringBuilder sb = new StringBuilder();
                for (byte b : mac) sb.append(String.format("%02X", b));
                macs.add(sb.toString());
            }
        } catch (Exception ignored) {
            // fall through - macs may be empty
        }
        Collections.sort(macs); // order-independent
        return macs.isEmpty() ? "none" : String.join(",", macs);
    }

    private static String hostName() {
        String h = System.getenv("COMPUTERNAME");
        if (h == null || h.isEmpty()) h = System.getenv("HOSTNAME");
        if (h == null || h.isEmpty()) {
            try {
                h = java.net.InetAddress.getLocalHost().getHostName();
            } catch (Exception ignored) {
                h = "unknown";
            }
        }
        return h;
    }

    private static String prop(String k) {
        String v = System.getProperty(k);
        return v == null ? "" : v;
    }

    public static String sha256Hex(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
