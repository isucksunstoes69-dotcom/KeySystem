package com.example.mymod;

import dev.license.LicenseResult;
import dev.license.Protection;
import net.fabricmc.api.DedicatedServerModInitializer;
import net.fabricmc.loader.api.FabricLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Example Fabric DEDICATED-SERVER entrypoint. A server-side mod can enforce
 * harder: if the license is invalid it refuses to finish loading and stops the
 * JVM, so the mod simply cannot run unlicensed.
 *
 * Register as a "server" entrypoint in fabric.mod.json.
 */
public class ExampleServerInit implements DedicatedServerModInitializer {

    private static final Logger LOGGER = LoggerFactory.getLogger("MyMod");

    private static final String BASE_URL    = "https://license.example.com";
    private static final String PRODUCT     = "MyMod";
    private static final String MOD_VERSION = "1.0.0";
    private static final String PUBLIC_KEY  = "PASTE_publickey.txt_CONTENTS_HERE";

    public static volatile boolean FEATURES_ENABLED = false;

    @Override
    public void onInitializeServer() {
        String key = readLicenseKey();

        Protection.Config cfg = new Protection.Config();
        cfg.baseUrl = BASE_URL;
        cfg.publicKeyB64 = PUBLIC_KEY;
        cfg.product = PRODUCT;
        cfg.modVersion = MOD_VERSION;
        cfg.licenseKey = key;
        cfg.keepAliveMinutes = 60;
        cfg.onLicenseLost = () -> {
            FEATURES_ENABLED = false;
            LOGGER.error("[License] Revoked mid-session ({}). Shutting down.", Protection.lastReason());
            // Hard stop so the mod cannot keep running unlicensed:
            Runtime.getRuntime().halt(1);
        };

        LicenseResult result = Protection.enforce(cfg);
        if (result.ok) {
            FEATURES_ENABLED = true;
            LOGGER.info("[License] Verified. Licensed to {} (uid {}).",
                    result.session.getUsername(), result.session.getUid());
        } else {
            FEATURES_ENABLED = false;
            LOGGER.error("[License] Verification FAILED: {}. Aborting server start.", result.reason);
            // Abort load. Use halt() to guarantee the process stops.
            Runtime.getRuntime().halt(1);
        }
    }

    private static String readLicenseKey() {
        try (java.io.InputStream in = ExampleServerInit.class.getResourceAsStream("/license.key")) {
            if (in != null) {
                String k = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                if (!k.isEmpty()) return k;
            }
        } catch (Exception ignored) { }
        try {
            Path file = FabricLoader.getInstance().getConfigDir().resolve("mymod-license.txt");
            if (!Files.exists(file)) { Files.writeString(file, "PUT-YOUR-LICENSE-KEY-HERE"); return ""; }
            String k = Files.readString(file).trim();
            return k.equals("PUT-YOUR-LICENSE-KEY-HERE") ? "" : k;
        } catch (Exception e) {
            return "";
        }
    }
}
