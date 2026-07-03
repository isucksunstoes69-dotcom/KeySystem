package com.example.mymod;

import dev.license.LicenseResult;
import dev.license.Protection;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Example Fabric CLIENT entrypoint that gates the mod behind a license.
 *
 * Copy the dev.license CLIENT classes into your mod's source (see README:
 * "Which files go where"), set the four constants below, and register this
 * class as a "client" entrypoint in fabric.mod.json.
 *
 * Nothing in your mod should run its real features unless FEATURES_ENABLED is
 * true. Check it at the top of every command / render / tick hook.
 */
public class ExampleClientInit implements ClientModInitializer {

    private static final Logger LOGGER = LoggerFactory.getLogger("MyMod");

    // ---- EDIT THESE ------------------------------------------------------
    private static final String BASE_URL   = "https://license.example.com"; // your server (use HTTPS in prod)
    private static final String PRODUCT    = "MyMod";
    private static final String MOD_VERSION= "1.0.0";
    // Paste the contents of publickey.txt here. This is PUBLIC - safe to ship.
    private static final String PUBLIC_KEY = "PASTE_publickey.txt_CONTENTS_HERE";
    // ----------------------------------------------------------------------

    /** The whole mod checks this before doing anything. Fail-closed default. */
    public static volatile boolean FEATURES_ENABLED = false;

    @Override
    public void onInitializeClient() {
        String key = readLicenseKey();
        if (key.isEmpty()) {
            LOGGER.error("[License] No key set. Put your license key in config/mymod-license.txt");
            FEATURES_ENABLED = false;
            return;
        }

        Protection.Config cfg = new Protection.Config();
        cfg.baseUrl = BASE_URL;
        cfg.publicKeyB64 = PUBLIC_KEY;
        cfg.product = PRODUCT;
        cfg.modVersion = MOD_VERSION;
        cfg.licenseKey = key;
        cfg.keepAliveMinutes = 30;                 // re-check every 30 min
        cfg.onLicenseLost = () -> {                // called if a later check fails
            FEATURES_ENABLED = false;
            LOGGER.warn("[License] Access revoked mid-session ({}).", Protection.lastReason());
        };

        LicenseResult result = Protection.enforce(cfg);
        if (result.ok) {
            FEATURES_ENABLED = true;
            LOGGER.info("[License] Verified. Licensed to {} (uid {}).",
                    result.session.getUsername(), result.session.getUid());
        } else {
            FEATURES_ENABLED = false;
            LOGGER.error("[License] Verification FAILED: {}. Mod features are disabled.", result.reason);
            // Optionally: show a toast/screen, or refuse to register your keybinds/commands.
        }
    }

    private static String readLicenseKey() {
        // 1. Baked-in key: jars handed out by the reseller download API contain /license.key.
        try (java.io.InputStream in = ExampleClientInit.class.getResourceAsStream("/license.key")) {
            if (in != null) {
                String k = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                if (!k.isEmpty()) return k;
            }
        } catch (Exception ignored) { }

        // 2. Fallback for manual installs: config/mymod-license.txt.
        try {
            Path file = FabricLoader.getInstance().getConfigDir().resolve("mymod-license.txt");
            if (!Files.exists(file)) {
                Files.writeString(file, "PUT-YOUR-LICENSE-KEY-HERE");
                return "";
            }
            String k = Files.readString(file).trim();
            return k.equals("PUT-YOUR-LICENSE-KEY-HERE") ? "" : k;
        } catch (Exception e) {
            LOGGER.error("[License] Could not read license file", e);
            return "";
        }
    }
}
