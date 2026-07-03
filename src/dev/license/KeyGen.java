package dev.license;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

/**
 * Generates the Ed25519 key pair.
 *
 *   publickey.txt   -> paste into the mod (LicenseConfig.PUBLIC_KEY). PUBLIC, safe to ship.
 *   privatekey.txt  -> keep on the license server ONLY. Never ship this. If it
 *                      leaks, anyone can mint valid licenses; rotate immediately.
 */
public final class KeyGen {

    public static void main(String[] args) throws Exception {
        KeyPair kp = Crypto.generateKeyPair();
        String pub = Crypto.encodeKey(kp.getPublic());
        String priv = Crypto.encodeKey(kp.getPrivate());

        Path pubFile = Paths.get(args.length > 0 ? args[0] : "publickey.txt");
        Path privFile = Paths.get(args.length > 1 ? args[1] : "privatekey.txt");
        Files.writeString(pubFile, pub);
        Files.writeString(privFile, priv);

        System.out.println("Wrote " + pubFile.toAbsolutePath());
        System.out.println("Wrote " + privFile.toAbsolutePath() + "   <-- keep secret, server only");
        System.out.println();
        System.out.println("PUBLIC KEY (embed in the mod):");
        System.out.println(pub);
    }
}
