package dev.license;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Ed25519 sign/verify plus key encoding helpers. Requires Java 15+ (Ed25519 is
 * built into the JDK since 15; Minecraft 1.18+ runs on Java 17/21).
 *
 * The SERVER holds the private key and signs responses.
 * The MOD embeds only the public key and verifies responses. A signed response
 * therefore cannot be forged by anyone who redirects the license domain,
 * because they do not have the private key.
 */
public final class Crypto {

    private Crypto() {}

    private static final String ALG = "Ed25519";
    private static final SecureRandom RNG = new SecureRandom();

    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance(ALG).generateKeyPair();
    }

    public static String encodeKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded()); // X.509 SPKI
    }

    public static String encodeKey(PrivateKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded()); // PKCS#8
    }

    public static PublicKey publicKeyFromBase64(String b64) throws GeneralSecurityException {
        byte[] der = Base64.getDecoder().decode(b64.trim());
        return KeyFactory.getInstance(ALG).generatePublic(new X509EncodedKeySpec(der));
    }

    public static PrivateKey privateKeyFromBase64(String b64) throws GeneralSecurityException {
        byte[] der = Base64.getDecoder().decode(b64.trim());
        return KeyFactory.getInstance(ALG).generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    public static String sign(PrivateKey priv, String message) throws GeneralSecurityException {
        Signature s = Signature.getInstance(ALG);
        s.initSign(priv);
        s.update(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(s.sign());
    }

    public static boolean verify(PublicKey pub, String message, String signatureB64) {
        try {
            Signature s = Signature.getInstance(ALG);
            s.initVerify(pub);
            s.update(message.getBytes(StandardCharsets.UTF_8));
            return s.verify(Base64.getDecoder().decode(signatureB64));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /** 128-bit random hex, used as an anti-replay nonce. */
    public static String newNonce() {
        byte[] b = new byte[16];
        RNG.nextBytes(b);
        StringBuilder sb = new StringBuilder(32);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        return sb.toString();
    }
}
