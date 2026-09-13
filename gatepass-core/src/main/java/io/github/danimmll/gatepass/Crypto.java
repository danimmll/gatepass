package io.github.danimmll.gatepass;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.jspecify.annotations.Nullable;

/**
 * The cryptographic primitives passes are built on.
 *
 * <p>Looking up a provider and keying an HMAC cost more than computing it for a pass-sized payload, so digests and
 * keyed HMACs are prepared once and cloned for each use. Prototypes are never updated themselves, which is what makes
 * sharing them between threads safe.
 */
final class Crypto {

    private static final String HMAC_SHA256 = "HmacSHA256";

    private static final byte[] KEY_ID_PREFIX = "gatepass-key-id\n".getBytes(StandardCharsets.UTF_8);

    private static final int KEY_ID_BYTES = 4;

    private static final MessageDigest SHA256_PROTOTYPE = newSha256();

    private Crypto() {
    }

    static byte[] sha256(byte[] input) {
        return sha256().digest(input);
    }

    /** Public by design: it names a key in passes and logs, and reveals nothing a signature doesn't. */
    static String keyId(byte[] keyMaterial) {
        MessageDigest digest = sha256();
        digest.update(KEY_ID_PREFIX);
        digest.update(keyMaterial);
        return HexFormat.of().formatHex(digest.digest(), 0, KEY_ID_BYTES);
    }

    static Mac hmacSha256(byte[] key) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac;
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalStateException(HMAC_SHA256 + " is not available in this JVM", ex);
        }
    }

    /**
     * A ready-to-use copy of a keyed HMAC.
     *
     * @return the copy, or {@code null} if this provider's HMAC cannot be cloned
     */
    static @Nullable Mac copy(Mac prototype) {
        try {
            return (Mac) prototype.clone();
        }
        catch (CloneNotSupportedException ex) {
            return null;
        }
    }

    static byte[] ed25519Sign(PrivateKey key, byte[] payload) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key);
            signature.update(payload);
            return signature.sign();
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Ed25519 is not available in this JVM", ex);
        }
    }

    static boolean ed25519Verify(PublicKey key, byte[] payload, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(key);
            signature.update(payload);
            return signature.verify(signatureBytes);
        }
        catch (SignatureException ex) {
            return false;
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Ed25519 is not available in this JVM", ex);
        }
    }

    private static MessageDigest sha256() {
        try {
            return (MessageDigest) SHA256_PROTOTYPE.clone();
        }
        catch (CloneNotSupportedException ex) {
            return newSha256();
        }
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalStateException("SHA-256 is not available in this JVM", ex);
        }
    }

}
