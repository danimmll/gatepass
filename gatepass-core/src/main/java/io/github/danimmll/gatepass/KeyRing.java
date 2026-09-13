package io.github.danimmll.gatepass;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;

import org.jspecify.annotations.Nullable;

import io.github.danimmll.gatepass.GatepassConfigurationException.Reason;

/**
 * Every key a {@link Gatepass} signs and verifies with, parsed and validated once, when it is built.
 */
final class KeyRing {

    private final List<Secret> secrets;

    private final @Nullable SigningKey signingKey;

    private final List<TrustedKey> trustedKeys;

    private KeyRing(List<Secret> secrets, @Nullable SigningKey signingKey, List<TrustedKey> trustedKeys) {
        this.secrets = secrets;
        this.signingKey = signingKey;
        this.trustedKeys = trustedKeys;
    }

    static KeyRing of(GatepassMode mode, List<@Nullable String> secrets, @Nullable String privateKey,
            @Nullable String publicKey, Map<String, List<String>> trustedServices) {
        KeyRing keys = new KeyRing(toSecrets(secrets, mode), (privateKey != null) ? toSigningKey(privateKey, publicKey)
                : null, toTrustedKeys(trustedServices));
        keys.checkCombination(mode, publicKey != null && privateKey == null);
        return keys;
    }

    boolean hasSecrets() {
        return !this.secrets.isEmpty();
    }

    /** The secret that signs: the first one. Only valid when {@link #hasSecrets()}. */
    Secret signingSecret() {
        return this.secrets.get(0);
    }

    List<Secret> secrets() {
        return this.secrets;
    }

    @Nullable SigningKey signingKey() {
        return this.signingKey;
    }

    Set<String> trustedServices() {
        Set<String> names = new LinkedHashSet<>();
        for (TrustedKey key : this.trustedKeys) {
            names.add(key.service);
        }
        return names;
    }

    @Nullable Secret findSecret(String id) {
        for (Secret secret : this.secrets) {
            if (secret.id.equals(id)) {
                return secret;
            }
        }
        return null;
    }

    @Nullable TrustedKey findTrustedKey(String id) {
        for (TrustedKey key : this.trustedKeys) {
            if (key.id.equals(id)) {
                return key;
            }
        }
        return null;
    }

    private void checkCombination(GatepassMode mode, boolean publicKeyWithoutPrivateKey) {
        if (publicKeyWithoutPrivateKey) {
            throw new GatepassConfigurationException(Reason.CONFLICTING_SETTINGS,
                    "A public key is set without the private key it belongs to.");
        }
        boolean hasPrivateKey = this.signingKey != null;
        switch (mode) {
            case SHARED_SECRET -> {
                if (this.secrets.isEmpty()) {
                    throw new GatepassConfigurationException(Reason.NO_SECRETS,
                            "Shared-secret mode needs at least one secret.");
                }
                if (hasPrivateKey || !this.trustedKeys.isEmpty()) {
                    throw new GatepassConfigurationException(Reason.CONFLICTING_SETTINGS,
                            "Shared-secret mode sends the secret itself and has no use for Ed25519 keys.");
                }
            }
            case HMAC -> {
                if (hasPrivateKey) {
                    throw new GatepassConfigurationException(Reason.CONFLICTING_SETTINGS,
                            "A private key is set, but the mode is hmac, so it would never sign anything.");
                }
                if (this.secrets.isEmpty() && this.trustedKeys.isEmpty()) {
                    throw noKeys();
                }
            }
            case ED25519 -> {
                if (!hasPrivateKey && this.secrets.isEmpty() && this.trustedKeys.isEmpty()) {
                    throw noKeys();
                }
            }
        }
    }

    private static GatepassConfigurationException noKeys() {
        return new GatepassConfigurationException(Reason.NO_KEYS,
                "Nothing to issue or verify passes with: no secret, no private key and no trusted service.");
    }

    private static List<Secret> toSecrets(List<@Nullable String> values, GatepassMode mode) {
        List<Secret> secrets = new ArrayList<>(values.size());
        for (int i = 0; i < values.size(); i++) {
            String value = values.get(i);
            if (value == null || value.isBlank()) {
                throw new GatepassConfigurationException(Reason.BLANK_SECRET, "secrets[" + i + "] is empty.");
            }
            int length = value.getBytes(StandardCharsets.UTF_8).length;
            if (length < Gatepass.MIN_SECRET_BYTES) {
                throw new GatepassConfigurationException(Reason.SECRET_TOO_SHORT, "secrets[" + i + "] is " + length
                        + " bytes long; at least " + Gatepass.MIN_SECRET_BYTES + " are required.");
            }
            if (mode == GatepassMode.SHARED_SECRET && !isHeaderSafe(value)) {
                throw new GatepassConfigurationException(Reason.SECRET_NOT_HEADER_SAFE, "secrets[" + i
                        + "] contains characters that cannot travel in an HTTP header. In shared-secret mode the"
                        + " secret is sent as is, so it must be printable ASCII without spaces.");
            }
            for (int j = 0; j < i; j++) {
                if (value.equals(secrets.get(j).value)) {
                    throw new GatepassConfigurationException(Reason.DUPLICATE_SECRET,
                            "secrets[" + i + "] is the same as secrets[" + j + "].");
                }
            }
            secrets.add(new Secret(value));
        }
        return List.copyOf(secrets);
    }

    private static List<TrustedKey> toTrustedKeys(Map<String, List<String>> services) {
        List<TrustedKey> keys = new ArrayList<>();
        for (Map.Entry<String, List<String>> service : services.entrySet()) {
            String name = service.getKey();
            if (name.isBlank()) {
                throw new GatepassConfigurationException(Reason.INVALID_KEY, "A trusted service has an empty name.");
            }
            if (service.getValue().isEmpty()) {
                throw new GatepassConfigurationException(Reason.INVALID_KEY,
                        "Trusted service '" + name + "' has no public key.");
            }
            for (int i = 0; i < service.getValue().size(); i++) {
                String label = "trusted-services." + name + "[" + i + "]";
                PublicKey publicKey = parsePublicKey(service.getValue().get(i), label);
                byte[] encoded = publicKey.getEncoded();
                String id = Crypto.keyId(encoded);
                for (TrustedKey other : keys) {
                    if (Arrays.equals(other.encoded, encoded)) {
                        throw new GatepassConfigurationException(Reason.DUPLICATE_KEY, label + " is the same key as "
                                + other.label + ". Each service needs a key pair of its own, listed once.");
                    }
                    if (other.id.equals(id)) {
                        throw new GatepassConfigurationException(Reason.DUPLICATE_KEY, label + " and " + other.label
                                + " are different keys with the same key id " + id + ". Generate a new pair for one of"
                                + " them.");
                    }
                }
                keys.add(new TrustedKey(name, label, publicKey, encoded, id));
            }
        }
        return List.copyOf(keys);
    }

    private static SigningKey toSigningKey(String privateKeyText, @Nullable String publicKeyText) {
        PrivateKey privateKey = parsePrivateKey(privateKeyText);
        PublicKey publicKey = (publicKeyText != null) ? parsePublicKey(publicKeyText, "public-key")
                : derivePublicKey(privateKey);
        byte[] probe = "gatepass-key-check".getBytes(StandardCharsets.UTF_8);
        if (!Crypto.ed25519Verify(publicKey, probe, Crypto.ed25519Sign(privateKey, probe))) {
            throw new GatepassConfigurationException(Reason.INVALID_KEY,
                    "public-key does not belong to private-key.");
        }
        return new SigningKey(privateKey, Crypto.keyId(publicKey.getEncoded()));
    }

    private static PrivateKey parsePrivateKey(String text) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(decodeKey(text)));
        }
        catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new GatepassConfigurationException(Reason.INVALID_KEY, "private-key is not an Ed25519 private key"
                    + " (PKCS#8, as PEM or as base64 of the DER encoding).");
        }
    }

    private static PublicKey parsePublicKey(String text, String label) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(decodeKey(text)));
        }
        catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new GatepassConfigurationException(Reason.INVALID_KEY, label + " is not an Ed25519 public key"
                    + " (X.509 SubjectPublicKeyInfo, as PEM or as base64 of the DER encoding).");
        }
    }

    /**
     * An Ed25519 private key is 32 random bytes, and the JDK's generator derives the public key from them. Feeding it
     * those bytes as its "randomness" rebuilds the pair, so a service only has to be given its private key.
     */
    private static PublicKey derivePublicKey(PrivateKey privateKey) {
        try {
            byte[] seed = ((EdECPrivateKey) privateKey).getBytes().orElseThrow();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            generator.initialize(NamedParameterSpec.ED25519, new FixedSeed(seed));
            KeyPair pair = generator.generateKeyPair();
            byte[] regenerated = ((EdECPrivateKey) pair.getPrivate()).getBytes().orElseThrow();
            if (!MessageDigest.isEqual(seed, regenerated)) {
                throw new GeneralSecurityException("The generator did not use the given seed");
            }
            return pair.getPublic();
        }
        catch (GeneralSecurityException | RuntimeException ex) {
            throw new GatepassConfigurationException(Reason.INVALID_KEY, "The public key cannot be derived from"
                    + " private-key with this JVM's Ed25519 provider; set public-key as well.");
        }
    }

    private static byte[] decodeKey(String text) {
        StringBuilder base64 = new StringBuilder(text.length());
        for (String line : text.replace("\\n", "\n").split("\\R")) {
            String trimmed = line.strip();
            if (!trimmed.startsWith("-----")) {
                base64.append(trimmed);
            }
        }
        return Base64.getDecoder().decode(base64.toString().replaceAll("\\s+", ""));
    }

    private static boolean isHeaderSafe(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x21 || c > 0x7E) {
                return false;
            }
        }
        return true;
    }

    /** A shared secret, with its HMAC keyed once. */
    static final class Secret {

        private final String value;

        private final byte[] bytes;

        private final byte[] digest;

        private final String id;

        private final Mac prototype;

        private Secret(String value) {
            this.value = value;
            this.bytes = value.getBytes(StandardCharsets.UTF_8);
            this.digest = Crypto.sha256(this.bytes);
            this.id = Crypto.keyId(this.bytes);
            this.prototype = Crypto.hmacSha256(this.bytes);
        }

        String value() {
            return this.value;
        }

        String id() {
            return this.id;
        }

        byte[] hmac(byte[] payload) {
            Mac mac = Crypto.copy(this.prototype);
            return ((mac != null) ? mac : Crypto.hmacSha256(this.bytes)).doFinal(payload);
        }

        /** Constant time, for shared-secret mode. */
        boolean hasDigest(byte[] candidate) {
            return MessageDigest.isEqual(this.digest, candidate);
        }

    }

    /** This service's own Ed25519 key. */
    static final class SigningKey {

        private final PrivateKey privateKey;

        private final String id;

        private SigningKey(PrivateKey privateKey, String id) {
            this.privateKey = privateKey;
            this.id = id;
        }

        String id() {
            return this.id;
        }

        byte[] sign(byte[] payload) {
            return Crypto.ed25519Sign(this.privateKey, payload);
        }

    }

    /** The public key of a trusted service. */
    static final class TrustedKey {

        private final String service;

        private final String label;

        private final PublicKey publicKey;

        private final byte[] encoded;

        private final String id;

        private TrustedKey(String service, String label, PublicKey publicKey, byte[] encoded, String id) {
            this.service = service;
            this.label = label;
            this.publicKey = publicKey;
            this.encoded = encoded;
            this.id = id;
        }

        String service() {
            return this.service;
        }

        boolean verify(byte[] payload, byte[] signature) {
            return Crypto.ed25519Verify(this.publicKey, payload, signature);
        }

    }

    /** Hands a key generator the bytes of an existing private key instead of random ones. */
    private static final class FixedSeed extends SecureRandom {

        private static final long serialVersionUID = 1L;

        private final byte[] seed;

        private FixedSeed(byte[] seed) {
            this.seed = seed;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            if (bytes.length != this.seed.length) {
                throw new IllegalStateException("Expected a request for " + this.seed.length + " bytes");
            }
            System.arraycopy(this.seed, 0, bytes, 0, bytes.length);
        }

    }

}
