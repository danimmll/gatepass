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
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.jspecify.annotations.Nullable;

import io.github.danimmll.gatepass.GatepassConfigurationException.Reason;

/**
 * Issues and verifies passes: the header value that proves a request comes from inside your system, and in
 * {@link GatepassMode#ED25519 Ed25519} mode from which service.
 *
 * <p>A pass looks like {@code v1.hs256.ec609b60.1789293600.AAECAwQFBgcICQoLDA0ODw.-.Qm9...}: the format version, the
 * algorithm, the id of the key that signed it, when it was issued (epoch seconds), a random nonce, the SHA-256 of the
 * body or {@code -} when the body is not covered, and a signature over all of that plus the HTTP method, the raw path
 * and the raw query string. The key itself never travels, a pass is accepted once and only while its issue time is
 * within the maximum clock skew, and it cannot be moved to another request.
 *
 * <p>In {@link GatepassMode#SHARED_SECRET} mode the pass is the secret itself. Keep it for callers that cannot sign,
 * and only on a network you trust.
 *
 * <p>Instances are immutable and thread-safe.
 */
public final class Gatepass {

    /** Shortest secret accepted, in UTF-8 bytes. Anything shorter can be brute-forced from one captured pass. */
    public static final int MIN_SECRET_BYTES = 32;

    private static final String VERSION = "v1";

    private static final String HMAC_ALGORITHM = "hs256";

    private static final String ED25519_ALGORITHM = "ed25519";

    private static final String PAYLOAD_PREFIX = "gatepass-v1";

    private static final String NO_BODY = "-";

    private static final byte[] KEY_ID_PREFIX = "gatepass-key-id\n".getBytes(StandardCharsets.UTF_8);

    private static final int KEY_ID_LENGTH = 8;

    private static final int NONCE_BYTES = 16;

    private static final int NONCE_LENGTH = 22;

    private static final int DIGEST_LENGTH = 43;

    private static final int HMAC_SIGNATURE_LENGTH = 43;

    private static final int ED25519_SIGNATURE_LENGTH = 86;

    private static final int MAX_TIMESTAMP_DIGITS = 12;

    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    private final GatepassMode mode;

    private final List<Secret> secrets;

    private final @Nullable SigningKey signingKey;

    private final List<TrustedKey> trustedKeys;

    private final long maxClockSkewSeconds;

    private final Clock clock;

    private final ReplayGuard replayGuard;

    private final SecureRandom random;

    private Gatepass(Builder builder) {
        this.maxClockSkewSeconds = validSkew(builder.maxClockSkew).toSeconds();
        this.mode = (builder.mode != null) ? builder.mode
                : (builder.privateKey != null) ? GatepassMode.ED25519 : GatepassMode.HMAC;
        this.secrets = toSecrets(builder.secrets, this.mode);
        this.trustedKeys = toTrustedKeys(builder.trustedServices);
        this.signingKey = (builder.privateKey != null) ? toSigningKey(builder.privateKey, builder.publicKey) : null;
        checkCombination(builder.publicKey != null && builder.privateKey == null);
        this.clock = builder.clock;
        this.replayGuard = (builder.replayGuard != null) ? builder.replayGuard : new InMemoryReplayGuard(builder.clock);
        this.random = builder.random;
    }

    /**
     * Starts building a {@code Gatepass}.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * How this instance issues passes.
     *
     * @return the mode
     */
    public GatepassMode mode() {
        return this.mode;
    }

    /**
     * Whether this instance has a key to issue passes with in its mode: a secret, or a private key in Ed25519 mode.
     * A service that only receives calls may have none.
     *
     * @return {@code true} if {@link #issue(RequestParts)} can be called
     */
    public boolean canIssue() {
        return (this.mode == GatepassMode.ED25519) ? this.signingKey != null : !this.secrets.isEmpty();
    }

    /**
     * The names of the services whose Ed25519 passes this instance accepts.
     *
     * @return the trusted service names, in configuration order
     */
    public Set<String> trustedServices() {
        Set<String> names = new LinkedHashSet<>();
        for (TrustedKey key : this.trustedKeys) {
            names.add(key.service);
        }
        return names;
    }

    /**
     * Fails if something that sends passes could not do its job with this instance. Integrations call it when they
     * are created, so a sender without a key stops the application at startup rather than at its first request.
     *
     * @param bodySigning how the sender treats request bodies
     * @throws GatepassConfigurationException if this instance cannot issue the passes the sender needs
     */
    public void checkCanIssue(BodySigning bodySigning) {
        if (!canIssue()) {
            throw new GatepassConfigurationException(Reason.CANNOT_ISSUE, (this.mode == GatepassMode.ED25519)
                    ? "This application sends passes, but has no private key to sign them with."
                    : "This application sends passes, but has no secret to sign them with.");
        }
        if (bodySigning.enabled() && this.mode == GatepassMode.SHARED_SECRET) {
            throw new GatepassConfigurationException(Reason.CONFLICTING_SETTINGS,
                    "Body signing is on, but a shared-secret pass is the secret itself and cannot cover a body.");
        }
    }

    /**
     * Issues a pass for a request, without covering its body.
     *
     * @param request the request the pass is for, as it will go on the wire
     * @return the header value to send
     * @throws GatepassConfigurationException if this instance has no key to issue passes with
     */
    public String issue(RequestParts request) {
        checkCanIssue(BodySigning.disabled());
        return (this.mode == GatepassMode.SHARED_SECRET) ? this.secrets.get(0).value : sign(request, null);
    }

    /**
     * Issues a pass for a request that also covers its body.
     *
     * @param request the request the pass is for, as it will go on the wire
     * @param body the exact bytes of the body, empty if there is none
     * @return the header value to send
     * @throws GatepassConfigurationException if this instance has no key to issue passes with, or is in shared-secret
     * mode
     */
    public String issue(RequestParts request, byte[] body) {
        Objects.requireNonNull(body, "body");
        checkCanIssue(BodySigning.upTo(0));
        return sign(request, sha256(body));
    }

    /**
     * Checks the pass a request arrived with. A pass is accepted if any configured key verifies it: a secret for an
     * HMAC pass, a trusted service's public key for an Ed25519 pass.
     *
     * <p>A valid pass is remembered, and the same pass is rejected as {@link Verdict#REPLAYED} from then on. When the
     * result {@linkplain Verification#coversBody() covers the body}, the body still has to be checked with
     * {@link Verification#bodyMatches(byte[])}.
     *
     * @param pass the header value, or {@code null} when the header is absent
     * @param request the request as it arrived
     * @return the result
     */
    public Verification verify(@Nullable String pass, RequestParts request) {
        if (pass == null || pass.isEmpty()) {
            return Verification.rejected(Verdict.MISSING);
        }
        return (this.mode == GatepassMode.SHARED_SECRET) ? verifySharedSecret(pass) : verifySigned(pass, request);
    }

    private String sign(RequestParts request, byte @Nullable [] bodyDigest) {
        long issuedAt = this.clock.instant().getEpochSecond();
        byte[] nonceBytes = new byte[NONCE_BYTES];
        this.random.nextBytes(nonceBytes);
        String nonce = BASE64URL.encodeToString(nonceBytes);
        String body = (bodyDigest != null) ? BASE64URL.encodeToString(bodyDigest) : NO_BODY;
        String algorithm;
        String keyId;
        byte[] signature;
        if (this.mode == GatepassMode.ED25519) {
            SigningKey key = Objects.requireNonNull(this.signingKey);
            algorithm = ED25519_ALGORITHM;
            keyId = key.id;
            signature = ed25519Sign(key.privateKey, payload(algorithm, keyId, issuedAt, nonce, body, request));
        }
        else {
            Secret secret = this.secrets.get(0);
            algorithm = HMAC_ALGORITHM;
            keyId = secret.id;
            signature = hmac(secret, payload(algorithm, keyId, issuedAt, nonce, body, request));
        }
        return String.join(".", VERSION, algorithm, keyId, Long.toString(issuedAt), nonce, body,
                BASE64URL.encodeToString(signature));
    }

    private Verification verifySharedSecret(String pass) {
        byte[] candidate = sha256(pass.getBytes(StandardCharsets.UTF_8));
        boolean matched = false;
        for (Secret secret : this.secrets) {
            // No early exit: which secret matched, if any, must not show in the timing.
            matched |= MessageDigest.isEqual(secret.digest, candidate);
        }
        return matched ? Verification.valid(null, null) : Verification.rejected(Verdict.INVALID);
    }

    private Verification verifySigned(String pass, RequestParts request) {
        String[] parts = pass.split("\\.", -1);
        if (parts.length != 7 || !VERSION.equals(parts[0]) || !isKeyId(parts[2]) || !isTimestamp(parts[3])) {
            return Verification.rejected(Verdict.MALFORMED);
        }
        String algorithm = parts[1];
        boolean hmac = HMAC_ALGORITHM.equals(algorithm);
        if (!hmac && !ED25519_ALGORITHM.equals(algorithm)) {
            return Verification.rejected(Verdict.MALFORMED);
        }
        byte[] nonce = decodeCanonical(parts[4], NONCE_LENGTH);
        byte[] bodyDigest = NO_BODY.equals(parts[5]) ? null : decodeCanonical(parts[5], DIGEST_LENGTH);
        byte[] signature = decodeCanonical(parts[6], hmac ? HMAC_SIGNATURE_LENGTH : ED25519_SIGNATURE_LENGTH);
        if (nonce == null || signature == null || (bodyDigest == null && !NO_BODY.equals(parts[5]))) {
            return Verification.rejected(Verdict.MALFORMED);
        }
        long issuedAt = Long.parseLong(parts[3]);
        byte[] payload = payload(algorithm, parts[2], issuedAt, parts[4], parts[5], request);
        String caller = null;
        if (hmac) {
            Secret secret = findSecret(parts[2]);
            if (secret == null) {
                return Verification.rejected(Verdict.UNKNOWN_KEY);
            }
            if (!MessageDigest.isEqual(hmac(secret, payload), signature)) {
                return Verification.rejected(Verdict.INVALID);
            }
        }
        else {
            TrustedKey key = findTrustedKey(parts[2]);
            if (key == null) {
                return Verification.rejected(Verdict.UNKNOWN_KEY);
            }
            if (!ed25519Verify(key.publicKey, payload, signature)) {
                return Verification.rejected(Verdict.INVALID);
            }
            caller = key.service;
        }
        // Checked after the signature on purpose: EXPIRED and REPLAYED always mean a genuine pass.
        long drift = Math.abs(this.clock.instant().getEpochSecond() - issuedAt);
        if (drift > this.maxClockSkewSeconds) {
            return Verification.rejected(Verdict.EXPIRED);
        }
        String passId = algorithm + '.' + parts[2] + '.' + parts[4];
        if (!this.replayGuard.firstUse(passId, Instant.ofEpochSecond(issuedAt + this.maxClockSkewSeconds))) {
            return Verification.rejected(Verdict.REPLAYED);
        }
        return Verification.valid(caller, bodyDigest);
    }

    private @Nullable Secret findSecret(String id) {
        for (Secret secret : this.secrets) {
            if (secret.id.equals(id)) {
                return secret;
            }
        }
        return null;
    }

    private @Nullable TrustedKey findTrustedKey(String id) {
        for (TrustedKey key : this.trustedKeys) {
            if (key.id.equals(id)) {
                return key;
            }
        }
        return null;
    }

    private static byte[] payload(String algorithm, String keyId, long issuedAt, String nonce, String body,
            RequestParts request) {
        return String.join("\n", PAYLOAD_PREFIX, algorithm, keyId, Long.toString(issuedAt), nonce, body,
                request.method(), request.rawPath(), request.rawQuery()).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] hmac(Secret secret, byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.bytes, "HmacSHA256"));
            return mac.doFinal(payload);
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HmacSHA256 is not available in this JVM", ex);
        }
    }

    private static byte[] ed25519Sign(PrivateKey key, byte[] payload) {
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

    private static boolean ed25519Verify(PublicKey key, byte[] payload, byte[] signatureBytes) {
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

    static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalStateException("SHA-256 is not available in this JVM", ex);
        }
    }

    /** Public by design: it names a key in passes and logs, and reveals nothing a signature doesn't. */
    static String keyId(byte[] keyMaterial) {
        byte[] input = Arrays.copyOf(KEY_ID_PREFIX, KEY_ID_PREFIX.length + keyMaterial.length);
        System.arraycopy(keyMaterial, 0, input, KEY_ID_PREFIX.length, keyMaterial.length);
        return HexFormat.of().formatHex(sha256(input), 0, KEY_ID_LENGTH / 2);
    }

    /** Decodes unpadded base64url, refusing any other spelling of the same bytes. */
    private static byte @Nullable [] decodeCanonical(String value, int expectedLength) {
        if (value.length() != expectedLength) {
            return null;
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(value);
            return BASE64URL.encodeToString(decoded).equals(value) ? decoded : null;
        }
        catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private void checkCombination(boolean publicKeyWithoutPrivateKey) {
        if (publicKeyWithoutPrivateKey) {
            throw new GatepassConfigurationException(Reason.CONFLICTING_SETTINGS,
                    "A public key is set without the private key it belongs to.");
        }
        boolean hasPrivateKey = this.signingKey != null;
        switch (this.mode) {
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
            if (length < MIN_SECRET_BYTES) {
                throw new GatepassConfigurationException(Reason.SECRET_TOO_SHORT, "secrets[" + i + "] is " + length
                        + " bytes long; at least " + MIN_SECRET_BYTES + " are required.");
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
                String id = keyId(encoded);
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
        if (!ed25519Verify(publicKey, probe, ed25519Sign(privateKey, probe))) {
            throw new GatepassConfigurationException(Reason.INVALID_KEY,
                    "public-key does not belong to private-key.");
        }
        return new SigningKey(privateKey, keyId(publicKey.getEncoded()));
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

    private static Duration validSkew(Duration skew) {
        if (skew.isNegative() || skew.isZero()) {
            throw new GatepassConfigurationException(Reason.INVALID_CLOCK_SKEW,
                    "The maximum clock skew must be positive, but was " + skew + ".");
        }
        return skew;
    }

    private static boolean isKeyId(String value) {
        if (value.length() != KEY_ID_LENGTH) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isTimestamp(String value) {
        if (value.isEmpty() || value.length() > MAX_TIMESTAMP_DIGITS) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
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

    private static final class Secret {

        private final String value;

        private final byte[] bytes;

        private final byte[] digest;

        private final String id;

        private Secret(String value) {
            this.value = value;
            this.bytes = value.getBytes(StandardCharsets.UTF_8);
            this.digest = sha256(this.bytes);
            this.id = keyId(this.bytes);
        }

    }

    private static final class SigningKey {

        private final PrivateKey privateKey;

        private final String id;

        private SigningKey(PrivateKey privateKey, String id) {
            this.privateKey = privateKey;
            this.id = id;
        }

    }

    private static final class TrustedKey {

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

    /**
     * Builds {@link Gatepass} instances.
     */
    public static final class Builder {

        private @Nullable GatepassMode mode;

        private List<@Nullable String> secrets = new ArrayList<>();

        private @Nullable String privateKey;

        private @Nullable String publicKey;

        private final Map<String, List<String>> trustedServices = new LinkedHashMap<>();

        private Duration maxClockSkew = Duration.ofSeconds(30);

        private Clock clock = Clock.systemUTC();

        private @Nullable ReplayGuard replayGuard;

        private SecureRandom random = new SecureRandom();

        private Builder() {
        }

        /**
         * Sets how passes are issued. Defaults to {@link GatepassMode#ED25519} when a private key is set, and to
         * {@link GatepassMode#HMAC} otherwise.
         *
         * @param mode the mode
         * @return this builder
         */
        public Builder mode(GatepassMode mode) {
            this.mode = Objects.requireNonNull(mode, "mode");
            return this;
        }

        /**
         * Sets the shared secrets. The first one signs HMAC passes; all of them are accepted, which is how a secret
         * is rotated without downtime.
         *
         * @param secrets the secrets, each at least {@link #MIN_SECRET_BYTES} bytes long
         * @return this builder
         */
        public Builder secrets(List<? extends @Nullable String> secrets) {
            this.secrets = new ArrayList<>(Objects.requireNonNull(secrets, "secrets"));
            return this;
        }

        /**
         * Sets the shared secrets. The first one signs HMAC passes; all of them are accepted.
         *
         * @param secrets the secrets, each at least {@link #MIN_SECRET_BYTES} bytes long
         * @return this builder
         */
        public Builder secrets(String... secrets) {
            return secrets(List.of(secrets));
        }

        /**
         * Sets this service's own Ed25519 private key, which signs its passes in Ed25519 mode.
         *
         * @param privateKey the key in PKCS#8 form, as PEM or as base64 of the DER encoding
         * @return this builder
         */
        public Builder privateKey(String privateKey) {
            this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
            return this;
        }

        /**
         * Sets the public key that goes with the private key. Only needed on a JVM whose Ed25519 provider cannot
         * derive it; the JDK's own provider can.
         *
         * @param publicKey the key in X.509 SubjectPublicKeyInfo form, as PEM or as base64 of the DER encoding
         * @return this builder
         */
        public Builder publicKey(String publicKey) {
            this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
            return this;
        }

        /**
         * Trusts a service: Ed25519 passes signed with any of these keys are accepted, and name this service as
         * their caller. Listing two keys is how a service rotates its key pair without downtime.
         *
         * @param service the name the service is known by here, used in caller rules
         * @param publicKeys its public keys, as PEM or as base64 of the DER encoding
         * @return this builder
         */
        public Builder trustedService(String service, List<String> publicKeys) {
            this.trustedServices.put(Objects.requireNonNull(service, "service"),
                    new ArrayList<>(Objects.requireNonNull(publicKeys, "publicKeys")));
            return this;
        }

        /**
         * Trusts a service. See {@link #trustedService(String, List)}.
         *
         * @param service the name the service is known by here
         * @param publicKeys its public keys
         * @return this builder
         */
        public Builder trustedService(String service, String... publicKeys) {
            return trustedService(service, List.of(publicKeys));
        }

        /**
         * Replaces every trusted service. See {@link #trustedService(String, List)}.
         *
         * @param services the public keys of each trusted service, by name
         * @return this builder
         */
        public Builder trustedServices(Map<String, ? extends List<String>> services) {
            this.trustedServices.clear();
            Objects.requireNonNull(services, "services").forEach(this::trustedService);
            return this;
        }

        /**
         * Sets how far a pass's issue time may be from this machine's clock, in either direction. Defaults to 30
         * seconds. Ignored in {@link GatepassMode#SHARED_SECRET} mode.
         *
         * @param maxClockSkew a positive duration
         * @return this builder
         */
        public Builder maxClockSkew(Duration maxClockSkew) {
            this.maxClockSkew = Objects.requireNonNull(maxClockSkew, "maxClockSkew");
            return this;
        }

        /**
         * Sets the clock passes are issued and checked against. Defaults to the system clock in UTC.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Sets what remembers used passes. Defaults to an {@link InMemoryReplayGuard} on the same clock.
         *
         * @param replayGuard the guard, or {@link ReplayGuard#disabled()}
         * @return this builder
         */
        public Builder replayGuard(ReplayGuard replayGuard) {
            this.replayGuard = Objects.requireNonNull(replayGuard, "replayGuard");
            return this;
        }

        /** For tests that need a known nonce. */
        Builder random(SecureRandom random) {
            this.random = Objects.requireNonNull(random, "random");
            return this;
        }

        /**
         * Builds the instance, validating the configuration.
         *
         * @return a new {@code Gatepass}
         * @throws GatepassConfigurationException if the keys, their combination with the mode, or the clock skew are
         * not usable
         */
        public Gatepass build() {
            return new Gatepass(this);
        }

    }

}
