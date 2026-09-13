package io.github.danimmll.gatepass;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

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

    private static final int KEY_ID_LENGTH = 8;

    private static final int NONCE_BYTES = 16;

    private static final int DIGEST_BYTES = 32;

    private static final int HMAC_SIGNATURE_BYTES = 32;

    private static final int ED25519_SIGNATURE_BYTES = 64;

    private static final int MAX_TIMESTAMP_DIGITS = 12;

    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    private final GatepassMode mode;

    private final KeyRing keys;

    private final long maxClockSkewSeconds;

    private final Clock clock;

    private final ReplayGuard replayGuard;

    private final SecureRandom random;

    private Gatepass(Builder builder) {
        this.maxClockSkewSeconds = validSkew(builder.maxClockSkew).toSeconds();
        this.mode = (builder.mode != null) ? builder.mode
                : (builder.privateKey != null) ? GatepassMode.ED25519 : GatepassMode.HMAC;
        this.keys = KeyRing.of(this.mode, builder.secrets, builder.privateKey, builder.publicKey,
                builder.trustedServices);
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
        return (this.mode == GatepassMode.ED25519) ? this.keys.signingKey() != null : this.keys.hasSecrets();
    }

    /**
     * The names of the services whose Ed25519 passes this instance accepts.
     *
     * @return the trusted service names, in configuration order
     */
    public Set<String> trustedServices() {
        return this.keys.trustedServices();
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
        return (this.mode == GatepassMode.SHARED_SECRET) ? this.keys.signingSecret().value() : sign(request, null);
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
        return sign(request, Crypto.sha256(body));
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
            KeyRing.SigningKey key = Objects.requireNonNull(this.keys.signingKey());
            algorithm = ED25519_ALGORITHM;
            keyId = key.id();
            signature = key.sign(payload(algorithm, keyId, issuedAt, nonce, body, request));
        }
        else {
            KeyRing.Secret secret = this.keys.signingSecret();
            algorithm = HMAC_ALGORITHM;
            keyId = secret.id();
            signature = secret.hmac(payload(algorithm, keyId, issuedAt, nonce, body, request));
        }
        return VERSION + '.' + algorithm + '.' + keyId + '.' + issuedAt + '.' + nonce + '.' + body + '.'
                + BASE64URL.encodeToString(signature);
    }

    private Verification verifySharedSecret(String pass) {
        byte[] candidate = Crypto.sha256(pass.getBytes(StandardCharsets.UTF_8));
        boolean matched = false;
        for (KeyRing.Secret secret : this.keys.secrets()) {
            // No early exit: which secret matched, if any, must not show in the timing.
            matched |= secret.hasDigest(candidate);
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
        byte[] nonce = decodeCanonical(parts[4], NONCE_BYTES);
        boolean noBody = NO_BODY.equals(parts[5]);
        byte[] bodyDigest = noBody ? null : decodeCanonical(parts[5], DIGEST_BYTES);
        byte[] signature = decodeCanonical(parts[6], hmac ? HMAC_SIGNATURE_BYTES : ED25519_SIGNATURE_BYTES);
        if (nonce == null || signature == null || (bodyDigest == null && !noBody)) {
            return Verification.rejected(Verdict.MALFORMED);
        }
        long issuedAt = Long.parseLong(parts[3]);
        byte[] payload = payload(algorithm, parts[2], issuedAt, parts[4], parts[5], request);
        String caller = null;
        if (hmac) {
            KeyRing.Secret secret = this.keys.findSecret(parts[2]);
            if (secret == null) {
                return Verification.rejected(Verdict.UNKNOWN_KEY);
            }
            if (!java.security.MessageDigest.isEqual(secret.hmac(payload), signature)) {
                return Verification.rejected(Verdict.INVALID);
            }
        }
        else {
            KeyRing.TrustedKey key = this.keys.findTrustedKey(parts[2]);
            if (key == null) {
                return Verification.rejected(Verdict.UNKNOWN_KEY);
            }
            if (!key.verify(payload, signature)) {
                return Verification.rejected(Verdict.INVALID);
            }
            caller = key.service();
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

    private static byte[] payload(String algorithm, String keyId, long issuedAt, String nonce, String body,
            RequestParts request) {
        return (PAYLOAD_PREFIX + '\n' + algorithm + '\n' + keyId + '\n' + issuedAt + '\n' + nonce + '\n' + body + '\n'
                + request.method() + '\n' + request.rawPath() + '\n' + request.rawQuery())
                .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Decodes unpadded base64url, refusing any other spelling of the same bytes: the bits the last character carries
     * beyond the decoded bytes must be zero.
     */
    private static byte @Nullable [] decodeCanonical(String value, int bytes) {
        int length = (bytes * 8 + 5) / 6;
        if (value.length() != length) {
            return null;
        }
        int unusedBits = length * 6 - bytes * 8;
        int last = base64UrlValue(value.charAt(length - 1));
        if (last < 0 || (last & ((1 << unusedBits) - 1)) != 0) {
            return null;
        }
        try {
            return Base64.getUrlDecoder().decode(value);
        }
        catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static int base64UrlValue(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        return (c == '-') ? 62 : (c == '_') ? 63 : -1;
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
