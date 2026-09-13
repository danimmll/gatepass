package io.github.danimmll.gatepass;

/**
 * Thrown when Gatepass is configured in a way it refuses to run with. Fails at startup, never per request.
 */
public class GatepassConfigurationException extends IllegalStateException {

    private static final long serialVersionUID = 1L;

    private final Reason reason;

    /**
     * Creates the exception.
     *
     * @param reason what is wrong
     * @param message a description that never includes secret values
     */
    public GatepassConfigurationException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    /**
     * What is wrong with the configuration.
     *
     * @return the reason
     */
    public Reason getReason() {
        return this.reason;
    }

    /**
     * What can be wrong with a Gatepass configuration.
     */
    public enum Reason {

        /** No secret, no private key and no trusted service: nothing to issue or verify passes with. */
        NO_KEYS,

        /** Shared-secret mode without a secret. */
        NO_SECRETS,

        /** A configured secret is empty or only whitespace. */
        BLANK_SECRET,

        /** A secret is shorter than {@link Gatepass#MIN_SECRET_BYTES}. */
        SECRET_TOO_SHORT,

        /** In shared-secret mode, a secret that cannot be sent as a header value. */
        SECRET_NOT_HEADER_SAFE,

        /** The same secret appears twice. */
        DUPLICATE_SECRET,

        /** A key that is not a usable Ed25519 key, or a trusted service without a name or without keys. */
        INVALID_KEY,

        /** The same public key configured twice, or two keys that share a key id. */
        DUPLICATE_KEY,

        /** The application sends passes but has nothing to sign them with in its mode. */
        CANNOT_ISSUE,

        /** Settings that contradict each other, such as caller rules without any trusted service. */
        CONFLICTING_SETTINGS,

        /** The maximum clock skew is zero or negative. */
        INVALID_CLOCK_SKEW

    }

}
