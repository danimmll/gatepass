package io.github.danimmll.gatepass;

/**
 * The outcome of checking a request.
 *
 * <p>{@link Gatepass#verify} produces {@code VALID} and the next six. The inbound filters add the rest, which depend
 * on the request as a whole and on how the receiving service is configured.
 */
public enum Verdict {

    /** The pass is genuine, current, used for the first time, and the request meets every rule. */
    VALID,

    /** The request carried no pass. */
    MISSING,

    /** The header holds something that is not a pass in the configured mode. */
    MALFORMED,

    /** Signed with a key this service does not have. Usually a rotation applied on one side only. */
    UNKNOWN_KEY,

    /** The wrong key, or a signature that does not match this method, path and query string. */
    INVALID,

    /** A genuine pass outside the allowed clock skew: replayed late, or clocks that drifted apart. */
    EXPIRED,

    /** A genuine pass that has already been used once. */
    REPLAYED,

    /** A genuine pass from a service that may not call this path, or from no service in particular. */
    CALLER_NOT_ALLOWED,

    /** A genuine pass that does not cover the request body, on a service that requires it. */
    BODY_NOT_SIGNED,

    /** A genuine pass whose body digest does not match the body that arrived. */
    BODY_MISMATCH,

    /** A genuine pass covering a body larger than this service agrees to read into memory. */
    BODY_TOO_LARGE,

    /** The request did not arrive over TLS, on a service that requires it. */
    NOT_TLS;

    /**
     * Whether the request may go through.
     *
     * @return {@code true} only for {@link #VALID}
     */
    public boolean isValid() {
        return this == VALID;
    }

    /**
     * Whether only a request carrying a genuine pass can end up with this verdict. Such rejections are logged as
     * warnings: random traffic cannot trigger them, so they point at a real problem (a replay, a tampered body, a
     * service calling where it should not) rather than at noise.
     *
     * @return {@code true} if the verdict implies a genuine pass
     */
    public boolean requiresGenuinePass() {
        return switch (this) {
            case EXPIRED, REPLAYED, CALLER_NOT_ALLOWED, BODY_NOT_SIGNED, BODY_MISMATCH, BODY_TOO_LARGE -> true;
            case VALID, MISSING, MALFORMED, UNKNOWN_KEY, INVALID, NOT_TLS -> false;
        };
    }

}
