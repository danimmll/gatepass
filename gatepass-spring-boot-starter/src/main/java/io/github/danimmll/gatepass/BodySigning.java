package io.github.danimmll.gatepass;

import org.jspecify.annotations.Nullable;

/**
 * Whether a sender covers request bodies with its passes, and how large a body it agrees to hold in memory for it.
 *
 * <p>Multipart bodies are never signed: they are usually large uploads, and a servlet container parses them straight
 * from the connection, where a body read in advance could not be handed back.
 *
 * @param enabled whether bodies are signed
 * @param maxBytes the largest body that is signed, in bytes
 */
public record BodySigning(boolean enabled, long maxBytes) {

    /** One megabyte, the default limit. */
    public static final long DEFAULT_MAX_BYTES = 1024 * 1024;

    /**
     * Validates the limit.
     *
     * @param enabled whether bodies are signed
     * @param maxBytes the largest body that is signed, in bytes, between 0 and {@code Integer.MAX_VALUE - 8}
     */
    public BodySigning {
        if (maxBytes < 0 || maxBytes > Integer.MAX_VALUE - 8) {
            throw new IllegalArgumentException("The body size limit must be between 0 and 2 GB, but was " + maxBytes);
        }
    }

    /**
     * Bodies are not signed.
     *
     * @return a disabled configuration
     */
    public static BodySigning disabled() {
        return new BodySigning(false, DEFAULT_MAX_BYTES);
    }

    /**
     * Bodies up to this size are signed.
     *
     * @param maxBytes the largest body that is signed, in bytes
     * @return an enabled configuration
     */
    public static BodySigning upTo(long maxBytes) {
        return new BodySigning(true, maxBytes);
    }

    /**
     * Whether a request with this content type gets its body signed.
     *
     * @param contentType the {@code Content-Type} header, or {@code null}
     * @return {@code true} if signing is enabled and the body is not multipart
     */
    public boolean appliesTo(@Nullable String contentType) {
        return this.enabled && !isMultipart(contentType);
    }

    /**
     * The limit as an {@code int}, for the APIs that take one.
     *
     * @return the largest body that is signed, in bytes
     */
    public int maxBytesAsInt() {
        return (int) this.maxBytes;
    }

    /**
     * Fails when a body is too large to be signed: a sender that cannot cover a body fails the request rather than
     * send it unsigned.
     *
     * @param bodyBytes the size of the body
     * @throws IllegalStateException if the body is larger than the limit
     */
    public void checkSize(long bodyBytes) {
        if (bodyBytes > this.maxBytes) {
            throw new IllegalStateException("The request body is " + bodyBytes + " bytes, over the " + this.maxBytes
                    + " bytes Gatepass agrees to sign (gatepass.body.max-size)");
        }
    }

    /**
     * Whether a content type is multipart.
     *
     * @param contentType the {@code Content-Type} header, or {@code null}
     * @return {@code true} for {@code multipart/*}
     */
    public static boolean isMultipart(@Nullable String contentType) {
        return contentType != null && contentType.stripLeading().regionMatches(true, 0, "multipart/", 0, 10);
    }

}
