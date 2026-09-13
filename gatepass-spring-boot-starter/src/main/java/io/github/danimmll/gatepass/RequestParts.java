package io.github.danimmll.gatepass;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

/**
 * The parts of a request a pass is bound to: the method, the raw path and the raw query string.
 *
 * <p>Senders and receivers must agree byte for byte, so the path and the query are taken as they go on the wire:
 * still percent-encoded, without the {@code ?} and without any fragment. An empty path is {@code "/"} and a missing
 * query string is {@code ""}.
 *
 * @param method the HTTP method, in upper case
 * @param rawPath the percent-encoded path, never empty
 * @param rawQuery the percent-encoded query string without the {@code ?}, empty when there is none
 */
public record RequestParts(String method, String rawPath, String rawQuery) {

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    /**
     * Normalizes and validates the parts.
     *
     * @param method the HTTP method, in any case
     * @param rawPath the raw path, {@code "/"} when empty
     * @param rawQuery the raw query string
     * @throws IllegalArgumentException if a part contains a line break, which would make the signed text ambiguous
     */
    public RequestParts {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(rawPath, "rawPath");
        Objects.requireNonNull(rawQuery, "rawQuery");
        method = method.toUpperCase(Locale.ROOT);
        rawPath = rawPath.isEmpty() ? "/" : rawPath;
        requireSingleLine(method, "method");
        requireSingleLine(rawPath, "path");
        requireSingleLine(rawQuery, "query string");
    }

    /**
     * Describes a request from parts a server already has apart, such as {@code getRequestURI()} and
     * {@code getQueryString()}.
     *
     * @param method the HTTP method
     * @param rawPath the raw path, or {@code null} for the root
     * @param rawQuery the raw query string, or {@code null} when there is none
     * @return the request parts
     */
    public static RequestParts of(String method, @Nullable String rawPath, @Nullable String rawQuery) {
        return new RequestParts(method, (rawPath != null) ? rawPath : "/", (rawQuery != null) ? rawQuery : "");
    }

    /**
     * Describes the request a client is about to send to this URI.
     *
     * @param method the HTTP method
     * @param uri the URI the request goes to
     * @return the request parts
     */
    public static RequestParts fromUri(String method, URI uri) {
        // HTTP clients put the ASCII form on the wire, with every non-ASCII character percent-encoded.
        return fromUrl(method, uri.toASCIIString());
    }

    /**
     * Describes the request a client is about to send to this URL or request target, such as
     * {@code http://orders:8080/a/b?x=1} or {@code /a/b?x=1}.
     *
     * @param method the HTTP method
     * @param url an absolute URL, a path with an optional query string, or {@code null} for the root
     * @return the request parts
     */
    public static RequestParts fromUrl(String method, @Nullable String url) {
        if (url == null || url.isEmpty()) {
            return new RequestParts(method, "/", "");
        }
        int start = 0;
        int schemeEnd = url.indexOf("://");
        int firstDelimiter = indexOfAny(url, "/?#", 0);
        if (schemeEnd >= 0 && (firstDelimiter < 0 || schemeEnd < firstDelimiter)) {
            start = indexOfAny(url, "/?#", schemeEnd + 3);
            if (start < 0) {
                return new RequestParts(method, "/", "");
            }
        }
        int fragment = url.indexOf('#', start);
        int end = (fragment < 0) ? url.length() : fragment;
        int question = url.indexOf('?', start);
        if (question >= 0 && question < end) {
            return new RequestParts(method, toAscii(url.substring(start, question)),
                    toAscii(url.substring(question + 1, end)));
        }
        return new RequestParts(method, toAscii(url.substring(start, end)), "");
    }

    private static int indexOfAny(String value, String characters, int from) {
        for (int i = from; i < value.length(); i++) {
            if (characters.indexOf(value.charAt(i)) >= 0) {
                return i;
            }
        }
        return -1;
    }

    /** Percent-encodes non-ASCII characters as UTF-8, the way {@link URI#toASCIIString()} does. */
    private static String toAscii(String value) {
        if (value.chars().allMatch(c -> c <= 0x7F)) {
            return value;
        }
        StringBuilder result = new StringBuilder(value.length() + 16);
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            if (b >= 0) {
                result.append((char) b);
            }
            else {
                result.append('%').append(HEX[(b >> 4) & 0xF]).append(HEX[b & 0xF]);
            }
        }
        return result.toString();
    }

    private static void requireSingleLine(String value, String name) {
        if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("The " + name + " of a request cannot contain a line break");
        }
    }

}
