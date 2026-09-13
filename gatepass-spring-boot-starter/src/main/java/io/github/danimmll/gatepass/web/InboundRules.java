package io.github.danimmll.gatepass.web;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.Verdict;
import io.github.danimmll.gatepass.Verification;

/**
 * What the inbound filters check beyond the pass itself, and how they turn a request away. Shared by the servlet and
 * the WebFlux filter so both behave the same.
 */
public final class InboundRules {

    /**
     * The request attribute (servlet) or exchange attribute (WebFlux) holding the name of the calling service, set
     * for requests with a valid Ed25519 pass. Read it with {@code @RequestAttribute(InboundRules.CALLER_ATTRIBUTE)}.
     */
    public static final String CALLER_ATTRIBUTE = "io.github.danimmll.gatepass.caller";

    /**
     * The RFC 9457 body of a {@code 403}. It never says why the request was rejected: that goes to the log, where it
     * helps you and not whoever is probing.
     */
    public static final String REJECTION_BODY = "{\"type\":\"about:blank\",\"title\":\"Forbidden\",\"status\":403,"
            + "\"detail\":\"This endpoint only accepts internal traffic.\"}";

    /** The RFC 9457 body of a {@code 413}, only ever sent in answer to a genuine pass. */
    public static final String TOO_LARGE_BODY = "{\"type\":\"about:blank\",\"title\":\"Content Too Large\","
            + "\"status\":413,\"detail\":\"The request body is larger than this endpoint agrees to verify.\"}";

    /** Content type of the rejection bodies. */
    public static final String REJECTION_CONTENT_TYPE = "application/problem+json";

    private static final Log logger = LogFactory.getLog(InboundRules.class);

    private static final int MAX_LOGGED_PATH_LENGTH = 200;

    private final String headerName;

    private final List<PathPattern> includePaths;

    private final List<PathPattern> excludePaths;

    private final List<CompiledCallerRule> callerRules;

    private final boolean requireTls;

    private final boolean requireSignedBody;

    private final long maxBodyBytes;

    private InboundRules(Builder builder) {
        this.headerName = builder.headerName;
        this.includePaths = parse(builder.includePaths);
        this.excludePaths = parse(builder.excludePaths);
        this.callerRules = builder.callerRules.stream().map(CompiledCallerRule::new).toList();
        this.requireTls = builder.requireTls;
        this.requireSignedBody = builder.requireSignedBody;
        this.maxBodyBytes = builder.maxBodyBytes;
    }

    /**
     * Starts building rules. By default every path except {@code /actuator/health/**} needs a pass, from any caller,
     * over plain HTTP or TLS, with or without a signed body of up to one megabyte.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The header that carries the pass.
     *
     * @return the header name
     */
    public String headerName() {
        return this.headerName;
    }

    /**
     * Whether requests must arrive over TLS.
     *
     * @return {@code true} if plain HTTP is rejected
     */
    public boolean requireTls() {
        return this.requireTls;
    }

    /**
     * The largest body read into memory to check it against its pass.
     *
     * @return the limit, in bytes
     */
    public long maxBodyBytes() {
        return this.maxBodyBytes;
    }

    /**
     * Whether a request to this path needs a pass.
     *
     * @param pathWithinApplication the request path without the context path
     * @return {@code true} if the path is included and not excluded
     */
    public boolean appliesTo(String pathWithinApplication) {
        PathContainer path = path(pathWithinApplication);
        return matchesAny(this.includePaths, path) && !matchesAny(this.excludePaths, path);
    }

    /**
     * Applies the rules that come after the pass itself: who may call the path, and whether the body must be signed.
     * Checking the body against the pass is left to the filter, which has to read it first.
     *
     * @param verification the result of checking the pass
     * @param pathWithinApplication the request path without the context path
     * @param contentType the {@code Content-Type} of the request, or {@code null}
     * @return {@link Verdict#VALID}, or the reason the request is rejected
     */
    public Verdict check(Verification verification, String pathWithinApplication, @Nullable String contentType) {
        if (!verification.isValid()) {
            return verification.verdict();
        }
        if (!this.callerRules.isEmpty()) {
            PathContainer path = path(pathWithinApplication);
            for (CompiledCallerRule rule : this.callerRules) {
                if (matchesAny(rule.paths, path)) {
                    String caller = verification.caller();
                    if (caller == null || !rule.services.contains(caller)) {
                        return Verdict.CALLER_NOT_ALLOWED;
                    }
                    break;
                }
            }
        }
        if (this.requireSignedBody && !verification.coversBody() && !BodySigning.isMultipart(contentType)) {
            return Verdict.BODY_NOT_SIGNED;
        }
        return Verdict.VALID;
    }

    /**
     * The status a rejected request gets.
     *
     * @param verdict why the request is rejected
     * @return {@code 413} for a body that is too large, {@code 403} for everything else
     */
    public static int status(Verdict verdict) {
        return (verdict == Verdict.BODY_TOO_LARGE) ? 413 : 403;
    }

    /**
     * The body a rejected request gets.
     *
     * @param verdict why the request is rejected
     * @return {@link #TOO_LARGE_BODY} for a body that is too large, {@link #REJECTION_BODY} for everything else
     */
    public static String body(Verdict verdict) {
        return (verdict == Verdict.BODY_TOO_LARGE) ? TOO_LARGE_BODY : REJECTION_BODY;
    }

    /**
     * Logs a rejected request. Verdicts that only a genuine pass can produce are warnings, since random traffic cannot
     * trigger them; everything else is logged at debug level.
     *
     * @param verdict why the request was rejected
     * @param method the request method
     * @param rawPath the request path
     * @param caller the calling service, when the pass names one
     */
    public void logRejection(Verdict verdict, String method, String rawPath, @Nullable String caller) {
        boolean warn = verdict.requiresGenuinePass();
        if (warn ? logger.isWarnEnabled() : logger.isDebugEnabled()) {
            String message = "Rejected " + method + " " + printable(rawPath)
                    + ((caller != null) ? " from " + printable(caller) : "") + ": " + explain(verdict);
            if (warn) {
                logger.warn(message);
            }
            else {
                logger.debug(message);
            }
        }
    }

    private static String explain(Verdict verdict) {
        return switch (verdict) {
            case MISSING -> "no pass";
            case MALFORMED -> "the header does not hold a pass in the configured mode";
            case UNKNOWN_KEY -> "signed with a key this service does not have (a rotation applied on one side only?)";
            case INVALID -> "wrong key, or the signature does not match this method, path and query string";
            case EXPIRED -> "genuine pass outside max-clock-skew (replayed late, or clocks out of sync)";
            case REPLAYED -> "genuine pass used for the second time (a replay, or a client resending the same request)";
            case CALLER_NOT_ALLOWED -> "genuine pass from a caller that gatepass.inbound.callers does not allow here";
            case BODY_NOT_SIGNED -> "genuine pass that does not cover the body, and gatepass.inbound.require-signed-body is on";
            case BODY_MISMATCH -> "genuine pass, but the body is not the one it was signed for";
            case BODY_TOO_LARGE -> "genuine pass covering a body over gatepass.body.max-size";
            case NOT_TLS -> "plain HTTP, and gatepass.inbound.require-tls is on";
            case VALID -> "valid";
        };
    }

    private static String printable(String value) {
        StringBuilder result = new StringBuilder(Math.min(value.length(), MAX_LOGGED_PATH_LENGTH));
        for (int i = 0; i < value.length() && i < MAX_LOGGED_PATH_LENGTH; i++) {
            char c = value.charAt(i);
            result.append((c < 0x20 || c == 0x7F) ? '?' : c);
        }
        if (value.length() > MAX_LOGGED_PATH_LENGTH) {
            result.append("...");
        }
        return result.toString();
    }

    private static PathContainer path(String pathWithinApplication) {
        return PathContainer.parsePath(pathWithinApplication.isEmpty() ? "/" : pathWithinApplication);
    }

    private static List<PathPattern> parse(Collection<String> patterns) {
        return patterns.stream().map(PathPatternParser.defaultInstance::parse).toList();
    }

    private static boolean matchesAny(List<PathPattern> patterns, PathContainer path) {
        for (PathPattern pattern : patterns) {
            if (pattern.matches(path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Restricts who may call some paths. The first rule with a matching path decides; paths no rule matches accept
     * any valid pass.
     *
     * @param paths {@link PathPattern} expressions, relative to the context path
     * @param services the names of the trusted services allowed to call them
     */
    public record CallerRule(List<String> paths, List<String> services) {

        /**
         * Copies the lists.
         *
         * @param paths {@link PathPattern} expressions, relative to the context path
         * @param services the names of the trusted services allowed to call them
         */
        public CallerRule {
            paths = List.copyOf(paths);
            services = List.copyOf(services);
        }

    }

    private static final class CompiledCallerRule {

        private final List<PathPattern> paths;

        private final Set<String> services;

        private CompiledCallerRule(CallerRule rule) {
            this.paths = parse(rule.paths());
            this.services = Set.copyOf(rule.services());
        }

    }

    /**
     * Builds {@link InboundRules}.
     */
    public static final class Builder {

        private String headerName = "X-Gatepass";

        private List<String> includePaths = List.of("/**");

        private List<String> excludePaths = List.of("/actuator/health/**");

        private List<CallerRule> callerRules = List.of();

        private boolean requireTls;

        private boolean requireSignedBody;

        private long maxBodyBytes = BodySigning.DEFAULT_MAX_BYTES;

        private Builder() {
        }

        /**
         * Sets the header that carries the pass.
         *
         * @param headerName the header name
         * @return this builder
         */
        public Builder headerName(String headerName) {
            this.headerName = Objects.requireNonNull(headerName, "headerName");
            return this;
        }

        /**
         * Sets the paths that need a pass.
         *
         * @param includePaths {@link PathPattern} expressions, relative to the context path
         * @return this builder
         */
        public Builder includePaths(Collection<String> includePaths) {
            this.includePaths = List.copyOf(includePaths);
            return this;
        }

        /**
         * Sets the paths that never need a pass, even when included.
         *
         * @param excludePaths {@link PathPattern} expressions, relative to the context path
         * @return this builder
         */
        public Builder excludePaths(Collection<String> excludePaths) {
            this.excludePaths = List.copyOf(excludePaths);
            return this;
        }

        /**
         * Sets who may call which paths.
         *
         * @param callerRules the rules, the first matching one deciding
         * @return this builder
         */
        public Builder callerRules(Collection<CallerRule> callerRules) {
            this.callerRules = List.copyOf(callerRules);
            return this;
        }

        /**
         * Sets whether requests must arrive over TLS on their own connection. Forwarded headers do not count.
         *
         * @param requireTls {@code true} to reject plain HTTP
         * @return this builder
         */
        public Builder requireTls(boolean requireTls) {
            this.requireTls = requireTls;
            return this;
        }

        /**
         * Sets whether every pass must cover the request body. Multipart requests are exempt, since they are never
         * signed.
         *
         * @param requireSignedBody {@code true} to reject passes without a body digest
         * @return this builder
         */
        public Builder requireSignedBody(boolean requireSignedBody) {
            this.requireSignedBody = requireSignedBody;
            return this;
        }

        /**
         * Sets the largest body read into memory to check it against its pass.
         *
         * @param maxBodyBytes the limit, in bytes
         * @return this builder
         */
        public Builder maxBodyBytes(long maxBodyBytes) {
            this.maxBodyBytes = BodySigning.upTo(maxBodyBytes).maxBytes();
            return this;
        }

        /**
         * Builds the rules.
         *
         * @return the rules
         */
        public InboundRules build() {
            return new InboundRules(this);
        }

    }

}
