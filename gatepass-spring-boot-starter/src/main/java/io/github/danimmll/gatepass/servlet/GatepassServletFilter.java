package io.github.danimmll.gatepass.servlet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jspecify.annotations.Nullable;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.Verdict;
import io.github.danimmll.gatepass.Verification;
import io.github.danimmll.gatepass.web.InboundRules;

/**
 * Turns away servlet requests that do not carry a valid pass, or break one of the {@link InboundRules}, with a status
 * and an RFC 9457 body.
 *
 * <p>Registered as a plain servlet filter, ahead of Spring Security by default, so a rejected request never reaches
 * your security chain or your controllers. When the pass covers the body, the body is read and checked here, and
 * handed on to the rest of the chain from memory.
 */
public class GatepassServletFilter extends OncePerRequestFilter implements Ordered {

    /**
     * Set by the servlet container on requests that arrived over TLS. Unlike {@code isSecure()}, forwarded headers
     * such as {@code X-Forwarded-Proto} cannot fake it.
     */
    static final String CIPHER_SUITE_ATTRIBUTE = "jakarta.servlet.request.cipher_suite";

    private final Gatepass gatepass;

    private final InboundRules rules;

    private final int order;

    /**
     * Creates the filter.
     *
     * @param gatepass verifies the passes
     * @param rules which paths need a pass, and what else a request must meet
     * @param order the filter order
     */
    public GatepassServletFilter(Gatepass gatepass, InboundRules rules, int order) {
        this.gatepass = gatepass;
        this.rules = rules;
        this.order = order;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !this.rules.appliesTo(pathWithinApplication(request));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String method = request.getMethod();
        String rawPath = request.getRequestURI();
        if (this.rules.requireTls() && request.getAttribute(CIPHER_SUITE_ATTRIBUTE) == null) {
            reject(response, Verdict.NOT_TLS, method, rawPath, null);
            return;
        }
        Verification verification = this.gatepass.verify(request.getHeader(this.rules.headerName()),
                RequestParts.of(method, rawPath, request.getQueryString()));
        String caller = verification.caller();
        Verdict verdict = this.rules.check(verification, pathWithinApplication(request), request.getContentType());
        if (!verdict.isValid()) {
            reject(response, verdict, method, rawPath, caller);
            return;
        }
        if (caller != null) {
            request.setAttribute(InboundRules.CALLER_ATTRIBUTE, caller);
        }
        if (!verification.coversBody()) {
            filterChain.doFilter(request, response);
            return;
        }
        byte[] body = readBody(request);
        if (body == null) {
            reject(response, Verdict.BODY_TOO_LARGE, method, rawPath, caller);
        }
        else if (!verification.bodyMatches(body)) {
            reject(response, Verdict.BODY_MISMATCH, method, rawPath, caller);
        }
        else {
            filterChain.doFilter(new CachedBodyRequest(request, body), response);
        }
    }

    @Override
    public int getOrder() {
        return this.order;
    }

    private byte @Nullable [] readBody(HttpServletRequest request) throws IOException {
        long limit = this.rules.maxBodyBytes();
        if (request.getContentLengthLong() > limit) {
            return null;
        }
        byte[] body = request.getInputStream().readNBytes((int) Math.min(limit + 1, Integer.MAX_VALUE));
        return (body.length > limit) ? null : body;
    }

    private void reject(HttpServletResponse response, Verdict verdict, String method, String rawPath,
            @Nullable String caller) throws IOException {
        this.rules.logRejection(verdict, method, rawPath, caller);
        response.setStatus(InboundRules.status(verdict));
        response.setContentType(InboundRules.REJECTION_CONTENT_TYPE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(InboundRules.body(verdict));
    }

    private static String pathWithinApplication(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String contextPath = request.getContextPath();
        return (contextPath.isEmpty() || !uri.startsWith(contextPath)) ? uri : uri.substring(contextPath.length());
    }

}
