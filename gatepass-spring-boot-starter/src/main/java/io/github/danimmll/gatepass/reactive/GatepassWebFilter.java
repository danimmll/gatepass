package io.github.danimmll.gatepass.reactive;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.jspecify.annotations.Nullable;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.Verdict;
import io.github.danimmll.gatepass.Verification;
import io.github.danimmll.gatepass.web.InboundRules;

/**
 * Turns away WebFlux requests that do not carry a valid pass, or break one of the {@link InboundRules}, with a status
 * and an RFC 9457 body.
 *
 * <p>Runs ahead of Spring Security by default, so a rejected request never reaches your security chain or your
 * handlers. When the pass covers the body, the body is read and checked here, and handed on from memory.
 */
public class GatepassWebFilter implements WebFilter, Ordered {

    private static final byte[] EMPTY = new byte[0];

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
    public GatepassWebFilter(Gatepass gatepass, InboundRules rules, int order) {
        this.gatepass = gatepass;
        this.rules = rules;
        this.order = order;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String pathWithinApplication = request.getPath().pathWithinApplication().value();
        if (!this.rules.appliesTo(pathWithinApplication)) {
            return chain.filter(exchange);
        }
        String method = request.getMethod().name();
        String rawPath = request.getPath().value();
        // SslInfo comes from the connection itself; forwarded headers never set it.
        if (this.rules.requireTls() && request.getSslInfo() == null) {
            return reject(exchange, Verdict.NOT_TLS, method, rawPath, null);
        }
        Verification verification = this.gatepass.verify(request.getHeaders().getFirst(this.rules.headerName()),
                RequestParts.of(method, rawPath, request.getURI().getRawQuery()));
        String caller = verification.caller();
        MediaType contentType = request.getHeaders().getContentType();
        Verdict verdict = this.rules.check(verification, pathWithinApplication,
                (contentType != null) ? contentType.toString() : null);
        if (!verdict.isValid()) {
            return reject(exchange, verdict, method, rawPath, caller);
        }
        if (caller != null) {
            exchange.getAttributes().put(InboundRules.CALLER_ATTRIBUTE, caller);
        }
        if (!verification.coversBody()) {
            return chain.filter(exchange);
        }
        if (request.getHeaders().getContentLength() > this.rules.maxBodyBytes()) {
            return reject(exchange, Verdict.BODY_TOO_LARGE, method, rawPath, caller);
        }
        return DataBufferUtils.join(request.getBody(), this.rules.maxBodyBytes())
                .map(buffer -> toBytes(buffer, this.rules.maxBodyBytes()))
                .defaultIfEmpty(EMPTY)
                .map(Optional::of)
                .onErrorResume(DataBufferLimitException.class, ex -> Mono.just(Optional.empty()))
                .flatMap(body -> {
                    if (body.isEmpty()) {
                        return reject(exchange, Verdict.BODY_TOO_LARGE, method, rawPath, caller);
                    }
                    if (!verification.bodyMatches(body.get())) {
                        return reject(exchange, Verdict.BODY_MISMATCH, method, rawPath, caller);
                    }
                    return chain.filter(exchange.mutate().request(withBody(request, body.get())).build());
                });
    }

    @Override
    public int getOrder() {
        return this.order;
    }

    private Mono<Void> reject(ServerWebExchange exchange, Verdict verdict, String method, String rawPath,
            @Nullable String caller) {
        this.rules.logRejection(verdict, method, rawPath, caller);
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatusCode.valueOf(InboundRules.status(verdict)));
        response.getHeaders().setContentType(MediaType.parseMediaType(InboundRules.REJECTION_CONTENT_TYPE));
        DataBuffer body = response.bufferFactory().wrap(InboundRules.body(verdict).getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(body));
    }

    private static byte[] toBytes(DataBuffer buffer, int maxBytes) {
        try {
            // join() hands a Mono back as it is, without applying its limit.
            if (buffer.readableByteCount() > maxBytes) {
                throw new DataBufferLimitException("Body larger than " + maxBytes + " bytes");
            }
            byte[] bytes = new byte[buffer.readableByteCount()];
            buffer.read(bytes);
            return bytes;
        }
        finally {
            DataBufferUtils.release(buffer);
        }
    }

    private static ServerHttpRequest withBody(ServerHttpRequest request, byte[] body) {
        return new ServerHttpRequestDecorator(request) {

            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.defer(() -> Flux.just(DefaultDataBufferFactory.sharedInstance.wrap(body)));
            }

        };
    }

}
