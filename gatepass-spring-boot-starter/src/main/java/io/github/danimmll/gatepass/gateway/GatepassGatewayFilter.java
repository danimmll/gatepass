package io.github.danimmll.gatepass.gateway;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.ReactiveLoadBalancerClientFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.web.InboundRules;

/**
 * Attaches a pass to every request Spring Cloud Gateway forwards to an internal service, and strips whatever pass
 * header the client sent, on every route.
 *
 * <p>It runs right after load balancing, once route filters such as {@code StripPrefix} or {@code RewritePath} have
 * produced the final path and an instance has been chosen, so the pass is bound to exactly the request the service
 * will receive. With body signing on, the body of each signed request is read into memory, up to the configured
 * limit, and forwarded from there; a larger body is answered with {@code 413} and never forwarded unsigned.
 */
public class GatepassGatewayFilter implements GlobalFilter, Ordered {

    /** Right after the load balancer has resolved the final URL, and before the request is sent. */
    public static final int ORDER = ReactiveLoadBalancerClientFilter.LOAD_BALANCER_CLIENT_FILTER_ORDER + 1;

    private static final Log logger = LogFactory.getLog(GatepassGatewayFilter.class);

    private static final byte[] EMPTY = new byte[0];

    private final Gatepass gatepass;

    private final String headerName;

    private final List<String> routeIds;

    private final BodySigning bodySigning;

    /**
     * Creates a filter that does not sign request bodies.
     *
     * @param gatepass issues the passes
     * @param headerName the header that carries the pass
     * @param routeIds the routes that get a pass: empty for every {@code lb://} route, {@code *} for all
     */
    public GatepassGatewayFilter(Gatepass gatepass, String headerName, List<String> routeIds) {
        this(gatepass, headerName, routeIds, BodySigning.disabled());
    }

    /**
     * Creates the filter.
     *
     * @param gatepass issues the passes
     * @param headerName the header that carries the pass
     * @param routeIds the routes that get a pass: empty for every {@code lb://} route, {@code *} for all
     * @param bodySigning whether passes cover request bodies
     * @throws io.github.danimmll.gatepass.GatepassConfigurationException if {@code gatepass} cannot issue such passes
     */
    public GatepassGatewayFilter(Gatepass gatepass, String headerName, List<String> routeIds, BodySigning bodySigning) {
        gatepass.checkCanIssue(bodySigning);
        this.gatepass = gatepass;
        this.headerName = headerName;
        this.routeIds = List.copyOf(routeIds);
        this.bodySigning = bodySigning;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        URI url = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_REQUEST_URL_ATTR);
        if (route == null || url == null || !signs(route)) {
            return chain.filter(forward(exchange, request, null));
        }
        RequestParts parts = RequestParts.fromUri(request.getMethod().name(), url);
        MediaType contentType = request.getHeaders().getContentType();
        if (!this.bodySigning.appliesTo((contentType != null) ? contentType.toString() : null)) {
            return chain.filter(forward(exchange, request, this.gatepass.issue(parts)));
        }
        if (request.getHeaders().getContentLength() > this.bodySigning.maxBytes()) {
            return tooLarge(exchange, parts);
        }
        return DataBufferUtils.join(request.getBody(), this.bodySigning.maxBytesAsInt())
                .map(buffer -> toBytes(buffer, this.bodySigning.maxBytesAsInt()))
                .defaultIfEmpty(EMPTY)
                .map(Optional::of)
                .onErrorResume(DataBufferLimitException.class, ex -> Mono.just(Optional.empty()))
                .flatMap(body -> body.isPresent()
                        ? chain.filter(forward(exchange, withBody(exchange, request, body.get()),
                                this.gatepass.issue(parts, body.get())))
                        : tooLarge(exchange, parts));
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    private ServerWebExchange forward(ServerWebExchange exchange, ServerHttpRequest request, @Nullable String pass) {
        ServerHttpRequest forwarded = request.mutate().headers(headers -> replacePass(headers, pass)).build();
        return exchange.mutate().request(forwarded).build();
    }

    private void replacePass(HttpHeaders headers, @Nullable String pass) {
        // Whatever the client sent is never forwarded, signed route or not.
        headers.remove(this.headerName);
        if (pass != null) {
            headers.set(this.headerName, pass);
        }
    }

    private boolean signs(Route route) {
        if (this.routeIds.isEmpty()) {
            return "lb".equalsIgnoreCase(route.getUri().getScheme());
        }
        return this.routeIds.contains("*") || this.routeIds.contains(route.getId());
    }

    private Mono<Void> tooLarge(ServerWebExchange exchange, RequestParts parts) {
        if (logger.isWarnEnabled()) {
            logger.warn("Refused to forward " + parts.method() + " " + parts.rawPath() + ": its body is over the "
                    + this.bodySigning.maxBytes() + " bytes Gatepass signs (gatepass.body.max-size)");
        }
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.CONTENT_TOO_LARGE);
        response.getHeaders().setContentType(MediaType.parseMediaType(InboundRules.REJECTION_CONTENT_TYPE));
        DataBuffer body = response.bufferFactory().wrap(InboundRules.TOO_LARGE_BODY.getBytes(StandardCharsets.UTF_8));
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

    private static ServerHttpRequest withBody(ServerWebExchange exchange, ServerHttpRequest request, byte[] body) {
        // The response's factory is the server's own, whose buffers the routing filter forwards without copying.
        DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
        return new ServerHttpRequestDecorator(request) {

            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.defer(() -> Flux.just(bufferFactory.wrap(body)));
            }

        };
    }

}
