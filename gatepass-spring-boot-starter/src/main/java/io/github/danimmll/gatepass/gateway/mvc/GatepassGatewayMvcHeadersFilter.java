package io.github.danimmll.gatepass.gateway.mvc;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cloud.gateway.server.mvc.common.MvcUtils;
import org.springframework.cloud.gateway.server.mvc.filter.HttpHeadersFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;

/**
 * Attaches a pass to every request Spring Cloud Gateway Server MVC proxies to an internal service, and strips whatever
 * pass header the client sent, on every route.
 *
 * <p>It runs as the last request headers filter of the proxy, once route filters such as {@code stripPrefix} have
 * produced the final path and the load balancer has chosen an instance. The query string is rebuilt exactly the way the
 * proxy rebuilds it before sending, so the pass matches what the service receives. By default only routes that went
 * through the load balancer ({@code lb://} URIs or the {@code lb()} filter) are signed.
 */
public class GatepassGatewayMvcHeadersFilter implements HttpHeadersFilter.RequestHttpHeadersFilter, Ordered {

    /** Request attribute set by {@link GatepassLoadBalancerMarker} on requests the load balancer routes. */
    static final String LOAD_BALANCED_ATTRIBUTE = GatepassGatewayMvcHeadersFilter.class.getName()
            + ".loadBalanced";

    private static final Log logger = LogFactory.getLog(GatepassGatewayMvcHeadersFilter.class);

    private final Gatepass gatepass;

    private final String headerName;

    private final List<String> routeIds;

    private final BodySigning bodySigning;

    /**
     * Creates a filter that does not sign request bodies.
     *
     * @param gatepass issues the passes
     * @param headerName the header that carries the pass
     * @param routeIds the routes that get a pass: empty for every load-balanced route, {@code *} for all
     */
    public GatepassGatewayMvcHeadersFilter(Gatepass gatepass, String headerName, List<String> routeIds) {
        this(gatepass, headerName, routeIds, BodySigning.disabled());
    }

    /**
     * Creates the filter. Body signing also needs {@link GatepassBodyBufferingFilter}.
     *
     * @param gatepass issues the passes
     * @param headerName the header that carries the pass
     * @param routeIds the routes that get a pass: empty for every load-balanced route, {@code *} for all
     * @param bodySigning whether passes cover request bodies
     * @throws io.github.danimmll.gatepass.GatepassConfigurationException if {@code gatepass} cannot issue such passes
     */
    public GatepassGatewayMvcHeadersFilter(Gatepass gatepass, String headerName, List<String> routeIds,
            BodySigning bodySigning) {
        gatepass.checkCanIssue(bodySigning);
        this.gatepass = gatepass;
        this.headerName = headerName;
        this.routeIds = List.copyOf(routeIds);
        this.bodySigning = bodySigning;
    }

    @Override
    public HttpHeaders apply(HttpHeaders input, ServerRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.putAll(input);
        // Whatever the client sent is never forwarded, signed route or not.
        headers.remove(this.headerName);
        if (!signs(request)) {
            return headers;
        }
        RequestParts parts = RequestParts.fromUri(request.method().name(), UriComponentsBuilder.fromUri(request.uri())
                .replaceQueryParams(MvcUtils.encodeQueryParams(request.params()))
                .build(true)
                .toUri());
        String pass = this.bodySigning.appliesTo(headers.getFirst(HttpHeaders.CONTENT_TYPE))
                ? this.gatepass.issue(parts, body(request, parts))
                : this.gatepass.issue(parts);
        headers.set(this.headerName, pass);
        return headers;
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }

    private boolean signs(ServerRequest request) {
        if (this.routeIds.isEmpty()) {
            return Boolean.TRUE.equals(request.attributes().get(LOAD_BALANCED_ATTRIBUTE));
        }
        if (this.routeIds.contains("*")) {
            return true;
        }
        Object routeId = request.attributes().get(MvcUtils.GATEWAY_ROUTE_ID_ATTR);
        return routeId != null && this.routeIds.contains(routeId.toString());
    }

    private byte[] body(ServerRequest request, RequestParts parts) {
        HttpServletRequest servletRequest = request.servletRequest();
        if (!(servletRequest instanceof BufferedBodyRequest buffered)) {
            throw new IllegalStateException("Signing request bodies in Spring Cloud Gateway Server MVC needs "
                    + GatepassBodyBufferingFilter.class.getSimpleName() + " to be the last servlet filter, but the"
                    + " request that reached the gateway is a " + servletRequest.getClass().getName());
        }
        byte[] body = buffered.buffer(this.bodySigning.maxBytes());
        if (body == null) {
            if (logger.isWarnEnabled()) {
                logger.warn("Refused to forward " + parts.method() + " " + parts.rawPath() + ": its body is over the "
                        + this.bodySigning.maxBytes() + " bytes Gatepass signs (gatepass.body.max-size)");
            }
            throw new ResponseStatusException(HttpStatusCode.valueOf(413),
                    "The request body is larger than this gateway agrees to sign.");
        }
        return body;
    }

}
