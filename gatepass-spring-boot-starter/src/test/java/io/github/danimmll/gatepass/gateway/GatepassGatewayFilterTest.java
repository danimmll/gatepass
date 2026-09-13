package io.github.danimmll.gatepass.gateway;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.GatepassConfigurationException;
import io.github.danimmll.gatepass.GatepassMode;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.TestKeys;
import io.github.danimmll.gatepass.TestSecrets;
import io.github.danimmll.gatepass.Verdict;
import io.github.danimmll.gatepass.Verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class GatepassGatewayFilterTest {

    private static final String PIZZA = "{\"item\":\"pizza\"}";

    private final Gatepass gatepass = Gatepass.builder().secrets(TestSecrets.CURRENT).build();

    private final AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

    private final GatewayFilterChain chain = exchange -> {
        this.forwarded.set(exchange);
        return Mono.empty();
    };

    @Test
    void signsTheFinalPathAndQueryStringOfLoadBalancedRoutes() {
        // The client asked for /api/orders/5; StripPrefix and the load balancer turned it into this URL.
        MockServerWebExchange exchange = exchange(MockServerHttpRequest.get("/api/orders/5?expand=true"),
                route("orders", "lb://orders"), "http://10.0.0.7:8080/orders/5?expand=true");

        filter(List.of()).filter(exchange, this.chain).block();

        String pass = forwardedPass();
        assertThat(verify(pass, RequestParts.of("GET", "/orders/5", "expand=true")).verdict()).isEqualTo(Verdict.VALID);
        assertThat(verify(pass, RequestParts.of("GET", "/api/orders/5", "expand=true")).verdict())
                .isEqualTo(Verdict.INVALID);
    }

    @Test
    void replacesAPassForgedByTheClient() {
        MockServerWebExchange exchange = exchange(MockServerHttpRequest.get("/orders").header("X-Gatepass", "forged",
                "and-another"), route("orders", "lb://orders"), "http://orders:8080/orders");

        filter(List.of()).filter(exchange, this.chain).block();

        List<String> passes = this.forwarded.get().getRequest().getHeaders().getValuesAsList("X-Gatepass");
        assertThat(passes).hasSize(1).doesNotContain("forged", "and-another");
    }

    @Test
    void neverSignsRoutesToUnknownHostsByDefaultButStillStripsTheHeader() {
        MockServerWebExchange exchange = exchange(MockServerHttpRequest.get("/weather").header("X-Gatepass", "forged"),
                route("weather", "https://api.weather.example"), "https://api.weather.example/weather");

        filter(List.of()).filter(exchange, this.chain).block();

        assertThat(this.forwarded.get().getRequest().getHeaders().containsHeader("X-Gatepass")).isFalse();
    }

    @Test
    void signsExactlyTheRoutesListed() {
        MockServerWebExchange listed = exchange(MockServerHttpRequest.get("/orders"),
                route("orders", "http://orders:8080"), "http://orders:8080/orders");
        MockServerWebExchange unlisted = exchange(MockServerHttpRequest.get("/users"), route("users", "lb://users"),
                "http://users:8080/users");
        GatepassGatewayFilter onlyOrders = filter(List.of("orders"));

        onlyOrders.filter(listed, this.chain).block();
        String listedPass = forwardedPass();
        onlyOrders.filter(unlisted, this.chain).block();

        assertThat(listedPass).isNotNull();
        assertThat(forwardedPass()).isNull();
    }

    @Test
    void starSignsEveryRoute() {
        MockServerWebExchange exchange = exchange(MockServerHttpRequest.get("/orders"),
                route("orders", "http://orders:8080"), "http://orders:8080/orders");

        filter(List.of("*")).filter(exchange, this.chain).block();

        assertThat(forwardedPass()).isNotNull();
    }

    @Test
    void requestsWithoutARouteAreNotSigned() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/orders")
                .header("X-Gatepass", "forged"));

        filter(List.of("*")).filter(exchange, this.chain).block();

        assertThat(forwardedPass()).isNull();
    }

    @Test
    void runsRightAfterLoadBalancing() {
        assertThat(filter(List.of()).getOrder()).isEqualTo(10151);
    }

    @Test
    void withBodySigningTheBodyIsCoveredAndForwardedUntouched() {
        MockServerWebExchange exchange = exchange(MockServerHttpRequest.post("/orders")
                .contentType(MediaType.APPLICATION_JSON).body(PIZZA), route("orders", "lb://orders"),
                "http://orders:8080/orders");

        signingBodies(1024).filter(exchange, this.chain).block();

        String body = DataBufferUtils.join(this.forwarded.get().getRequest().getBody())
                .map(buffer -> buffer.toString(StandardCharsets.UTF_8)).block();
        Verification verification = verify(forwardedPass(), RequestParts.of("POST", "/orders", null));
        assertThat(body).isEqualTo(PIZZA);
        assertThat(verification.coversBody()).isTrue();
        assertThat(verification.bodyMatches(PIZZA.getBytes(StandardCharsets.UTF_8))).isTrue();
    }

    @Test
    void aBodyTooLargeToSignIsAnswered413AndNeverForwarded() {
        MockServerWebExchange exchange = exchange(MockServerHttpRequest.post("/orders")
                .contentType(MediaType.APPLICATION_JSON).body(PIZZA), route("orders", "lb://orders"),
                "http://orders:8080/orders");

        signingBodies(4).filter(exchange, this.chain).block();

        assertThat(this.forwarded.get()).isNull();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.CONTENT_TOO_LARGE);
    }

    @Test
    void multipartBodiesAreForwardedWithoutBeingRead() {
        MockServerWebExchange exchange = exchange(MockServerHttpRequest.post("/avatars")
                .contentType(MediaType.parseMediaType("multipart/form-data; boundary=x")).body("--x--"),
                route("users", "lb://users"), "http://users:8080/avatars");

        signingBodies(4).filter(exchange, this.chain).block();

        assertThat(verify(forwardedPass(), RequestParts.of("POST", "/avatars", null)).coversBody()).isFalse();
    }

    @Test
    void aGatewayWithNothingToSignWithCannotBeCreated() {
        Gatepass receiverOnly = Gatepass.builder().trustedService("orders", TestKeys.ORDERS_PUBLIC).build();
        Gatepass sharedSecret = Gatepass.builder().mode(GatepassMode.SHARED_SECRET).secrets(TestSecrets.CURRENT).build();

        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> new GatepassGatewayFilter(receiverOnly, "X-Gatepass", List.of()))
                .satisfies(ex -> assertThat(ex.getReason()).isEqualTo(GatepassConfigurationException.Reason.CANNOT_ISSUE));
        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> new GatepassGatewayFilter(sharedSecret, "X-Gatepass", List.of(), BodySigning.upTo(10)))
                .satisfies(ex -> assertThat(ex.getReason())
                        .isEqualTo(GatepassConfigurationException.Reason.CONFLICTING_SETTINGS));
    }

    private GatepassGatewayFilter filter(List<String> routes) {
        return new GatepassGatewayFilter(this.gatepass, "X-Gatepass", routes);
    }

    private GatepassGatewayFilter signingBodies(long maxBytes) {
        return new GatepassGatewayFilter(this.gatepass, "X-Gatepass", List.of(), BodySigning.upTo(maxBytes));
    }

    private Verification verify(String pass, RequestParts request) {
        // A fresh receiver each time, so checking the same pass twice in a test is not a replay.
        return Gatepass.builder().secrets(TestSecrets.CURRENT).build().verify(pass, request);
    }

    private String forwardedPass() {
        ServerWebExchange exchange = this.forwarded.get();
        return (exchange != null) ? exchange.getRequest().getHeaders().getFirst("X-Gatepass") : null;
    }

    private static MockServerWebExchange exchange(MockServerHttpRequest.BaseBuilder<?> request, Route route,
            String requestUrl) {
        return exchange(request.build(), route, requestUrl);
    }

    private static MockServerWebExchange exchange(MockServerHttpRequest request, Route route, String requestUrl) {
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, route);
        exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_REQUEST_URL_ATTR, URI.create(requestUrl));
        return exchange;
    }

    private static Route route(String id, String uri) {
        return Route.async().id(id).uri(URI.create(uri)).predicate(exchange -> true).build();
    }

}
