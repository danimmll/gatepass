package io.github.danimmll.gatepass.reactive;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.TestKeys;
import io.github.danimmll.gatepass.TestSecrets;
import io.github.danimmll.gatepass.web.InboundRules;

import static org.assertj.core.api.Assertions.assertThat;

class GatepassWebFilterTest {

    private static final String PIZZA = "{\"item\":\"pizza\"}";

    private final Gatepass gatepass = Gatepass.builder()
            .secrets(TestSecrets.CURRENT)
            .trustedService("orders", TestKeys.ORDERS_PUBLIC)
            .build();

    private final GatepassWebFilter filter = filter(InboundRules.builder().build());

    private final AtomicReference<ServerWebExchange> handled = new AtomicReference<>();

    private final WebFilterChain chain = exchange -> {
        this.handled.set(exchange);
        return Mono.empty();
    };

    @Test
    void rejectsRequestsWithoutAPass() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/orders"));

        this.filter.filter(exchange, this.chain).block();

        assertThat(this.handled.get()).isNull();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getContentType()).hasToString("application/problem+json");
        assertThat(exchange.getResponse().getBodyAsString().block()).isEqualTo(InboundRules.REJECTION_BODY);
    }

    @Test
    void letsRequestsWithAValidPassThrough() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/orders/7")
                .header("X-Gatepass", this.gatepass.issue(RequestParts.of("POST", "/orders/7", null))));

        this.filter.filter(exchange, this.chain).block();

        assertThat(this.handled.get()).isNotNull();
    }

    @Test
    void theQueryStringIsPartOfThePass() {
        String pass = this.gatepass.issue(RequestParts.of("GET", "/orders", "page=1"));

        MockServerWebExchange tampered = MockServerWebExchange.from(MockServerHttpRequest.get("/orders?page=2")
                .header("X-Gatepass", pass));
        this.filter.filter(tampered, this.chain).block();
        assertThat(tampered.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        MockServerWebExchange genuine = MockServerWebExchange.from(MockServerHttpRequest.get("/orders?page=1")
                .header("X-Gatepass", pass));
        this.filter.filter(genuine, this.chain).block();
        assertThat(this.handled.get()).isSameAs(genuine);
    }

    @Test
    void aPassIsAcceptedOnce() {
        String pass = this.gatepass.issue(RequestParts.of("GET", "/orders", null));

        this.filter.filter(exchange("/orders", pass), this.chain).block();
        MockServerWebExchange replay = exchange("/orders", pass);
        this.filter.filter(replay, this.chain).block();

        assertThat(replay.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void passIsBoundToTheFullPathIncludingTheContextPath() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/shop/orders")
                .contextPath("/shop")
                .header("X-Gatepass", this.gatepass.issue(RequestParts.of("GET", "/shop/orders", null))));

        this.filter.filter(exchange, this.chain).block();

        assertThat(this.handled.get()).isNotNull();
    }

    @Test
    void excludedPathsNeedNoPass() {
        this.filter.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/actuator/health")), this.chain).block();

        assertThat(this.handled.get()).isNotNull();
    }

    @Test
    void theCallingServiceIsAvailableToTheApplication() {
        Gatepass orders = Gatepass.builder().privateKey(TestKeys.ORDERS_PRIVATE).build();

        this.filter.filter(exchange("/orders", orders.issue(RequestParts.of("GET", "/orders", null))), this.chain)
                .block();

        assertThat(this.handled.get().<String>getAttribute(InboundRules.CALLER_ATTRIBUTE)).isEqualTo("orders");
    }

    @Test
    void aSignedBodyIsCheckedAndHandedOnFromMemory() {
        MockServerWebExchange exchange = post("/orders", PIZZA,
                this.gatepass.issue(RequestParts.of("POST", "/orders", null), PIZZA.getBytes(StandardCharsets.UTF_8)));

        this.filter.filter(exchange, this.chain).block();

        assertThat(bodyOf(this.handled.get())).isEqualTo(PIZZA);
    }

    @Test
    void aBodyThatIsNotTheSignedOneIsRejected() {
        MockServerWebExchange exchange = post("/orders", "{\"item\":\"caviar\"}",
                this.gatepass.issue(RequestParts.of("POST", "/orders", null), PIZZA.getBytes(StandardCharsets.UTF_8)));

        this.filter.filter(exchange, this.chain).block();

        assertThat(this.handled.get()).isNull();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void aSignedBodyOverTheLimitGets413WhetherOrNotItsLengthIsDeclared() {
        GatepassWebFilter small = filter(InboundRules.builder().maxBodyBytes(4).build());
        byte[] body = PIZZA.getBytes(StandardCharsets.UTF_8);

        MockServerWebExchange undeclared = post("/orders", PIZZA, this.gatepass.issue(RequestParts.of("POST", "/orders", null), body));
        small.filter(undeclared, this.chain).block();
        MockServerWebExchange declared = MockServerWebExchange.from(MockServerHttpRequest.post("/orders")
                .contentLength(body.length)
                .header("X-Gatepass", this.gatepass.issue(RequestParts.of("POST", "/orders", null), body))
                .body(PIZZA));
        small.filter(declared, this.chain).block();

        assertThat(this.handled.get()).isNull();
        assertThat(undeclared.getResponse().getStatusCode()).isEqualTo(HttpStatus.CONTENT_TOO_LARGE);
        assertThat(declared.getResponse().getStatusCode()).isEqualTo(HttpStatus.CONTENT_TOO_LARGE);
        assertThat(declared.getResponse().getBodyAsString().block()).isEqualTo(InboundRules.TOO_LARGE_BODY);
    }

    @Test
    void requiringTlsLooksAtTheConnectionNotAtForwardedHeaders() {
        GatepassWebFilter tlsOnly = filter(InboundRules.builder().requireTls(true).build());

        MockServerWebExchange forwarded = MockServerWebExchange.from(MockServerHttpRequest.get("https://orders/orders")
                .header("X-Forwarded-Proto", "https")
                .header("X-Gatepass", this.gatepass.issue(RequestParts.of("GET", "/orders", null))));
        tlsOnly.filter(forwarded, this.chain).block();
        assertThat(forwarded.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        MockServerWebExchange overTls = MockServerWebExchange.from(MockServerHttpRequest.get("/orders")
                .sslInfo(new TestSslInfo())
                .header("X-Gatepass", this.gatepass.issue(RequestParts.of("GET", "/orders", null))));
        tlsOnly.filter(overTls, this.chain).block();
        assertThat(this.handled.get()).isSameAs(overTls);
    }

    private GatepassWebFilter filter(InboundRules rules) {
        return new GatepassWebFilter(this.gatepass, rules, 0);
    }

    private static MockServerWebExchange exchange(String path, String pass) {
        return MockServerWebExchange.from(MockServerHttpRequest.get(path).header("X-Gatepass", pass));
    }

    private static MockServerWebExchange post(String path, String body, String pass) {
        return MockServerWebExchange.from(MockServerHttpRequest.post(path)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Gatepass", pass)
                .body(body));
    }

    private static String bodyOf(ServerWebExchange exchange) {
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .map(buffer -> buffer.toString(StandardCharsets.UTF_8))
                .block();
    }

    private static final class TestSslInfo implements SslInfo {

        @Override
        public @Nullable String getSessionId() {
            return "test";
        }

        @Override
        public X509Certificate @Nullable [] getPeerCertificates() {
            return null;
        }

    }

}
