package io.github.danimmll.gatepass.client;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import reactor.core.publisher.Mono;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.GatepassConfigurationException;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.TestClock;
import io.github.danimmll.gatepass.TestKeys;
import io.github.danimmll.gatepass.TestSecrets;
import io.github.danimmll.gatepass.Verdict;
import io.github.danimmll.gatepass.Verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

class GatepassClientsTest {

    private static final byte[] PIZZA = "{\"item\":\"pizza\"}".getBytes(StandardCharsets.UTF_8);

    private final Gatepass gatepass = Gatepass.builder().secrets(TestSecrets.CURRENT).build();

    @Test
    void restClientInterceptorSignsTheRequestItSends() throws Exception {
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.POST,
                URI.create("http://orders/api/orders%20v2?dryRun=true"));
        request.getHeaders().set("X-Gatepass", "stale");

        HttpRequest sent = intercept(new GatepassClientHttpRequestInterceptor(this.gatepass, "X-Gatepass"), request,
                new byte[0]);

        Verification verification = verify(sent.getHeaders().getFirst("X-Gatepass"),
                RequestParts.of("POST", "/api/orders%20v2", "dryRun=true"));
        assertThat(verification.verdict()).isEqualTo(Verdict.VALID);
        assertThat(verification.coversBody()).isFalse();
    }

    @Test
    void restClientInterceptorSignsTheBodyWhenAskedTo() throws Exception {
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.POST, URI.create("http://orders/orders"));
        request.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        HttpRequest sent = intercept(new GatepassClientHttpRequestInterceptor(this.gatepass, "X-Gatepass",
                BodySigning.upTo(1024)), request, PIZZA);

        Verification verification = verify(sent.getHeaders().getFirst("X-Gatepass"), RequestParts.of("POST", "/orders", null));
        assertThat(verification.bodyMatches(PIZZA)).isTrue();
    }

    @Test
    void restClientInterceptorLeavesMultipartBodiesUnsignedAndRefusesBodiesOverTheLimit() throws Exception {
        GatepassClientHttpRequestInterceptor interceptor = new GatepassClientHttpRequestInterceptor(this.gatepass,
                "X-Gatepass", BodySigning.upTo(4));
        MockClientHttpRequest multipart = new MockClientHttpRequest(HttpMethod.POST, URI.create("http://users/avatars"));
        multipart.getHeaders().setContentType(MediaType.MULTIPART_FORM_DATA);
        MockClientHttpRequest json = new MockClientHttpRequest(HttpMethod.POST, URI.create("http://orders/orders"));
        json.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        HttpRequest sent = intercept(interceptor, multipart, PIZZA);

        assertThat(verify(sent.getHeaders().getFirst("X-Gatepass"), RequestParts.of("POST", "/avatars", null)).coversBody())
                .isFalse();
        assertThatIllegalStateException().isThrownBy(() -> intercept(interceptor, json, PIZZA))
                .withMessageContaining("gatepass.body.max-size");
    }

    @Test
    void webClientFilterSignsTheRequestItSends() {
        ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("http://orders/api/orders/5?x=1")).build();
        AtomicReference<ClientRequest> sent = new AtomicReference<>();

        new GatepassExchangeFilterFunction(this.gatepass, "X-Gatepass")
                .filter(request, req -> {
                    sent.set(req);
                    return Mono.just(ClientResponse.create(HttpStatus.OK).build());
                })
                .block();

        assertThat(verify(sent.get().headers().getFirst("X-Gatepass"), RequestParts.of("GET", "/api/orders/5", "x=1"))
                .verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void webClientFilterIssuesThePassWhenSubscribedNotWhenBuilt() {
        TestClock clock = new TestClock(Instant.parse("2026-09-13T10:00:00Z"));
        Gatepass timed = Gatepass.builder().secrets(TestSecrets.CURRENT).clock(clock).build();
        ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("http://orders/a")).build();
        AtomicReference<ClientRequest> sent = new AtomicReference<>();

        Mono<ClientResponse> response = new GatepassExchangeFilterFunction(timed, "X-Gatepass").filter(request, req -> {
            sent.set(req);
            return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        });
        clock.advance(Duration.ofMinutes(5));
        response.block();

        assertThat(timed.verify(sent.get().headers().getFirst("X-Gatepass"), RequestParts.of("GET", "/a", null))
                .verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void webClientFilterSignsTheBodyTheCodecsWrite() {
        ClientRequest request = ClientRequest.create(HttpMethod.POST, URI.create("http://orders/orders?dryRun=true"))
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body(BodyInserters.fromValue("{\"item\":\"pizza\"}"))
                .build();
        AtomicReference<org.springframework.mock.http.client.reactive.MockClientHttpRequest> written = new AtomicReference<>();

        new GatepassExchangeFilterFunction(this.gatepass, "X-Gatepass", BodySigning.upTo(1024))
                .filter(request, writeTo(written)).block();

        String body = written.get().getBodyAsString().block();
        Verification verification = verify(written.get().getHeaders().getFirst("X-Gatepass"),
                RequestParts.of("POST", "/orders", "dryRun=true"));
        assertThat(body).isEqualTo("{\"item\":\"pizza\"}");
        assertThat(verification.bodyMatches(PIZZA)).isTrue();
    }

    @Test
    void webClientFilterCoversAnEmptyBodyToo() {
        ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("http://orders/orders")).build();
        AtomicReference<org.springframework.mock.http.client.reactive.MockClientHttpRequest> written = new AtomicReference<>();

        new GatepassExchangeFilterFunction(this.gatepass, "X-Gatepass", BodySigning.upTo(1024))
                .filter(request, writeTo(written)).block();

        Verification verification = verify(written.get().getHeaders().getFirst("X-Gatepass"),
                RequestParts.of("GET", "/orders", null));
        assertThat(verification.bodyMatches(new byte[0])).isTrue();
    }

    @Test
    void webClientFilterFailsTheRequestRatherThanSendABodyUnsigned() {
        ClientRequest request = ClientRequest.create(HttpMethod.POST, URI.create("http://orders/orders"))
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body(BodyInserters.fromValue("{\"item\":\"pizza\"}"))
                .build();

        Mono<ClientResponse> response = new GatepassExchangeFilterFunction(this.gatepass, "X-Gatepass",
                BodySigning.upTo(4)).filter(request, writeTo(new AtomicReference<>()));

        assertThatIllegalStateException().isThrownBy(response::block).withMessageContaining("gatepass.body.max-size");
    }

    @Test
    void clientsWithNothingToSignWithCannotBeCreated() {
        Gatepass receiverOnly = Gatepass.builder().trustedService("orders", TestKeys.ORDERS_PUBLIC).build();

        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> new GatepassClientHttpRequestInterceptor(receiverOnly, "X-Gatepass"));
        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> new GatepassExchangeFilterFunction(receiverOnly, "X-Gatepass"));
    }

    private static HttpRequest intercept(GatepassClientHttpRequestInterceptor interceptor, MockClientHttpRequest request,
            byte[] body) throws Exception {
        AtomicReference<HttpRequest> sent = new AtomicReference<>();
        interceptor.intercept(request, body, (req, bytes) -> {
            sent.set(req);
            return new MockClientHttpResponse(new byte[0], HttpStatus.OK);
        });
        return sent.get();
    }

    /** Lets the request write itself the way the connector would, then answers 200. */
    private static ExchangeFunction writeTo(
            AtomicReference<org.springframework.mock.http.client.reactive.MockClientHttpRequest> written) {
        return req -> {
            org.springframework.mock.http.client.reactive.MockClientHttpRequest mock =
                    new org.springframework.mock.http.client.reactive.MockClientHttpRequest(req.method(), req.url());
            written.set(mock);
            return req.writeTo(mock, ExchangeStrategies.withDefaults())
                    .then(Mono.fromCallable(() -> ClientResponse.create(HttpStatus.OK).build()));
        };
    }

    private static Verification verify(String pass, RequestParts request) {
        return Gatepass.builder().secrets(TestSecrets.CURRENT).build().verify(pass, request);
    }

}
