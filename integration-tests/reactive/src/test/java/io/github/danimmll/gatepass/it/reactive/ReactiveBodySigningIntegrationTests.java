package io.github.danimmll.gatepass.it.reactive;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.client.GatepassExchangeFilterFunction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatException;

/**
 * Every sender signs bodies, and the service refuses any pass that does not cover one.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "gatepass.secrets[0]=reactive-body-secret-0123456789abcdefghij",
        "gatepass.body.enabled=true",
        "gatepass.body.max-size=64B",
        "gatepass.inbound.require-signed-body=true" })
class ReactiveBodySigningIntegrationTests {

    private static final RequestParts CREATE = RequestParts.of("POST", "/orders", null);

    @LocalServerPort
    private int port;

    @Autowired
    private Gatepass gatepass;

    @Autowired
    private GatepassExchangeFilterFunction gatepassFilter;

    @Test
    void webClientSignsBodiesAndEmptyBodies() {
        WebClient client = client();

        assertThat(client.post().uri("/orders").contentType(MediaType.TEXT_PLAIN).bodyValue("pizza").retrieve()
                .bodyToMono(String.class).block()).isEqualTo("created pizza");
        assertThat(client.get().uri("/orders/1").retrieve().bodyToMono(String.class).block()).isEqualTo("order 1");
    }

    @Test
    void webClientFailsTheRequestRatherThanSendABodyItCannotSign() {
        assertThatException()
                .isThrownBy(() -> client().post().uri("/orders").contentType(MediaType.TEXT_PLAIN)
                        .bodyValue("x".repeat(100)).retrieve().bodyToMono(String.class).block())
                .satisfies(ex -> assertThat(ex).hasStackTraceContaining("gatepass.body.max-size"));
    }

    @Test
    void aBodySwappedOnTheWayIsRejected() throws Exception {
        assertThat(post("caviar", this.gatepass.issue(CREATE, "pizza".getBytes(StandardCharsets.UTF_8)))).isEqualTo(403);
    }

    @Test
    void aPassThatDoesNotCoverTheBodyIsRejected() throws Exception {
        assertThat(post("pizza", this.gatepass.issue(CREATE))).isEqualTo(403);
    }

    @Test
    void aSignedBodyOverTheLimitGets413() throws Exception {
        String body = "x".repeat(100);

        assertThat(post(body, this.gatepass.issue(CREATE, body.getBytes(StandardCharsets.UTF_8)))).isEqualTo(413);
    }

    private WebClient client() {
        return WebClient.builder().baseUrl("http://localhost:" + this.port).filter(this.gatepassFilter).build();
    }

    private int post(String body, String pass) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + "/orders"))
                .header("Content-Type", "text/plain")
                .header("X-Gatepass", pass)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

}
