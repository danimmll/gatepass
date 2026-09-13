package io.github.danimmll.gatepass.it.gateway;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.Verification;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "gatepass.secrets[0]=" + GatewayBodySigningIntegrationTests.SECRET,
        "gatepass.body.enabled=true",
        "gatepass.body.max-size=64B" })
class GatewayBodySigningIntegrationTests {

    static final String SECRET = "gateway-body-secret-0123456789abcdefghij";

    private static final String PIZZA = "{\"item\":\"pizza\"}";

    private static final RecordingBackend backend = RecordingBackend.start();

    private final Gatepass service = Gatepass.builder().secrets(SECRET).build();

    @LocalServerPort
    private int port;

    @DynamicPropertySource
    static void backend(DynamicPropertyRegistry registry) {
        registry.add("test.backend-url", backend::url);
        registry.add("spring.cloud.discovery.client.simple.instances.orders[0].uri", backend::url);
    }

    @AfterAll
    static void stopBackend() {
        backend.stop();
    }

    @BeforeEach
    void clearBackend() {
        backend.clear();
    }

    @Test
    void forwardsTheBodyUntouchedWithAPassThatCoversIt() throws Exception {
        assertThat(send("POST", "/api/orders", PIZZA)).isEqualTo(200);

        RecordingBackend.Received received = backend.next();
        Verification verification = verify(received);
        assertThat(new String(received.body(), StandardCharsets.UTF_8)).isEqualTo(PIZZA);
        assertThat(verification.isValid()).isTrue();
        assertThat(verification.bodyMatches(received.body())).isTrue();
    }

    @Test
    void aRequestWithoutABodyIsCoveredToo() throws Exception {
        assertThat(send("GET", "/api/orders/1", null)).isEqualTo(200);

        assertThat(verify(backend.next()).bodyMatches(new byte[0])).isTrue();
    }

    @Test
    void aBodyTooLargeToSignIsAnswered413AndNeverForwarded() throws Exception {
        assertThat(send("POST", "/api/orders", "x".repeat(100))).isEqualTo(413);

        backend.expectNothing();
    }

    private Verification verify(RecordingBackend.Received received) {
        return this.service.verify(received.passes().get(0),
                RequestParts.of(received.method(), received.rawPath(), received.rawQuery()));
    }

    private int send(String method, String path, String body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + path))
                .header("Content-Type", "application/json")
                .method(method, (body != null) ? HttpRequest.BodyPublishers.ofString(body)
                        : HttpRequest.BodyPublishers.noBody())
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

}
