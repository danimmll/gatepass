package io.github.danimmll.gatepass.it.gatewaymvc;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.TestKeys;
import io.github.danimmll.gatepass.Verification;
import io.github.danimmll.gatepass.it.RecordingBackend;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The gateway signs with its own private key; the service behind it only holds the gateway's public key.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "gatepass.private-key=" + TestKeys.GATEWAY_PRIVATE)
class GatewayMvcEd25519IntegrationTests {

    private static final RecordingBackend backend = RecordingBackend.start();

    private final Gatepass service = Gatepass.builder().trustedService("gateway", TestKeys.GATEWAY_PUBLIC).build();

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

    @Test
    void theServiceKnowsTheRequestCameFromTheGateway() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + "/api/orders/5?x=1")).build();

        assertThat(HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode())
                .isEqualTo(200);

        RecordingBackend.Received received = backend.next();
        Verification verification = this.service.verify(received.passes().get(0),
                RequestParts.of(received.method(), received.rawPath(), received.rawQuery()));
        assertThat(verification.isValid()).isTrue();
        assertThat(verification.caller()).isEqualTo("gateway");
    }

}
