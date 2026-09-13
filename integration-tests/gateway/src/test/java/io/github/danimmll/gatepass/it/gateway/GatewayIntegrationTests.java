package io.github.danimmll.gatepass.it.gateway;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.Verdict;
import io.github.danimmll.gatepass.it.RecordingBackend;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "gatepass.secrets[0]=" + GatewayIntegrationTests.SECRET)
class GatewayIntegrationTests {

    static final String SECRET = "gateway-integration-secret-0123456789abcdefghij";

    private static final RecordingBackend backend = RecordingBackend.start();

    /** What the service behind the gateway would use to check the pass. */
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
    void forwardsAPassBoundToThePathAndQueryStringTheServiceReceives() throws Exception {
        assertThat(send("GET", "/api/orders/5?expand=true&note=a%20b%2Bc+d", "forged-by-the-client")).isEqualTo(200);

        RecordingBackend.Received received = backend.next();
        assertThat(received.rawPath()).isEqualTo("/orders/5");
        assertThat(received.rawQuery()).isEqualTo("expand=true&note=a%20b%2Bc+d");
        assertThat(received.passes()).hasSize(1);
        assertThat(verify(received).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void percentEncodedPathsArriveSignedAsTheyAreSent() throws Exception {
        assertThat(send("GET", "/api/orders/a%20b/caf%C3%A9", null)).isEqualTo(200);

        assertThat(verify(backend.next()).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void passIsBoundToTheMethod() throws Exception {
        assertThat(send("POST", "/api/orders", null)).isEqualTo(200);

        RecordingBackend.Received received = backend.next();
        String pass = received.passes().get(0);
        assertThat(this.service.verify(pass, RequestParts.of("DELETE", "/orders", null)).verdict()).isEqualTo(Verdict.INVALID);
        assertThat(this.service.verify(pass, RequestParts.of("POST", "/orders", null)).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void aRetriedRequestCarriesAFreshPassEachTime() throws Exception {
        backend.respondNextWith(503);

        assertThat(send("GET", "/api/flaky/1", null)).isEqualTo(200);

        RecordingBackend.Received first = backend.next();
        RecordingBackend.Received retry = backend.next();
        assertThat(retry.passes()).isNotEqualTo(first.passes());
        assertThat(verify(first).verdict()).isEqualTo(Verdict.VALID);
        assertThat(verify(retry).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void routesOutsideTheSystemNeverGetAPassNorTheOneTheClientSent() throws Exception {
        assertThat(send("GET", "/external/weather", "forged-by-the-client")).isEqualTo(200);

        assertThat(backend.next().passes()).isEmpty();
    }

    @Test
    void theGatewayItselfAsksNobodyForAPass() throws Exception {
        assertThat(send("GET", "/api/orders/1", null)).isEqualTo(200);
    }

    private io.github.danimmll.gatepass.Verification verify(RecordingBackend.Received received) {
        return this.service.verify(received.passes().get(0),
                RequestParts.of(received.method(), received.rawPath(), received.rawQuery()));
    }

    private int send(String method, String path, String clientPass) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + path))
                .method(method, HttpRequest.BodyPublishers.noBody());
        if (clientPass != null) {
            request.header("X-Gatepass", clientPass);
        }
        return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

}
