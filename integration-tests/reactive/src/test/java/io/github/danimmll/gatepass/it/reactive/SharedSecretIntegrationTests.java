package io.github.danimmll.gatepass.it.reactive;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A caller that cannot sign, like a shell script, sends the secret itself.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "gatepass.mode=shared-secret",
        "gatepass.secrets[0]=" + SharedSecretIntegrationTests.CURRENT,
        "gatepass.secrets[1]=" + SharedSecretIntegrationTests.PREVIOUS })
class SharedSecretIntegrationTests {

    static final String CURRENT = "current-shared-secret-0123456789abcdefghij";

    static final String PREVIOUS = "previous-shared-secret-0123456789abcdefghij";

    @LocalServerPort
    private int port;

    @Test
    void acceptsAnyConfiguredSecretAndNothingElse() throws Exception {
        assertThat(get(CURRENT)).isEqualTo(200);
        assertThat(get(PREVIOUS)).isEqualTo(200);
        assertThat(get(CURRENT + "-nope")).isEqualTo(403);
    }

    private int get(String pass) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + "/orders/1"))
                .header("X-Gatepass", pass)
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

}
