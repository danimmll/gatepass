package io.github.danimmll.gatepass.it.servlet;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.it.TestCertificates;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A service that serves HTTPS itself and requires it.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "gatepass.secrets[0]=servlet-tls-secret-0123456789abcdefghij",
        "gatepass.inbound.require-tls=true",
        "test.self-url=http://localhost:1" })
class ServletTlsIntegrationTests {

    @DynamicPropertySource
    static void tls(DynamicPropertyRegistry registry) {
        registry.add("server.ssl.key-store", () -> TestCertificates.keyStore().toUri().toString());
        registry.add("server.ssl.key-store-password", () -> TestCertificates.PASSWORD);
        registry.add("server.ssl.key-store-type", () -> "PKCS12");
        registry.add("server.ssl.key-alias", () -> TestCertificates.ALIAS);
    }

    @LocalServerPort
    private int port;

    @Autowired
    private Gatepass gatepass;

    @Test
    void requestsOverTlsGetThrough() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/orders/1"))
                .header("X-Gatepass", this.gatepass.issue(RequestParts.of("GET", "/orders/1", null)))
                .build();

        HttpResponse<String> response = TestCertificates.trustingClient().send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("order 1");
    }

}
