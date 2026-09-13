package io.github.danimmll.gatepass.it.servlet;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plain HTTP with Tomcat trusting forwarded headers from local proxies: X-Forwarded-Proto fools the container, not
 * Gatepass.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "gatepass.secrets[0]=servlet-tls-secret-0123456789abcdefghij",
        "gatepass.inbound.require-tls=true",
        "gatepass.inbound.exclude-paths=/actuator/health/**,/public/**",
        "server.forward-headers-strategy=native",
        "test.self-url=http://localhost:1" })
class ServletRequireTlsIntegrationTests {

    @LocalServerPort
    private int port;

    @Autowired
    private Gatepass gatepass;

    @Test
    void aForwardedProtoHeaderConvincesTheContainerTheRequestIsSecure() throws Exception {
        assertThat(send("/public/secure", null).body()).isEqualTo("true");
    }

    @Test
    void butGatepassStillRejectsTheRequestBecauseItDidNotArriveOverTls() throws Exception {
        String pass = this.gatepass.issue(RequestParts.of("GET", "/orders/1", null));

        assertThat(send("/orders/1", pass).statusCode()).isEqualTo(403);
    }

    private HttpResponse<String> send(String path, String pass) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + path))
                .header("X-Forwarded-Proto", "https");
        if (pass != null) {
            request.header("X-Gatepass", pass);
        }
        return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

}
