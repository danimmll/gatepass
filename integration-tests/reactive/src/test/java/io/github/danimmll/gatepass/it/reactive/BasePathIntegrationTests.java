package io.github.danimmll.gatepass.it.reactive;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.web.reactive.function.client.WebClient;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.client.GatepassExchangeFilterFunction;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "gatepass.secrets[0]=reactive-integration-secret-0123456789abcdefghij",
        "spring.webflux.base-path=/shop" })
class BasePathIntegrationTests {

    @LocalServerPort
    private int port;

    @Autowired
    private Gatepass gatepass;

    @Autowired
    private GatepassExchangeFilterFunction gatepassFilter;

    @Test
    void passIsBoundToThePathIncludingTheBasePath() throws Exception {
        assertThat(get("/shop/orders/1", this.gatepass.issue(RequestParts.of("GET", "/shop/orders/1", null))))
                .isEqualTo(200);
        assertThat(get("/shop/orders/1", this.gatepass.issue(RequestParts.of("GET", "/orders/1", null))))
                .isEqualTo(403);
    }

    @Test
    void webClientSignsThePathItActuallyCalls() {
        WebClient client = WebClient.builder().baseUrl("http://localhost:" + this.port + "/shop")
                .filter(this.gatepassFilter).build();

        assertThat(client.get().uri("/orders/9").retrieve().bodyToMono(String.class).block()).isEqualTo("order 9");
    }

    private int get(String path, String pass) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + path))
                .header("X-Gatepass", pass)
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

}
