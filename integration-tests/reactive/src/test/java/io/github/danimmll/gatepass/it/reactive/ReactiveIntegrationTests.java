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
import org.springframework.web.reactive.function.client.WebClientResponseException;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.client.GatepassExchangeFilterFunction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "gatepass.secrets[0]=reactive-integration-secret-0123456789abcdefghij")
class ReactiveIntegrationTests {

    @LocalServerPort
    private int port;

    @Autowired
    private Gatepass gatepass;

    @Autowired
    private GatepassExchangeFilterFunction gatepassFilter;

    @Test
    void webClientWithTheFilterGetsThrough() {
        WebClient client = WebClient.builder().baseUrl(baseUrl()).filter(this.gatepassFilter).build();

        assertThat(client.get().uri("/orders/{id}", "a b").retrieve().bodyToMono(String.class).block())
                .isEqualTo("order a b");
        assertThat(client.get().uri("/orders?page={page}", "2 & 3").retrieve().bodyToMono(String.class).block())
                .isEqualTo("page 2 & 3");
    }

    @Test
    void webClientWithoutTheFilterIsTurnedAway() {
        WebClient client = WebClient.builder().baseUrl(baseUrl()).build();

        assertThatExceptionOfType(WebClientResponseException.Forbidden.class)
                .isThrownBy(() -> client.get().uri("/orders/1").retrieve().bodyToMono(String.class).block());
    }

    @Test
    void directCallsWithoutAPassAreTurnedAway() throws Exception {
        HttpResponse<String> response = send("/orders/1", null);

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("only accepts internal traffic");
    }

    @Test
    void aPassIsAcceptedOnceAndForItsOwnRequestOnly() throws Exception {
        String pass = this.gatepass.issue(RequestParts.of("GET", "/orders", "page=1"));

        assertThat(send("/orders?page=2", pass).statusCode()).as("another query string").isEqualTo(403);
        assertThat(send("/orders?page=1", pass).statusCode()).as("its own request").isEqualTo(200);
        assertThat(send("/orders?page=1", pass).statusCode()).as("the same request again").isEqualTo(403);
    }

    private HttpResponse<String> send(String path, String pass) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl() + path));
        if (pass != null) {
            request.header("X-Gatepass", pass);
        }
        return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String baseUrl() {
        return "http://localhost:" + this.port;
    }

}
