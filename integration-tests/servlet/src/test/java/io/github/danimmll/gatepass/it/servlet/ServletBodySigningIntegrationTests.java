package io.github.danimmll.gatepass.it.servlet;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.TestSocketUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.client.GatepassClientHttpRequestInterceptor;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every sender signs bodies, and the service refuses any pass that does not cover one.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, properties = {
        "gatepass.secrets[0]=servlet-body-secret-0123456789abcdefghij",
        "gatepass.feign.clients=orders",
        "gatepass.body.enabled=true",
        "gatepass.body.max-size=64B",
        "gatepass.inbound.require-signed-body=true" })
class ServletBodySigningIntegrationTests {

    private static final int PORT = TestSocketUtils.findAvailableTcpPort();

    private static final String BASE_URL = "http://localhost:" + PORT;

    private static final RequestParts CREATE = RequestParts.of("POST", "/orders", null);

    @DynamicPropertySource
    static void port(DynamicPropertyRegistry registry) {
        registry.add("server.port", () -> PORT);
        registry.add("test.self-url", () -> BASE_URL);
    }

    @Autowired
    private Gatepass gatepass;

    @Autowired
    private GatepassClientHttpRequestInterceptor gatepassInterceptor;

    @Autowired
    private ServletTestApplication.OrdersClient orders;

    @Test
    void feignSignsBodiesAndEmptyBodies() {
        assertThat(this.orders.create("pizza")).isEqualTo("created pizza");
        assertThat(this.orders.order("7")).isEqualTo("order 7");
    }

    @Test
    void restClientSignsBodies() {
        assertThat(client().post().uri("/orders").contentType(MediaType.TEXT_PLAIN).body("calzone").retrieve()
                .body(String.class)).isEqualTo("created calzone");
    }

    @Test
    void formParametersSurviveTheBodyBeingCheckedFirst() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("item", "pizza");
        form.add("size", "L&XL");

        assertThat(client().post().uri("/forms").contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form)
                .retrieve().body(String.class)).isEqualTo("form pizza L&XL");
    }

    @Test
    void aBodySwappedOnTheWayIsRejected() throws Exception {
        String pass = this.gatepass.issue(CREATE, "pizza".getBytes(StandardCharsets.UTF_8));

        assertThat(post("caviar", pass)).isEqualTo(403);
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

    private RestClient client() {
        return RestClient.builder().baseUrl(BASE_URL).requestInterceptor(this.gatepassInterceptor).build();
    }

    private static int post(String body, String pass) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/orders"))
                .header("Content-Type", "text/plain")
                .header("X-Gatepass", pass)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

}
