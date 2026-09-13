package io.github.danimmll.gatepass.it.servlet;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import feign.FeignException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.TestSocketUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.client.GatepassClientHttpRequestInterceptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, properties = {
        "gatepass.secrets[0]=" + ServletIntegrationTests.SECRET,
        "gatepass.feign.clients=orders,prefixed" })
class ServletIntegrationTests {

    static final String SECRET = "servlet-integration-secret-0123456789abcdefghij";

    // Feign resolves its URLs while the context starts, so the port has to be known before that.
    private static final int PORT = TestSocketUtils.findAvailableTcpPort();

    private static final String BASE_URL = "http://localhost:" + PORT;

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

    @Autowired
    private ServletTestApplication.PrefixedClient prefixed;

    @Autowired
    private ServletTestApplication.ThirdPartyClient thirdParty;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void directCallsWithoutAPassAreTurnedAway() throws Exception {
        HttpResponse<String> response = get("/orders/1", null);

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.headers().firstValue("Content-Type")).hasValueSatisfying(
                contentType -> assertThat(contentType).startsWith("application/problem+json"));
        assertThat(response.body()).contains("only accepts internal traffic");
    }

    @Test
    void restClientWithTheInterceptorGetsThrough() {
        RestClient client = RestClient.builder().baseUrl(BASE_URL).requestInterceptor(this.gatepassInterceptor).build();

        assertThat(client.get().uri("/orders/{id}", "a b").retrieve().body(String.class)).isEqualTo("order a b");
        assertThat(client.get().uri("/orders?page={page}", "2 & 3").retrieve().body(String.class))
                .isEqualTo("page 2 & 3");
    }

    @Test
    void restClientWithoutTheInterceptorIsTurnedAway() {
        RestClient client = RestClient.builder().baseUrl(BASE_URL).build();

        assertThatExceptionOfType(HttpClientErrorException.Forbidden.class)
                .isThrownBy(() -> client.get().uri("/orders/1").retrieve().body(String.class));
    }

    @Test
    void feignClientsNamedInTheConfigurationGetThrough() {
        assertThat(this.orders.order("7")).isEqualTo("order 7");
        assertThat(this.orders.page("2 & 3")).isEqualTo("page 2 & 3");
        assertThat(this.orders.create("pizza")).isEqualTo("created pizza");
    }

    @Test
    void feignClientWithAPathPrefixSignsTheFullPath() {
        assertThat(this.prefixed.root()).isEqualTo("api root");
    }

    @Test
    void feignClientsNotNamedNeverSendAPass() {
        assertThatExceptionOfType(FeignException.Forbidden.class).isThrownBy(() -> this.thirdParty.order("7"));
    }

    @Test
    void aPassIsAcceptedOnceAndForItsOwnRequestOnly() throws Exception {
        String pass = this.gatepass.issue(RequestParts.of("GET", "/orders/1", null));

        assertThat(get("/orders/2", pass).statusCode()).as("another path").isEqualTo(403);
        assertThat(get("/orders/1", pass).statusCode()).as("its own request").isEqualTo(200);
        assertThat(get("/orders/1", pass).statusCode()).as("the same request again").isEqualTo(403);
    }

    @Test
    void theQueryStringCannotBeChanged() throws Exception {
        String pass = this.gatepass.issue(RequestParts.of("GET", "/orders", "page=1"));

        assertThat(get("/orders?page=2", pass).statusCode()).isEqualTo(403);
    }

    @Test
    void healthChecksNeedNoPass() throws Exception {
        assertThat(get("/actuator/health", null).statusCode()).isEqualTo(200);
    }

    @Test
    void theCheckRunsBeforeSpringSecurity() throws Exception {
        assertThat(get("/secured", null).statusCode()).as("no pass: Gatepass answers").isEqualTo(403);
        assertThat(get("/secured", this.gatepass.issue(RequestParts.of("GET", "/secured", null))).statusCode())
                .as("valid pass: Spring Security answers").isEqualTo(401);
    }

    private HttpResponse<String> get(String path, String pass) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(BASE_URL + path)).GET();
        if (pass != null) {
            request.header("X-Gatepass", pass);
        }
        return this.http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

}
