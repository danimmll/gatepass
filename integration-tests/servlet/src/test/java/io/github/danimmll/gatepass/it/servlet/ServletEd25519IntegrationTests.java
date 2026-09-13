package io.github.danimmll.gatepass.it.servlet;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.TestSocketUtils;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * This service is "orders": it signs with its own private key, and trusts itself and the gateway. Only the gateway
 * may call {@code /admin/**}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, properties = {
        "gatepass.private-key=" + ServletEd25519IntegrationTests.ORDERS_PRIVATE,
        "gatepass.trusted-services.orders[0]=" + ServletEd25519IntegrationTests.ORDERS_PUBLIC,
        "gatepass.trusted-services.gateway[0]=" + ServletEd25519IntegrationTests.GATEWAY_PUBLIC,
        "gatepass.feign.clients=orders",
        "gatepass.inbound.callers[0].paths[0]=/admin/**",
        "gatepass.inbound.callers[0].services[0]=gateway" })
class ServletEd25519IntegrationTests {

    static final String ORDERS_PRIVATE = "MC4CAQAwBQYDK2VwBCIEIFVT6n9twGnPgLB2eGdcnW4SvwwGlSMT2WONhMZO2jSm";

    static final String ORDERS_PUBLIC = "MCowBQYDK2VwAyEAb8G61fNi6MCDYc9eLa5uMHhhq2vPyTlxsnWFbPOe+pk=";

    static final String GATEWAY_PRIVATE = "MC4CAQAwBQYDK2VwBCIEINM+bvg0MvLd4MiyAh4eqVjyrMj2a5AWUCAh6R5sSKN5";

    static final String GATEWAY_PUBLIC = "MCowBQYDK2VwAyEAfY5j7ro5HiLteabA14arzexLf6RXI75QlarV8XfIb1o=";

    static final String UNTRUSTED_PRIVATE = "MC4CAQAwBQYDK2VwBCIEIB5c+yFZ1uRzEs3iZARtA8uGgrsXuUZKb/U3XIsK2TA6";

    private static final int PORT = TestSocketUtils.findAvailableTcpPort();

    private static final String BASE_URL = "http://localhost:" + PORT;

    private static final RequestParts REINDEX = RequestParts.of("GET", "/admin/reindex", null);

    @DynamicPropertySource
    static void port(DynamicPropertyRegistry registry) {
        registry.add("server.port", () -> PORT);
        registry.add("test.self-url", () -> BASE_URL);
    }

    @Autowired
    private Gatepass gatepass;

    @Autowired
    private ServletTestApplication.OrdersClient orders;

    @Test
    void theApplicationKnowsWhichServiceCalled() {
        assertThat(this.orders.caller()).isEqualTo("caller orders");
    }

    @Test
    void theGatewayMayCallAdminPaths() throws Exception {
        Gatepass gateway = Gatepass.builder().privateKey(GATEWAY_PRIVATE).build();

        assertThat(get("/admin/reindex", gateway.issue(REINDEX))).isEqualTo(200);
    }

    @Test
    void anotherTrustedServiceMayNot() throws Exception {
        assertThat(get("/admin/reindex", this.gatepass.issue(REINDEX))).isEqualTo(403);
    }

    @Test
    void aServiceNobodyTrustsIsTurnedAwayEverywhere() throws Exception {
        Gatepass untrusted = Gatepass.builder().privateKey(UNTRUSTED_PRIVATE).build();

        assertThat(get("/orders/1", untrusted.issue(RequestParts.of("GET", "/orders/1", null)))).isEqualTo(403);
    }

    @Test
    void anHmacPassIsNotAcceptedWhenNoSecretIsConfigured() throws Exception {
        Gatepass hmac = Gatepass.builder().secrets("a-secret-this-service-does-not-have-0123456789").build();

        assertThat(get("/orders/1", hmac.issue(RequestParts.of("GET", "/orders/1", null)))).isEqualTo(403);
    }

    private static int get(String path, String pass) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + path)).header("X-Gatepass", pass).build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

}
