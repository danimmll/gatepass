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

/**
 * This service is "orders": it signs with its own private key, and trusts itself and the gateway. Only the gateway
 * may call {@code /admin/**}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "gatepass.private-key=" + ReactiveEd25519IntegrationTests.ORDERS_PRIVATE,
        "gatepass.trusted-services.orders[0]=" + ReactiveEd25519IntegrationTests.ORDERS_PUBLIC,
        "gatepass.trusted-services.gateway[0]=" + ReactiveEd25519IntegrationTests.GATEWAY_PUBLIC,
        "gatepass.inbound.callers[0].paths[0]=/admin/**",
        "gatepass.inbound.callers[0].services[0]=gateway" })
class ReactiveEd25519IntegrationTests {

    static final String ORDERS_PRIVATE = "MC4CAQAwBQYDK2VwBCIEIFVT6n9twGnPgLB2eGdcnW4SvwwGlSMT2WONhMZO2jSm";

    static final String ORDERS_PUBLIC = "MCowBQYDK2VwAyEAb8G61fNi6MCDYc9eLa5uMHhhq2vPyTlxsnWFbPOe+pk=";

    static final String GATEWAY_PRIVATE = "MC4CAQAwBQYDK2VwBCIEINM+bvg0MvLd4MiyAh4eqVjyrMj2a5AWUCAh6R5sSKN5";

    static final String GATEWAY_PUBLIC = "MCowBQYDK2VwAyEAfY5j7ro5HiLteabA14arzexLf6RXI75QlarV8XfIb1o=";

    private static final RequestParts REINDEX = RequestParts.of("GET", "/admin/reindex", null);

    @LocalServerPort
    private int port;

    @Autowired
    private Gatepass gatepass;

    @Autowired
    private GatepassExchangeFilterFunction gatepassFilter;

    @Test
    void theApplicationKnowsWhichServiceCalled() {
        WebClient client = WebClient.builder().baseUrl("http://localhost:" + this.port).filter(this.gatepassFilter).build();

        assertThat(client.get().uri("/caller").retrieve().bodyToMono(String.class).block()).isEqualTo("caller orders");
    }

    @Test
    void onlyTheGatewayMayCallAdminPaths() throws Exception {
        Gatepass gateway = Gatepass.builder().privateKey(GATEWAY_PRIVATE).build();

        assertThat(get("/admin/reindex", gateway.issue(REINDEX))).isEqualTo(200);
        assertThat(get("/admin/reindex", this.gatepass.issue(REINDEX))).isEqualTo(403);
    }

    private int get(String path, String pass) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + path))
                .header("X-Gatepass", pass)
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

}
