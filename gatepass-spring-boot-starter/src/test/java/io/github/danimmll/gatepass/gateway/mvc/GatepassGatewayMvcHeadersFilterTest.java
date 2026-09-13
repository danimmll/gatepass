package io.github.danimmll.gatepass.gateway.mvc;

import java.nio.charset.StandardCharsets;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.server.mvc.common.MvcUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.function.ServerRequest;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.GatepassConfigurationException;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.TestKeys;
import io.github.danimmll.gatepass.TestSecrets;
import io.github.danimmll.gatepass.Verdict;
import io.github.danimmll.gatepass.Verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

class GatepassGatewayMvcHeadersFilterTest {

    private static final byte[] PIZZA = "{\"item\":\"pizza\"}".getBytes(StandardCharsets.UTF_8);

    private final Gatepass gatepass = Gatepass.builder().secrets(TestSecrets.CURRENT).build();

    @Test
    void signsLoadBalancedRequestsWithThePathAndQueryStringTheProxySends() {
        // One parameter only: the proxy rebuilds the query string from the parameter map, whose order depends on the
        // Spring Framework version. The integration tests check a real proxied query string with several.
        MockHttpServletRequest servletRequest = new MockHttpServletRequest("GET", "/orders/5");
        servletRequest.setQueryString("note=a%20b");
        servletRequest.addParameter("note", "a b");
        ServerRequest request = loadBalanced(servletRequest);

        HttpHeaders headers = filter(List.of(), BodySigning.disabled()).apply(clientHeaders(null), request);

        assertThat(headers.get("X-Gatepass")).hasSize(1);
        assertThat(headers.getFirst("Accept")).isEqualTo("application/json");
        assertThat(verify(headers, RequestParts.of("GET", "/orders/5", "note=a%20b")).verdict())
                .isEqualTo(Verdict.VALID);
    }

    @Test
    void stripsTheClientsPassFromRoutesItDoesNotSign() {
        ServerRequest request = serverRequest(new MockHttpServletRequest("GET", "/weather"));

        HttpHeaders headers = filter(List.of(), BodySigning.disabled()).apply(clientHeaders(null), request);

        assertThat(headers.get("X-Gatepass")).isNull();
        assertThat(headers.getFirst("Accept")).isEqualTo("application/json");
    }

    @Test
    void signsExactlyTheRoutesListedById() {
        GatepassGatewayMvcHeadersFilter onlyOrders = filter(List.of("orders"), BodySigning.disabled());
        ServerRequest orders = serverRequest(new MockHttpServletRequest("GET", "/orders"));
        orders.attributes().put(MvcUtils.GATEWAY_ROUTE_ID_ATTR, "orders");
        ServerRequest users = serverRequest(new MockHttpServletRequest("GET", "/users"));
        users.attributes().put(MvcUtils.GATEWAY_ROUTE_ID_ATTR, "users");
        users.attributes().put(GatepassGatewayMvcHeadersFilter.LOAD_BALANCED_ATTRIBUTE, true);

        assertThat(onlyOrders.apply(clientHeaders(null), orders).getFirst("X-Gatepass")).isNotNull();
        assertThat(onlyOrders.apply(clientHeaders(null), users).getFirst("X-Gatepass")).isNull();
        assertThat(filter(List.of("*"), BodySigning.disabled()).apply(clientHeaders(null), users).getFirst("X-Gatepass"))
                .isNotNull();
    }

    @Test
    void signsTheBodyAndLeavesItReadableForTheProxyAndItsRetries() throws Exception {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest("POST", "/orders");
        servletRequest.setContent(PIZZA);
        BufferedBodyRequest buffered = new BufferedBodyRequest(servletRequest);

        HttpHeaders headers = filter(List.of(), BodySigning.upTo(1024)).apply(clientHeaders("application/json"),
                loadBalanced(buffered));

        assertThat(verify(headers, RequestParts.of("POST", "/orders", null)).bodyMatches(PIZZA)).isTrue();
        assertThat(buffered.getInputStream().readAllBytes()).isEqualTo(PIZZA);
        assertThat(buffered.getInputStream().readAllBytes()).isEqualTo(PIZZA);
    }

    @Test
    void refusesToForwardABodyTooLargeToSign() {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest("POST", "/orders");
        servletRequest.setContent(PIZZA);

        assertThatExceptionOfType(ResponseStatusException.class)
                .isThrownBy(() -> filter(List.of(), BodySigning.upTo(4)).apply(clientHeaders("application/json"),
                        loadBalanced(new BufferedBodyRequest(servletRequest))))
                .satisfies(ex -> assertThat(ex.getStatusCode().value()).isEqualTo(413));
    }

    @Test
    void saysWhatIsMissingWhenBodiesCannotBeBuffered() {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest("POST", "/orders");
        servletRequest.setContent(PIZZA);

        assertThatIllegalStateException()
                .isThrownBy(() -> filter(List.of(), BodySigning.upTo(1024)).apply(clientHeaders("application/json"),
                        loadBalanced(servletRequest)))
                .withMessageContaining("GatepassBodyBufferingFilter");
    }

    @Test
    void leavesMultipartBodiesStreaming() {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest("POST", "/avatars");
        servletRequest.setContent(PIZZA);

        HttpHeaders headers = filter(List.of(), BodySigning.upTo(4)).apply(
                clientHeaders("multipart/form-data; boundary=x"), loadBalanced(servletRequest));

        assertThat(verify(headers, RequestParts.of("POST", "/avatars", null)).coversBody()).isFalse();
    }

    @Test
    void runsAfterEveryOtherRequestHeadersFilter() {
        assertThat(filter(List.of(), BodySigning.disabled()).getOrder()).isEqualTo(Ordered.LOWEST_PRECEDENCE);
    }

    @Test
    void aGatewayWithNothingToSignWithCannotBeCreated() {
        Gatepass receiverOnly = Gatepass.builder().trustedService("orders", TestKeys.ORDERS_PUBLIC).build();

        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> new GatepassGatewayMvcHeadersFilter(receiverOnly, "X-Gatepass", List.of()));
    }

    private GatepassGatewayMvcHeadersFilter filter(List<String> routes, BodySigning bodySigning) {
        return new GatepassGatewayMvcHeadersFilter(this.gatepass, "X-Gatepass", routes, bodySigning);
    }

    private static HttpHeaders clientHeaders(String contentType) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Gatepass", "forged-by-the-client");
        headers.add("Accept", "application/json");
        if (contentType != null) {
            headers.add(HttpHeaders.CONTENT_TYPE, contentType);
        }
        return headers;
    }

    private static ServerRequest loadBalanced(HttpServletRequest servletRequest) {
        ServerRequest request = serverRequest(servletRequest);
        request.attributes().put(GatepassGatewayMvcHeadersFilter.LOAD_BALANCED_ATTRIBUTE, true);
        return request;
    }

    private static ServerRequest serverRequest(HttpServletRequest servletRequest) {
        return ServerRequest.create(servletRequest, List.of(new StringHttpMessageConverter()));
    }

    private static Verification verify(HttpHeaders headers, RequestParts request) {
        return Gatepass.builder().secrets(TestSecrets.CURRENT).build().verify(headers.getFirst("X-Gatepass"), request);
    }

}
