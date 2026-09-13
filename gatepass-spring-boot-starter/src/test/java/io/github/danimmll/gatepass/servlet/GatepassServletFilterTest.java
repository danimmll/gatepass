package io.github.danimmll.gatepass.servlet;

import java.nio.charset.StandardCharsets;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.TestKeys;
import io.github.danimmll.gatepass.TestSecrets;
import io.github.danimmll.gatepass.web.InboundRules;

import static org.assertj.core.api.Assertions.assertThat;

class GatepassServletFilterTest {

    private static final byte[] PIZZA = "{\"item\":\"pizza\"}".getBytes(StandardCharsets.UTF_8);

    private final Gatepass gatepass = Gatepass.builder()
            .secrets(TestSecrets.CURRENT)
            .trustedService("orders", TestKeys.ORDERS_PUBLIC)
            .trustedService("users", TestKeys.USERS_PUBLIC)
            .build();

    private final Gatepass orders = Gatepass.builder().privateKey(TestKeys.ORDERS_PRIVATE).build();

    private final GatepassServletFilter filter = filter(InboundRules.builder().build());

    @Test
    void rejectsRequestsWithoutAPass() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        this.filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNull();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(response.getContentAsString()).isEqualTo(InboundRules.REJECTION_BODY);
    }

    @Test
    void letsRequestsWithAValidPassThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader("X-Gatepass", this.gatepass.issue(RequestParts.of("GET", "/orders", null)));
        MockFilterChain chain = new MockFilterChain();

        this.filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isSameAs(request);
    }

    @Test
    void rejectsAPassIssuedForAnotherMethod() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/orders/1");
        request.addHeader("X-Gatepass", this.gatepass.issue(RequestParts.of("GET", "/orders/1", null)));

        assertThat(run(this.filter, request).getStatus()).isEqualTo(403);
    }

    @Test
    void theQueryStringIsPartOfThePass() throws Exception {
        String pass = this.gatepass.issue(RequestParts.of("GET", "/orders", "page=1"));

        MockHttpServletRequest tampered = new MockHttpServletRequest("GET", "/orders");
        tampered.setQueryString("page=2");
        tampered.addHeader("X-Gatepass", pass);
        assertThat(run(this.filter, tampered).getStatus()).isEqualTo(403);

        MockHttpServletRequest genuine = new MockHttpServletRequest("GET", "/orders");
        genuine.setQueryString("page=1");
        genuine.addHeader("X-Gatepass", pass);
        assertThat(run(this.filter, genuine).getStatus()).isEqualTo(200);
    }

    @Test
    void aPassIsAcceptedOnce() throws Exception {
        String pass = this.gatepass.issue(RequestParts.of("GET", "/orders", null));

        assertThat(run(this.filter, get("/orders", pass)).getStatus()).isEqualTo(200);
        assertThat(run(this.filter, get("/orders", pass)).getStatus()).isEqualTo(403);
    }

    @Test
    void passIsBoundToTheFullPathIncludingTheContextPath() throws Exception {
        MockHttpServletRequest request = get("/shop/orders", this.gatepass.issue(RequestParts.of("GET", "/shop/orders", null)));
        request.setContextPath("/shop");

        assertThat(run(this.filter, request).getStatus()).isEqualTo(200);
    }

    @Test
    void excludedPathsNeedNoPass() throws Exception {
        for (String path : List.of("/actuator/health", "/actuator/health/liveness")) {
            assertThat(run(this.filter, new MockHttpServletRequest("GET", path)).getStatus()).as(path).isEqualTo(200);
        }
        assertThat(run(this.filter, new MockHttpServletRequest("GET", "/actuator/env")).getStatus()).isEqualTo(403);
    }

    @Test
    void pathRulesAreRelativeToTheContextPath() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/shop/actuator/health");
        request.setContextPath("/shop");

        assertThat(run(this.filter, request).getStatus()).isEqualTo(200);
    }

    @Test
    void onlyIncludedPathsNeedAPass() throws Exception {
        GatepassServletFilter internalOnly = filter(InboundRules.builder()
                .includePaths(List.of("/internal/**"))
                .excludePaths(List.of())
                .build());

        assertThat(run(internalOnly, new MockHttpServletRequest("GET", "/public")).getStatus()).isEqualTo(200);
        assertThat(run(internalOnly, new MockHttpServletRequest("GET", "/internal/x")).getStatus()).isEqualTo(403);
    }

    @Test
    void theCallingServiceIsAvailableToTheApplication() throws Exception {
        MockHttpServletRequest request = get("/orders", this.orders.issue(RequestParts.of("GET", "/orders", null)));
        MockFilterChain chain = new MockFilterChain();

        this.filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest().getAttribute(InboundRules.CALLER_ATTRIBUTE)).isEqualTo("orders");
    }

    @Test
    void callerRulesTurnAwayServicesThatMayNotCallAPath() throws Exception {
        GatepassServletFilter adminForUsersOnly = filter(InboundRules.builder()
                .callerRules(List.of(new InboundRules.CallerRule(List.of("/admin/**"), List.of("users"))))
                .build());
        MockHttpServletRequest request = get("/admin/reindex",
                this.orders.issue(RequestParts.of("GET", "/admin/reindex", null)));

        assertThat(run(adminForUsersOnly, request).getStatus()).isEqualTo(403);
    }

    @Test
    void aSignedBodyIsCheckedAndHandedOnFromMemory() throws Exception {
        MockHttpServletRequest request = post("/orders", "application/json", PIZZA,
                this.gatepass.issue(RequestParts.of("POST", "/orders", null), PIZZA));
        MockFilterChain chain = new MockFilterChain();

        this.filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest forwarded = (HttpServletRequest) chain.getRequest();
        assertThat(forwarded).isNotSameAs(request);
        assertThat(forwarded.getInputStream().readAllBytes()).isEqualTo(PIZZA);
        assertThat(forwarded.getReader().readLine()).isEqualTo("{\"item\":\"pizza\"}");
    }

    @Test
    void aBodyThatIsNotTheSignedOneIsRejected() throws Exception {
        byte[] caviar = "{\"item\":\"caviar\"}".getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = post("/orders", "application/json", caviar,
                this.gatepass.issue(RequestParts.of("POST", "/orders", null), PIZZA));

        assertThat(run(this.filter, request).getStatus()).isEqualTo(403);
    }

    @Test
    void aSignedBodyOverTheLimitGets413() throws Exception {
        GatepassServletFilter small = filter(InboundRules.builder().maxBodyBytes(4).build());
        MockHttpServletRequest request = post("/orders", "application/json", PIZZA,
                this.gatepass.issue(RequestParts.of("POST", "/orders", null), PIZZA));

        MockHttpServletResponse response = run(small, request);

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentAsString()).isEqualTo(InboundRules.TOO_LARGE_BODY);
    }

    @Test
    void formParametersSurviveTheBodyBeingReadFirst() throws Exception {
        byte[] form = "name=pizza&size=L%26XL&name=calzone&empty=".getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = post("/orders", "application/x-www-form-urlencoded", form,
                this.gatepass.issue(RequestParts.of("POST", "/orders", "dryRun=true"), form));
        request.setQueryString("dryRun=true");
        request.addParameter("dryRun", "true"); // what the container parses from the query string
        MockFilterChain chain = new MockFilterChain();

        this.filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest forwarded = (HttpServletRequest) chain.getRequest();
        assertThat(forwarded.getParameter("dryRun")).isEqualTo("true");
        assertThat(forwarded.getParameterValues("name")).containsExactly("pizza", "calzone");
        assertThat(forwarded.getParameter("size")).isEqualTo("L&XL");
        assertThat(forwarded.getParameter("empty")).isEmpty();
        assertThat(forwarded.getParameterMap()).containsOnlyKeys("dryRun", "name", "size", "empty");
    }

    @Test
    void requiringASignedBodyTurnsAwayPassesThatDoNotCoverIt() throws Exception {
        GatepassServletFilter strict = filter(InboundRules.builder().requireSignedBody(true).build());
        MockHttpServletRequest request = post("/orders", "application/json", PIZZA,
                this.gatepass.issue(RequestParts.of("POST", "/orders", null)));

        assertThat(run(strict, request).getStatus()).isEqualTo(403);
    }

    @Test
    void requiringTlsLooksAtTheConnectionNotAtForwardedHeaders() throws Exception {
        GatepassServletFilter tlsOnly = filter(InboundRules.builder().requireTls(true).build());

        MockHttpServletRequest plain = get("/orders", this.gatepass.issue(RequestParts.of("GET", "/orders", null)));
        plain.setSecure(true); // what X-Forwarded-Proto: https makes a container believe
        assertThat(run(tlsOnly, plain).getStatus()).isEqualTo(403);

        MockHttpServletRequest overTls = get("/orders", this.gatepass.issue(RequestParts.of("GET", "/orders", null)));
        overTls.setAttribute(GatepassServletFilter.CIPHER_SUITE_ATTRIBUTE, "TLS_AES_256_GCM_SHA384");
        assertThat(run(tlsOnly, overTls).getStatus()).isEqualTo(200);
    }

    private GatepassServletFilter filter(InboundRules rules) {
        return new GatepassServletFilter(this.gatepass, rules, 0);
    }

    private static MockHttpServletRequest get(String path, String pass) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.addHeader("X-Gatepass", pass);
        return request;
    }

    private static MockHttpServletRequest post(String path, String contentType, byte[] body, String pass) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.setContentType(contentType);
        request.setCharacterEncoding("UTF-8");
        request.setContent(body);
        request.addHeader("X-Gatepass", pass);
        return request;
    }

    private static MockHttpServletResponse run(GatepassServletFilter filter, MockHttpServletRequest request)
            throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

}
