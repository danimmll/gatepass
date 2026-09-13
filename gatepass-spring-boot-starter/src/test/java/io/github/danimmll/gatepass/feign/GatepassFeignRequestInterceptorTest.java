package io.github.danimmll.gatepass.feign;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;

import feign.Request;
import feign.RequestTemplate;
import feign.Target;
import org.junit.jupiter.api.Test;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.TestSecrets;
import io.github.danimmll.gatepass.Verdict;
import io.github.danimmll.gatepass.Verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

class GatepassFeignRequestInterceptorTest {

    private final Gatepass gatepass = Gatepass.builder().secrets(TestSecrets.CURRENT).build();

    private final GatepassFeignRequestInterceptor interceptor = new GatepassFeignRequestInterceptor(this.gatepass,
            "X-Gatepass", List.of("orders"));

    @Test
    void signsThePathAndQueryTheRequestWillHaveOnceTheBaseUrlIsApplied() {
        RequestTemplate template = template("orders", "http://orders/api", Request.HttpMethod.GET, "/orders/5?expand=true");

        this.interceptor.apply(template);

        assertThat(verify(pass(template), RequestParts.of("GET", "/api/orders/5", "expand=true")).verdict())
                .isEqualTo(Verdict.VALID);
    }

    @Test
    void handlesABaseUrlWithATrailingSlash() {
        RequestTemplate template = template("orders", "http://orders:8080/api/", Request.HttpMethod.POST, "/orders");

        this.interceptor.apply(template);

        assertThat(verify(pass(template), RequestParts.of("POST", "/api/orders", null)).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void handlesAMethodMappedToTheBaseUrlItself() {
        RequestTemplate template = template("orders", "http://orders/api", Request.HttpMethod.GET, "");

        this.interceptor.apply(template);

        assertThat(verify(pass(template), RequestParts.of("GET", "/api", null)).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void usesAnAbsoluteUrlPassedAtCallTime() {
        RequestTemplate template = template("orders", "http://orders/api", Request.HttpMethod.GET, "/x");
        template.target("http://elsewhere/base");

        this.interceptor.apply(template);

        assertThat(verify(pass(template), RequestParts.of("GET", "/base/x", null)).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void signsTheBodyWhenAskedTo() {
        byte[] body = "{\"item\":\"pizza\"}".getBytes(StandardCharsets.UTF_8);
        RequestTemplate template = template("orders", "http://orders", Request.HttpMethod.POST, "/orders");
        template.header("Content-Type", "application/json");
        template.body(body, StandardCharsets.UTF_8);

        new GatepassFeignRequestInterceptor(this.gatepass, "X-Gatepass", List.of("orders"), BodySigning.upTo(1024))
                .apply(template);

        Verification verification = verify(pass(template), RequestParts.of("POST", "/orders", null));
        assertThat(verification.bodyMatches(body)).isTrue();
    }

    @Test
    void refusesToSendABodyItCannotSign() {
        RequestTemplate template = template("orders", "http://orders", Request.HttpMethod.POST, "/orders");
        template.body("{\"item\":\"pizza\"}".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        assertThatIllegalStateException().isThrownBy(() -> new GatepassFeignRequestInterceptor(this.gatepass,
                "X-Gatepass", List.of("orders"), BodySigning.upTo(4)).apply(template));
    }

    @Test
    void leavesClientsThatAreNotListedAlone() {
        RequestTemplate template = template("weather-api", "https://api.weather.example", Request.HttpMethod.GET, "/today");

        this.interceptor.apply(template);

        assertThat(template.headers()).doesNotContainKey("X-Gatepass");
    }

    @Test
    void starSignsEveryClient() {
        RequestTemplate template = template("anything", "http://anything", Request.HttpMethod.GET, "/a");

        new GatepassFeignRequestInterceptor(this.gatepass, "X-Gatepass", List.of("*")).apply(template);

        assertThat(pass(template)).isNotNull();
    }

    @Test
    void replacesAnExistingPassHeaderSoEveryRetryGetsAFreshOne() {
        RequestTemplate template = template("orders", "http://orders", Request.HttpMethod.GET, "/a");
        template.header("X-Gatepass", "stale");

        this.interceptor.apply(template);
        String first = pass(template);
        this.interceptor.apply(template);

        assertThat(template.headers().get("X-Gatepass")).hasSize(1).doesNotContain("stale", first);
    }

    private static RequestTemplate template(String name, String url, Request.HttpMethod method, String uri) {
        RequestTemplate template = new RequestTemplate();
        template.method(method);
        template.uri(uri);
        template.feignTarget(new Target.HardCodedTarget<>(Object.class, name, url));
        return template;
    }

    private static String pass(RequestTemplate template) {
        Collection<String> values = template.headers().get("X-Gatepass");
        return (values == null || values.isEmpty()) ? null : values.iterator().next();
    }

    private static Verification verify(String pass, RequestParts request) {
        return Gatepass.builder().secrets(TestSecrets.CURRENT).build().verify(pass, request);
    }

}
