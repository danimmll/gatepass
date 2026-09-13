package io.github.danimmll.gatepass.autoconfigure;

import feign.RequestInterceptor;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.assertj.ApplicationContextAssertProvider;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.GatepassConfigurationException;
import io.github.danimmll.gatepass.GatepassConfigurationException.Reason;
import io.github.danimmll.gatepass.GatepassMode;
import io.github.danimmll.gatepass.InMemoryReplayGuard;
import io.github.danimmll.gatepass.ReplayGuard;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.TestKeys;
import io.github.danimmll.gatepass.TestSecrets;
import io.github.danimmll.gatepass.Verdict;
import io.github.danimmll.gatepass.client.GatepassClientHttpRequestInterceptor;
import io.github.danimmll.gatepass.client.GatepassExchangeFilterFunction;
import io.github.danimmll.gatepass.feign.GatepassFeignRequestInterceptor;
import io.github.danimmll.gatepass.gateway.GatepassGatewayFilter;
import io.github.danimmll.gatepass.reactive.GatepassWebFilter;
import io.github.danimmll.gatepass.servlet.GatepassServletFilter;

import static org.assertj.core.api.Assertions.assertThat;

class GatepassAutoConfigurationTests {

    private static final AutoConfigurations GATEPASS = AutoConfigurations.of(GatepassAutoConfiguration.class,
            GatepassServletAutoConfiguration.class, GatepassReactiveAutoConfiguration.class,
            GatepassGatewayAutoConfiguration.class, GatepassHttpClientsAutoConfiguration.class,
            GatepassFeignAutoConfiguration.class);

    private static final String SECRET = "gatepass.secrets[0]=" + TestSecrets.CURRENT;

    private static final String TRUSTS_GATEWAY = "gatepass.trusted-services.gateway[0]=" + TestKeys.GATEWAY_PUBLIC;

    private static final RequestParts REQUEST = RequestParts.of("GET", "/orders/1", null);

    private final ApplicationContextRunner plain = new ApplicationContextRunner().withConfiguration(GATEPASS);

    // The gateway is an optional dependency of the starter, so it is on this test classpath. Hide it to look like
    // an ordinary service.
    private final WebApplicationContextRunner service = new WebApplicationContextRunner()
            .withConfiguration(GATEPASS)
            .withClassLoader(new FilteredClassLoader(GlobalFilter.class));

    private final ReactiveWebApplicationContextRunner reactiveService = new ReactiveWebApplicationContextRunner()
            .withConfiguration(GATEPASS)
            .withClassLoader(new FilteredClassLoader(GlobalFilter.class));

    private final ReactiveWebApplicationContextRunner gateway = new ReactiveWebApplicationContextRunner()
            .withConfiguration(GATEPASS);

    @Test
    void failsAtStartupWithNothingToSignOrVerifyWith() {
        this.plain.run(context -> assertFailedBecause(context, Reason.NO_KEYS));
    }

    @Test
    void staysOutOfTheWayWhenDisabled() {
        this.service.withPropertyValues("gatepass.enabled=false").run(context -> assertThat(context)
                .hasNotFailed()
                .doesNotHaveBean(Gatepass.class)
                .doesNotHaveBean(GatepassServletFilter.class)
                .doesNotHaveBean(GatepassClientHttpRequestInterceptor.class));
    }

    @Test
    void buildsGatepassFromProperties() {
        this.plain.withPropertyValues(SECRET, "gatepass.mode=shared-secret").run(context -> {
            assertThat(context).hasSingleBean(Gatepass.class);
            assertThat(context.getBean(Gatepass.class).mode()).isEqualTo(GatepassMode.SHARED_SECRET);
        });
    }

    @Test
    void buildsAnEd25519GatepassFromProperties() {
        this.plain.withPropertyValues("gatepass.private-key=" + TestKeys.ORDERS_PRIVATE, TRUSTS_GATEWAY,
                "gatepass.trusted-services.users[0]=" + TestKeys.USERS_PUBLIC).run(context -> {
                    Gatepass gatepass = context.getBean(Gatepass.class);
                    assertThat(gatepass.mode()).isEqualTo(GatepassMode.ED25519);
                    assertThat(gatepass.canIssue()).isTrue();
                    assertThat(gatepass.trustedServices()).containsExactly("gateway", "users");
                });
    }

    @Test
    void anEmptyPrivateKeyCountsAsNone() {
        this.plain.withPropertyValues(SECRET, "gatepass.private-key=")
                .run(context -> assertThat(context.getBean(Gatepass.class).mode()).isEqualTo(GatepassMode.HMAC));
    }

    @Test
    void backsOffWhenTheApplicationDefinesItsOwnGatepass() {
        Gatepass own = Gatepass.builder().secrets(TestSecrets.OTHER).build();
        this.plain.withBean(Gatepass.class, () -> own)
                .run(context -> assertThat(context).hasNotFailed().getBean(Gatepass.class).isSameAs(own));
    }

    @Test
    void passesAreRememberedInMemoryByDefault() {
        this.plain.withPropertyValues(SECRET).run(context -> {
            assertThat(context).getBean(ReplayGuard.class).isInstanceOf(InMemoryReplayGuard.class);
            Gatepass gatepass = context.getBean(Gatepass.class);
            String pass = gatepass.issue(REQUEST);
            assertThat(gatepass.verify(pass, REQUEST).verdict()).isEqualTo(Verdict.VALID);
            assertThat(gatepass.verify(pass, REQUEST).verdict()).isEqualTo(Verdict.REPLAYED);
        });
    }

    @Test
    void usesTheReplayGuardTheApplicationDefines() {
        ReplayGuard sharedStore = (passId, expiresAt) -> false;
        this.plain.withPropertyValues(SECRET).withBean(ReplayGuard.class, () -> sharedStore).run(context -> {
            Gatepass gatepass = context.getBean(Gatepass.class);
            assertThat(gatepass.verify(gatepass.issue(REQUEST), REQUEST).verdict()).isEqualTo(Verdict.REPLAYED);
        });
    }

    @Test
    void replayProtectionCanBeTurnedOff() {
        this.plain.withPropertyValues(SECRET, "gatepass.replay-protection.enabled=false").run(context -> {
            Gatepass gatepass = context.getBean(Gatepass.class);
            String pass = gatepass.issue(REQUEST);
            gatepass.verify(pass, REQUEST);
            assertThat(gatepass.verify(pass, REQUEST).verdict()).isEqualTo(Verdict.VALID);
        });
    }

    @Test
    void servletServicesCheckPasses() {
        this.service.withPropertyValues(SECRET).run(context -> assertThat(context)
                .hasSingleBean(GatepassServletFilter.class)
                .doesNotHaveBean(GatepassWebFilter.class)
                .doesNotHaveBean(GatepassGatewayFilter.class));
    }

    @Test
    void inboundPropertiesReachTheFilter() {
        this.service.withPropertyValues(SECRET, "gatepass.inbound.filter-order=42")
                .run(context -> assertThat(context.getBean(GatepassServletFilter.class).getOrder()).isEqualTo(42));
    }

    @Test
    void inboundCheckCanBeTurnedOff() {
        this.service.withPropertyValues(SECRET, "gatepass.inbound.enabled=false")
                .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(GatepassServletFilter.class));
    }

    @Test
    void aServiceThatOnlyReceivesCallsNeedsNoKeyToSignWith() {
        this.service.withPropertyValues(TRUSTS_GATEWAY).run(context -> assertThat(context)
                .hasNotFailed()
                .hasSingleBean(GatepassServletFilter.class));
    }

    @Test
    void injectingAClientHookWithNothingToSignWithFailsTheStartup() {
        this.plain.withPropertyValues(TRUSTS_GATEWAY).withUserConfiguration(UsesTheRestClientHook.class)
                .run(context -> assertFailedBecause(context, Reason.CANNOT_ISSUE));
    }

    @Test
    void callerRulesNeedTheServicesTheyNameToBeTrusted() {
        this.service.withPropertyValues(SECRET, "gatepass.inbound.callers[0].paths[0]=/admin/**",
                "gatepass.inbound.callers[0].services[0]=gateway")
                .run(context -> assertFailedBecause(context, Reason.CONFLICTING_SETTINGS));
        this.service.withPropertyValues(TRUSTS_GATEWAY, "gatepass.inbound.callers[0].paths[0]=/admin/**",
                "gatepass.inbound.callers[0].services[0]=gatewya").run(context -> {
                    assertFailedBecause(context, Reason.CONFLICTING_SETTINGS);
                    assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("'gatewya'");
                });
        this.service.withPropertyValues(TRUSTS_GATEWAY, "gatepass.inbound.callers[0].paths[0]=/admin/**",
                "gatepass.inbound.callers[0].services[0]=gateway")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void aSignedBodyCannotBeRequiredInSharedSecretMode() {
        this.reactiveService.withPropertyValues(SECRET, "gatepass.mode=shared-secret",
                "gatepass.inbound.require-signed-body=true")
                .run(context -> assertFailedBecause(context, Reason.CONFLICTING_SETTINGS));
    }

    @Test
    void webFluxServicesCheckPasses() {
        this.reactiveService.withPropertyValues(SECRET).run(context -> assertThat(context)
                .hasSingleBean(GatepassWebFilter.class)
                .doesNotHaveBean(GatepassGatewayFilter.class));
    }

    @Test
    void aGatewayIssuesPassesInsteadOfCheckingThem() {
        this.gateway.withPropertyValues(SECRET).run(context -> assertThat(context)
                .hasSingleBean(GatepassGatewayFilter.class)
                .doesNotHaveBean(GatepassWebFilter.class));
    }

    @Test
    void aGatewayWithNothingToSignWithFailsToStart() {
        this.gateway.withPropertyValues(TRUSTS_GATEWAY)
                .run(context -> assertFailedBecause(context, Reason.CANNOT_ISSUE));
    }

    @Test
    void aGatewayCannotSignBodiesInSharedSecretMode() {
        this.gateway.withPropertyValues(SECRET, "gatepass.mode=shared-secret", "gatepass.body.enabled=true")
                .run(context -> assertFailedBecause(context, Reason.CONFLICTING_SETTINGS));
    }

    @Test
    void aGatewayAlsoChecksPassesWhenAskedTo() {
        this.gateway.withPropertyValues(SECRET, "gatepass.inbound.enabled=true").run(context -> assertThat(context)
                .hasSingleBean(GatepassGatewayFilter.class)
                .hasSingleBean(GatepassWebFilter.class));
    }

    @Test
    void gatewayIssuingCanBeTurnedOff() {
        this.gateway.withPropertyValues(SECRET, "gatepass.gateway.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(GatepassGatewayFilter.class));
    }

    @Test
    void clientPiecesAreReadyToInjectInAnyApplication() {
        this.plain.withPropertyValues(SECRET, "gatepass.body.enabled=true", "gatepass.body.max-size=64KB")
                .run(context -> assertThat(context)
                        .hasSingleBean(GatepassClientHttpRequestInterceptor.class)
                        .hasSingleBean(GatepassExchangeFilterFunction.class));
    }

    @Test
    void feignClientsAreNotSignedUntilNamed() {
        this.plain.withPropertyValues(SECRET)
                .run(context -> assertThat(context).doesNotHaveBean(GatepassFeignRequestInterceptor.class));
        this.plain.withPropertyValues(SECRET, "gatepass.feign.clients=orders,users")
                .run(context -> assertThat(context).hasSingleBean(GatepassFeignRequestInterceptor.class));
    }

    @Test
    void feignSupportNeedsFeign() {
        this.plain.withClassLoader(new FilteredClassLoader(RequestInterceptor.class))
                .withPropertyValues(SECRET, "gatepass.feign.clients=orders")
                .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(GatepassFeignRequestInterceptor.class));
    }

    private static void assertFailedBecause(ApplicationContextAssertProvider<?> context, Reason reason) {
        assertThat(context.getStartupFailure()).as("startup failure").isNotNull();
        assertThat(context.getStartupFailure()).rootCause()
                .isInstanceOfSatisfying(GatepassConfigurationException.class,
                        ex -> assertThat(ex.getReason()).isEqualTo(reason));
    }

    @Configuration(proxyBeanMethods = false)
    static class UsesTheRestClientHook {

        @Bean
        String ordersClient(GatepassClientHttpRequestInterceptor gatepass) {
            return "a client built with " + gatepass;
        }

    }

}
