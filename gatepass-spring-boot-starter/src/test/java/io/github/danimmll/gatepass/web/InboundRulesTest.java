package io.github.danimmll.gatepass.web;

import java.util.List;

import org.junit.jupiter.api.Test;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.TestKeys;
import io.github.danimmll.gatepass.TestSecrets;
import io.github.danimmll.gatepass.Verdict;
import io.github.danimmll.gatepass.Verification;

import static org.assertj.core.api.Assertions.assertThat;

class InboundRulesTest {

    private static final RequestParts REQUEST = RequestParts.of("POST", "/admin/reindex", null);

    private final Gatepass gateway = Gatepass.builder().privateKey(TestKeys.GATEWAY_PRIVATE).build();

    private final Gatepass orders = Gatepass.builder().privateKey(TestKeys.ORDERS_PRIVATE).build();

    private final Gatepass hmac = Gatepass.builder().secrets(TestSecrets.CURRENT).build();

    private final Gatepass receiver = Gatepass.builder()
            .secrets(TestSecrets.CURRENT)
            .trustedService("gateway", TestKeys.GATEWAY_PUBLIC)
            .trustedService("orders", TestKeys.ORDERS_PUBLIC)
            .build();

    private final InboundRules adminForTheGatewayOnly = InboundRules.builder()
            .callerRules(List.of(new InboundRules.CallerRule(List.of("/admin/**"), List.of("gateway")),
                    new InboundRules.CallerRule(List.of("/**"), List.of("gateway", "orders"))))
            .build();

    @Test
    void theFirstRuleWhosePathMatchesDecidesWhoMayCall() {
        assertThat(check(this.adminForTheGatewayOnly, this.gateway, "/admin/reindex")).isEqualTo(Verdict.VALID);
        assertThat(check(this.adminForTheGatewayOnly, this.orders, "/admin/reindex"))
                .isEqualTo(Verdict.CALLER_NOT_ALLOWED);
        assertThat(check(this.adminForTheGatewayOnly, this.orders, "/orders/1")).isEqualTo(Verdict.VALID);
    }

    @Test
    void anHmacPassNamesNoCallerSoCallerRulesTurnItAway() {
        assertThat(check(this.adminForTheGatewayOnly, this.hmac, "/orders/1")).isEqualTo(Verdict.CALLER_NOT_ALLOWED);
    }

    @Test
    void pathsNoRuleMatchesAcceptAnyValidPass() {
        InboundRules rules = InboundRules.builder()
                .callerRules(List.of(new InboundRules.CallerRule(List.of("/admin/**"), List.of("gateway"))))
                .build();

        assertThat(check(rules, this.hmac, "/orders/1")).isEqualTo(Verdict.VALID);
    }

    @Test
    void aRejectedPassKeepsItsOwnVerdict() {
        Verification forged = this.receiver.verify("v1.nonsense", REQUEST);

        assertThat(this.adminForTheGatewayOnly.check(forged, "/admin/reindex", null)).isEqualTo(Verdict.MALFORMED);
    }

    @Test
    void requiringASignedBodyTurnsAwayPassesThatDoNotCoverItExceptForMultipart() {
        InboundRules rules = InboundRules.builder().requireSignedBody(true).build();

        Verification withoutBody = this.receiver.verify(this.hmac.issue(REQUEST), REQUEST);
        assertThat(rules.check(withoutBody, "/admin/reindex", "application/json")).isEqualTo(Verdict.BODY_NOT_SIGNED);

        Verification multipart = this.receiver.verify(this.hmac.issue(REQUEST), REQUEST);
        assertThat(rules.check(multipart, "/admin/reindex", "multipart/form-data; boundary=x"))
                .isEqualTo(Verdict.VALID);

        Verification withBody = this.receiver.verify(this.hmac.issue(REQUEST, new byte[0]), REQUEST);
        assertThat(rules.check(withBody, "/admin/reindex", null)).isEqualTo(Verdict.VALID);
    }

    @Test
    void onlyATooLargeBodyGetsSomethingOtherThanForbidden() {
        for (Verdict verdict : Verdict.values()) {
            if (verdict == Verdict.BODY_TOO_LARGE) {
                assertThat(InboundRules.status(verdict)).isEqualTo(413);
                assertThat(InboundRules.body(verdict)).isEqualTo(InboundRules.TOO_LARGE_BODY);
            }
            else if (verdict != Verdict.VALID) {
                assertThat(InboundRules.status(verdict)).as(verdict.name()).isEqualTo(403);
                assertThat(InboundRules.body(verdict)).isEqualTo(InboundRules.REJECTION_BODY);
            }
        }
    }

    @Test
    void includedPathsNeedAPassUnlessExcluded() {
        InboundRules rules = InboundRules.builder().includePaths(List.of("/internal/**")).excludePaths(List.of("/internal/ping")).build();

        assertThat(rules.appliesTo("/internal/orders")).isTrue();
        assertThat(rules.appliesTo("/internal/ping")).isFalse();
        assertThat(rules.appliesTo("/public")).isFalse();
        assertThat(InboundRules.builder().build().appliesTo("")).isTrue();
    }

    private Verdict check(InboundRules rules, Gatepass sender, String path) {
        RequestParts request = RequestParts.of("GET", path, null);
        return rules.check(this.receiver.verify(sender.issue(request), request), path, null);
    }

}
