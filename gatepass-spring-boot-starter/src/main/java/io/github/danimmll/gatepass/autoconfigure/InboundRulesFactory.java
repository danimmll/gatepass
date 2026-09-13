package io.github.danimmll.gatepass.autoconfigure;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.GatepassConfigurationException;
import io.github.danimmll.gatepass.GatepassConfigurationException.Reason;
import io.github.danimmll.gatepass.GatepassMode;
import io.github.danimmll.gatepass.web.InboundRules;

/**
 * Builds the {@link InboundRules} of the servlet and WebFlux filters from the properties, refusing combinations that
 * could never let a request through.
 */
final class InboundRulesFactory {

    private InboundRulesFactory() {
    }

    static InboundRules create(Gatepass gatepass, GatepassProperties properties) {
        GatepassProperties.Inbound inbound = properties.getInbound();
        Set<String> trusted = gatepass.trustedServices();
        List<InboundRules.CallerRule> callerRules = new ArrayList<>();
        for (int i = 0; i < inbound.getCallers().size(); i++) {
            GatepassProperties.Inbound.CallerRule rule = inbound.getCallers().get(i);
            String name = "gatepass.inbound.callers[" + i + "]";
            if (rule.getPaths().isEmpty()) {
                throw conflict(name + ".paths is empty, so the rule would never apply.");
            }
            if (rule.getServices().isEmpty()) {
                throw conflict(name + ".services is empty, so nothing could ever call " + rule.getPaths() + ".");
            }
            for (String service : rule.getServices()) {
                if (!trusted.contains(service)) {
                    throw conflict(name + ".services names '" + service + "', which is not under"
                            + " gatepass.trusted-services" + (trusted.isEmpty()
                                    ? ": there are none, and only an Ed25519 pass says which service sent it."
                                    : " " + trusted + "."));
                }
            }
            callerRules.add(new InboundRules.CallerRule(rule.getPaths(), rule.getServices()));
        }
        if (inbound.isRequireSignedBody() && gatepass.mode() == GatepassMode.SHARED_SECRET) {
            throw conflict("gatepass.inbound.require-signed-body is on, but in shared-secret mode no pass covers a"
                    + " body.");
        }
        return InboundRules.builder()
                .headerName(properties.getHeaderName())
                .includePaths(inbound.getIncludePaths())
                .excludePaths(inbound.getExcludePaths())
                .callerRules(callerRules)
                .requireTls(inbound.isRequireTls())
                .requireSignedBody(inbound.isRequireSignedBody())
                .maxBodyBytes(properties.getBody().getMaxSize().toBytes())
                .build();
    }

    private static GatepassConfigurationException conflict(String message) {
        return new GatepassConfigurationException(Reason.CONFLICTING_SETTINGS, message);
    }

}
