package io.github.danimmll.gatepass.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.ClassUtils;

/**
 * Honours {@code gatepass.inbound.enabled} when set. When it is not, checks passes everywhere except inside a
 * Spring Cloud Gateway: the gateway receives traffic from the outside world, which by definition has no pass.
 */
class OnInboundEnabledCondition extends SpringBootCondition {

    static final String GATEWAY_CLASS = "org.springframework.cloud.gateway.filter.GlobalFilter";

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        ConditionMessage.Builder message = ConditionMessage.forCondition("Gatepass inbound check");
        Boolean configured = Binder.get(context.getEnvironment())
                .bind("gatepass.inbound.enabled", Boolean.class)
                .orElse(null);
        if (configured != null) {
            return configured
                    ? ConditionOutcome.match(message.because("gatepass.inbound.enabled is true"))
                    : ConditionOutcome.noMatch(message.because("gatepass.inbound.enabled is false"));
        }
        if (ClassUtils.isPresent(GATEWAY_CLASS, context.getClassLoader())) {
            return ConditionOutcome.noMatch(message.because(
                    "Spring Cloud Gateway is present, and a gateway issues passes rather than checking them"));
        }
        return ConditionOutcome.match(message.because("this is not a Spring Cloud Gateway"));
    }

}
