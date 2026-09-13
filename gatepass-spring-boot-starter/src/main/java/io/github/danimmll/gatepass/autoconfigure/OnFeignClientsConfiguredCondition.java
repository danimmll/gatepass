package io.github.danimmll.gatepass.autoconfigure;

import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Matches when {@code gatepass.feign.clients} names at least one client.
 */
class OnFeignClientsConfiguredCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        ConditionMessage.Builder message = ConditionMessage.forCondition("Gatepass Feign clients");
        List<String> clients = Binder.get(context.getEnvironment())
                .bind("gatepass.feign.clients", Bindable.listOf(String.class))
                .orElse(List.of());
        return clients.isEmpty()
                ? ConditionOutcome.noMatch(message.because("gatepass.feign.clients is empty"))
                : ConditionOutcome.match(message.because("gatepass.feign.clients is " + clients));
    }

}
