package io.github.danimmll.gatepass.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.web.server.WebFilter;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.reactive.GatepassWebFilter;

/**
 * Checks passes on incoming requests in WebFlux applications. Off by default inside Spring Cloud Gateway.
 */
@AutoConfiguration(after = GatepassAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass(WebFilter.class)
@ConditionalOnBean(Gatepass.class)
@Conditional(OnInboundEnabledCondition.class)
@EnableConfigurationProperties(GatepassProperties.class)
public class GatepassReactiveAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    GatepassWebFilter gatepassWebFilter(Gatepass gatepass, GatepassProperties properties) {
        return new GatepassWebFilter(gatepass, InboundRulesFactory.create(gatepass, properties),
                properties.getInbound().getFilterOrder());
    }

}
