package io.github.danimmll.gatepass.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.gateway.GatepassGatewayFilter;

/**
 * Attaches passes to the requests Spring Cloud Gateway forwards. Fails the startup if the gateway has no key to sign
 * them with.
 */
@AutoConfiguration(after = GatepassAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass(GlobalFilter.class)
@ConditionalOnBean(Gatepass.class)
@ConditionalOnProperty(prefix = "gatepass.gateway", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(GatepassProperties.class)
public class GatepassGatewayAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    GatepassGatewayFilter gatepassGatewayFilter(Gatepass gatepass, GatepassProperties properties) {
        return new GatepassGatewayFilter(gatepass, properties.getHeaderName(), properties.getGateway().getRoutes(),
                properties.bodySigning());
    }

}
