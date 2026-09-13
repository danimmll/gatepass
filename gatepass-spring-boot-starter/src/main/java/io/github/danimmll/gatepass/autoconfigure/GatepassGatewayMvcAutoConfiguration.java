package io.github.danimmll.gatepass.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.gateway.mvc.GatepassBodyBufferingFilter;
import io.github.danimmll.gatepass.gateway.mvc.GatepassGatewayMvcHeadersFilter;
import io.github.danimmll.gatepass.gateway.mvc.GatepassLoadBalancerMarker;

/**
 * Attaches passes to the requests Spring Cloud Gateway Server MVC proxies. Fails the startup if the gateway has no key
 * to sign them with.
 */
@AutoConfiguration(after = GatepassAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(name = OnInboundEnabledCondition.GATEWAY_MVC_CLASS)
@ConditionalOnBean(Gatepass.class)
@ConditionalOnProperty(prefix = "gatepass.gateway", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(GatepassProperties.class)
public class GatepassGatewayMvcAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    GatepassGatewayMvcHeadersFilter gatepassGatewayMvcHeadersFilter(Gatepass gatepass, GatepassProperties properties) {
        return new GatepassGatewayMvcHeadersFilter(gatepass, properties.getHeaderName(),
                properties.getGateway().getRoutes(), properties.bodySigning());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "gatepass.body", name = "enabled", havingValue = "true")
    GatepassBodyBufferingFilter gatepassBodyBufferingFilter() {
        return new GatepassBodyBufferingFilter();
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.cloud.client.loadbalancer.LoadBalancerLifecycle")
    static class LoadBalancerMarkerConfiguration {

        @Bean
        @ConditionalOnMissingBean
        GatepassLoadBalancerMarker gatepassLoadBalancerMarker() {
            return new GatepassLoadBalancerMarker();
        }

    }

}
