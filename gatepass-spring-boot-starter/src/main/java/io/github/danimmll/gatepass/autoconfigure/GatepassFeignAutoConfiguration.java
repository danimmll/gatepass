package io.github.danimmll.gatepass.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.feign.GatepassFeignRequestInterceptor;

/**
 * Attaches passes to the Feign clients listed in {@code gatepass.feign.clients}. Does nothing until at least one is
 * listed, and fails the startup if one is listed but there is no key to sign with.
 */
@AutoConfiguration(after = GatepassAutoConfiguration.class)
@ConditionalOnClass(name = "feign.RequestInterceptor")
@ConditionalOnBean(Gatepass.class)
@Conditional(OnFeignClientsConfiguredCondition.class)
@EnableConfigurationProperties(GatepassProperties.class)
public class GatepassFeignAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    GatepassFeignRequestInterceptor gatepassFeignRequestInterceptor(Gatepass gatepass, GatepassProperties properties) {
        return new GatepassFeignRequestInterceptor(gatepass, properties.getHeaderName(),
                properties.getFeign().getClients(), properties.bodySigning());
    }

}
