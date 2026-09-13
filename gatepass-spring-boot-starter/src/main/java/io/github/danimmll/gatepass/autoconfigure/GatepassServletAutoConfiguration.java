package io.github.danimmll.gatepass.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.servlet.GatepassServletFilter;

/**
 * Checks passes on incoming requests in servlet applications.
 */
@AutoConfiguration(after = GatepassAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(OncePerRequestFilter.class)
@ConditionalOnBean(Gatepass.class)
@Conditional(OnInboundEnabledCondition.class)
@EnableConfigurationProperties(GatepassProperties.class)
public class GatepassServletAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    GatepassServletFilter gatepassServletFilter(Gatepass gatepass, GatepassProperties properties) {
        return new GatepassServletFilter(gatepass, InboundRulesFactory.create(gatepass, properties),
                properties.getInbound().getFilterOrder());
    }

}
