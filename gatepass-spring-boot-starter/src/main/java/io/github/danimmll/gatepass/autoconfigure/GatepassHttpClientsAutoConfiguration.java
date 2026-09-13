package io.github.danimmll.gatepass.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.client.GatepassClientHttpRequestInterceptor;
import io.github.danimmll.gatepass.client.GatepassExchangeFilterFunction;

/**
 * Makes the {@code RestClient} interceptor and the {@code WebClient} filter available for injection. Neither is
 * applied to any client on its own: only the clients you add them to send a pass.
 *
 * <p>Both are lazy. A service that only receives calls may have no key to sign with, and that is only a mistake if
 * something actually injects one of them, which then fails the startup.
 */
@AutoConfiguration(after = GatepassAutoConfiguration.class)
@ConditionalOnBean(Gatepass.class)
@EnableConfigurationProperties(GatepassProperties.class)
public class GatepassHttpClientsAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.http.client.ClientHttpRequestInterceptor")
    static class BlockingClientConfiguration {

        @Bean
        @Lazy
        @ConditionalOnMissingBean
        GatepassClientHttpRequestInterceptor gatepassClientHttpRequestInterceptor(Gatepass gatepass,
                GatepassProperties properties) {
            return new GatepassClientHttpRequestInterceptor(gatepass, properties.getHeaderName(),
                    properties.bodySigning());
        }

    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.web.reactive.function.client.WebClient")
    static class ReactiveClientConfiguration {

        @Bean
        @Lazy
        @ConditionalOnMissingBean
        GatepassExchangeFilterFunction gatepassExchangeFilterFunction(Gatepass gatepass,
                GatepassProperties properties) {
            return new GatepassExchangeFilterFunction(gatepass, properties.getHeaderName(), properties.bodySigning());
        }

    }

}
