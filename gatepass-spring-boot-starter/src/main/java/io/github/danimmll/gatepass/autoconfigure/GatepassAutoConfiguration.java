package io.github.danimmll.gatepass.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.util.StringUtils;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.GatepassMode;
import io.github.danimmll.gatepass.InMemoryReplayGuard;
import io.github.danimmll.gatepass.ReplayGuard;

/**
 * Creates the {@link Gatepass} every integration shares. Fails the startup, with a hint on how to fix it, if the keys
 * are missing or unusable.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "gatepass", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(GatepassProperties.class)
public class GatepassAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    ReplayGuard gatepassReplayGuard(GatepassProperties properties) {
        return properties.getReplayProtection().isEnabled() ? new InMemoryReplayGuard() : ReplayGuard.disabled();
    }

    @Bean
    @ConditionalOnMissingBean
    Gatepass gatepass(GatepassProperties properties, ReplayGuard replayGuard) {
        Gatepass.Builder builder = Gatepass.builder()
                .secrets(properties.getSecrets())
                .trustedServices(properties.getTrustedServices())
                .maxClockSkew(properties.getMaxClockSkew())
                .replayGuard(replayGuard);
        GatepassMode mode = properties.getMode();
        if (mode != null) {
            builder.mode(mode);
        }
        String privateKey = properties.getPrivateKey();
        if (StringUtils.hasText(privateKey)) {
            builder.privateKey(privateKey);
        }
        String publicKey = properties.getPublicKey();
        if (StringUtils.hasText(publicKey)) {
            builder.publicKey(publicKey);
        }
        return builder.build();
    }

}
