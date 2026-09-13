package io.github.danimmll.gatepass.autoconfigure;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Configuration;

import io.github.danimmll.gatepass.GatepassConfigurationException;
import io.github.danimmll.gatepass.GatepassConfigurationException.Reason;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatException;

@ExtendWith(OutputCaptureExtension.class)
class GatepassConfigurationFailureAnalyzerTests {

    @Test
    void explainsWhichPropertyToFix() {
        GatepassConfigurationException cause = new GatepassConfigurationException(Reason.NO_SECRETS, "No secrets configured.");

        FailureAnalysis analysis = new GatepassConfigurationFailureAnalyzer()
                .analyze(new BeanCreationException("gatepass", cause));

        assertThat(analysis.getDescription()).contains("No secrets configured.");
        assertThat(analysis.getAction()).contains("gatepass.secrets", "openssl rand -base64 32", "gatepass.enabled=false");
    }

    @Test
    void hasAnActionForEveryReason() {
        for (Reason reason : Reason.values()) {
            FailureAnalysis analysis = new GatepassConfigurationFailureAnalyzer()
                    .analyze(new GatepassConfigurationException(reason, "whatever"));
            assertThat(analysis.getAction()).as(reason.name()).contains("gatepass.");
        }
    }

    @Test
    void anApplicationWithoutKeysSaysHowToFixItWhenItFailsToStart(CapturedOutput output) {
        SpringApplication application = new SpringApplication(ApplicationWithoutKeys.class);
        application.setWebApplicationType(WebApplicationType.NONE);

        assertThatException().isThrownBy(application::run);

        assertThat(output).contains("APPLICATION FAILED TO START", "Gatepass is misconfigured", "gatepass.secrets",
                "gatepass.private-key", "gatepass.trusted-services");
    }

    @Configuration(proxyBeanMethods = false)
    @ImportAutoConfiguration(GatepassAutoConfiguration.class)
    static class ApplicationWithoutKeys {

    }

}
