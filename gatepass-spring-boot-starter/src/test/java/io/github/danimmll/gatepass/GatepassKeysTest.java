package io.github.danimmll.gatepass;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
class GatepassKeysTest {

    private static final RequestParts REQUEST = RequestParts.of("GET", "/orders/1", null);

    @Test
    void generatedKeysSignAndVerifyPassesThatNameTheCaller() {
        GatepassKeys.GeneratedKeys keys = GatepassKeys.generate();
        Gatepass sender = Gatepass.builder().privateKey(keys.privateKey()).build();
        Gatepass receiver = Gatepass.builder().trustedService("orders", keys.publicKey()).build();

        String pass = sender.issue(REQUEST);

        assertThat(pass).contains(".ed25519." + keys.keyId() + ".");
        Verification verification = receiver.verify(pass, REQUEST);
        assertThat(verification.verdict()).isEqualTo(Verdict.VALID);
        assertThat(verification.caller()).isEqualTo("orders");
    }

    @Test
    void everyPairIsNew() {
        assertThat(GatepassKeys.generate().privateKey()).isNotEqualTo(GatepassKeys.generate().privateKey());
    }

    @Test
    void toStringNeverShowsThePrivateKey() {
        GatepassKeys.GeneratedKeys keys = GatepassKeys.generate();

        assertThat(keys.toString()).doesNotContain(keys.privateKey()).contains(keys.keyId());
    }

    @Test
    void mainPrintsAPairAndWhereEachHalfGoes(CapturedOutput output) {
        GatepassKeys.main(new String[0]);

        assertThat(output).contains("gatepass.private-key", "gatepass.trusted-services", "MC4CAQAwBQYDK2Vw",
                "MCowBQYDK2VwAyEA");
    }

}
