package io.github.danimmll.gatepass.autoconfigure;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.GatepassConfigurationException;

/**
 * Turns a {@link GatepassConfigurationException} into a startup report that says which property to fix.
 */
class GatepassConfigurationFailureAnalyzer extends AbstractFailureAnalyzer<GatepassConfigurationException> {

    private static final String DISABLE_HINT = "\nTo start without Gatepass (in a test, for example), set"
            + " gatepass.enabled=false.";

    private static final String KEY_GENERATOR_HINT = "java -jar gatepass-core-<version>.jar prints a new key pair"
            + " in the expected form.";

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, GatepassConfigurationException cause) {
        return new FailureAnalysis("Gatepass is misconfigured: " + cause.getMessage(), action(cause), cause);
    }

    private static String action(GatepassConfigurationException cause) {
        return switch (cause.getReason()) {
            case NO_KEYS -> "Give Gatepass something to sign and check passes with, the same way in the gateway and"
                    + " in every service:"
                    + "\n  - one secret they all share: gatepass.secrets, at least " + Gatepass.MIN_SECRET_BYTES
                    + " bytes (openssl rand -base64 32)"
                    + "\n  - or a key pair per service: gatepass.private-key, plus gatepass.trusted-services with the"
                    + " public keys of the services it accepts. " + KEY_GENERATOR_HINT
                    + DISABLE_HINT;
            case NO_SECRETS, BLANK_SECRET, SECRET_TOO_SHORT -> "Set gatepass.secrets to at least one secret of "
                    + Gatepass.MIN_SECRET_BYTES + " bytes or more, the same in the gateway and in every service."
                    + " Generate one with: openssl rand -base64 32" + DISABLE_HINT;
            case SECRET_NOT_HEADER_SAFE -> "Use a secret made of printable ASCII, such as the output of"
                    + " 'openssl rand -base64 32', or switch to gatepass.mode=hmac, which never sends the secret.";
            case DUPLICATE_SECRET -> "Remove the repeated entry from gatepass.secrets. During a rotation the list"
                    + " holds the new secret and the old one, once each.";
            case INVALID_KEY -> "Check gatepass.private-key, gatepass.public-key and gatepass.trusted-services. Keys"
                    + " are Ed25519, as PEM or as base64 of their DER encoding: PKCS#8 for a private key"
                    + " (openssl genpkey -algorithm ed25519), X.509 SubjectPublicKeyInfo for a public key"
                    + " (openssl pkey -pubout). " + KEY_GENERATOR_HINT;
            case DUPLICATE_KEY -> "Give every service a key pair of its own, and list each public key once under"
                    + " gatepass.trusted-services.";
            case CANNOT_ISSUE -> "This application sends passes: it is a gateway, it lists clients in"
                    + " gatepass.feign.clients, or it injects the RestClient or WebClient hook. Set"
                    + " gatepass.private-key (ed25519 mode) or gatepass.secrets (hmac mode). " + KEY_GENERATOR_HINT;
            case CONFLICTING_SETTINGS -> "Change one of the gatepass.* settings named above: as they are, they"
                    + " cannot work together.";
            case INVALID_CLOCK_SKEW -> "Set gatepass.max-clock-skew to a positive duration, such as 30s.";
        };
    }

}
