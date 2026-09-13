package io.github.danimmll.gatepass;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import io.github.danimmll.gatepass.GatepassConfigurationException.Reason;

import static io.github.danimmll.gatepass.TestSecrets.CURRENT;
import static io.github.danimmll.gatepass.TestSecrets.OTHER;
import static io.github.danimmll.gatepass.TestSecrets.PREVIOUS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class GatepassTest {

    private static final Instant NOW = Instant.parse("2026-09-13T10:00:00Z");

    private static final RequestParts GET_ORDER = RequestParts.of("GET", "/orders/42", "expand=true");

    private static final String BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    // HMAC passes

    @Test
    void passIssuedForARequestIsValidForThatRequestExactlyOnce() {
        Gatepass gatepass = hmacAt(NOW, CURRENT);
        String pass = gatepass.issue(GET_ORDER);

        Verification first = gatepass.verify(pass, GET_ORDER);
        assertThat(first.verdict()).isEqualTo(Verdict.VALID);
        assertThat(first.caller()).isNull();
        assertThat(first.coversBody()).isFalse();
        assertThat(gatepass.verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.REPLAYED);
    }

    @Test
    void passHasTheDocumentedShapeAndNeverContainsTheSecret() {
        String pass = hmacAt(NOW, CURRENT).issue(GET_ORDER);

        assertThat(pass).matches("v1\\.hs256\\.ec609b60\\.1789293600\\.[A-Za-z0-9_-]{22}\\.-\\.[A-Za-z0-9_-]{43}")
                .doesNotContain(CURRENT);
    }

    @Test
    void hmacPassMatchesTheDocumentedFormatByteForByte() {
        // Computed separately with Python and with openssl, following the algorithm described in the README. If this
        // test fails, passes from callers written in other languages stop being accepted.
        Gatepass gatepass = Gatepass.builder().secrets(CURRENT).clock(fixed(NOW)).random(new CountingRandom()).build();

        String pass = gatepass.issue(RequestParts.of("post", "/orders/a%20b", "b=2&a=1"),
                "{\"item\":\"pizza\"}".getBytes(StandardCharsets.UTF_8));

        assertThat(pass).isEqualTo("v1.hs256.ec609b60.1789293600.AAECAwQFBgcICQoLDA0ODw."
                + "KstPWBD4Yz81tbKyjMbCB8Q9-HEsp140gAv5T_Thqv0.k03rMLtTB9ve_Ag1qT79bEPit0Zhbrg2BgyeBUzLMvQ");
    }

    @Test
    void twoPassesForTheSameRequestInTheSameSecondAreDifferentAndBothAccepted() {
        Gatepass gatepass = hmacAt(NOW, CURRENT);

        String first = gatepass.issue(GET_ORDER);
        String second = gatepass.issue(GET_ORDER);

        assertThat(first).isNotEqualTo(second);
        assertThat(gatepass.verify(first, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
        assertThat(gatepass.verify(second, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void methodIsCaseInsensitive() {
        Gatepass gatepass = hmacAt(NOW, CURRENT);

        String pass = gatepass.issue(RequestParts.of("get", "/a", null));

        assertThat(gatepass.verify(pass, RequestParts.of("GET", "/a", null)).verdict()).isEqualTo(Verdict.VALID);
    }

    @ParameterizedTest
    @MethodSource("otherRequests")
    void passCannotBeMovedToAnotherRequest(RequestParts other) {
        Gatepass gatepass = hmacAt(NOW, CURRENT);

        assertThat(gatepass.verify(gatepass.issue(GET_ORDER), other).verdict()).isEqualTo(Verdict.INVALID);
    }

    static Stream<RequestParts> otherRequests() {
        return Stream.of(
                RequestParts.of("DELETE", "/orders/42", "expand=true"),
                RequestParts.of("GET", "/orders/43", "expand=true"),
                RequestParts.of("GET", "/orders/42", null),
                RequestParts.of("GET", "/orders/42", "expand=false"),
                RequestParts.of("GET", "/orders/42", "expand=true&admin=true"));
    }

    @Test
    void passCanCoverTheBody() {
        Gatepass gatepass = hmacAt(NOW, CURRENT);
        byte[] body = "{\"item\":\"pizza\"}".getBytes(StandardCharsets.UTF_8);

        Verification verification = gatepass.verify(gatepass.issue(GET_ORDER, body), GET_ORDER);

        assertThat(verification.verdict()).isEqualTo(Verdict.VALID);
        assertThat(verification.coversBody()).isTrue();
        assertThat(verification.bodyMatches(body)).isTrue();
        assertThat(verification.bodyMatches("{\"item\":\"caviar\"}".getBytes(StandardCharsets.UTF_8))).isFalse();
    }

    @Test
    void bodyDigestCannotBeRemovedOrSwapped() {
        Gatepass gatepass = hmacAt(NOW, CURRENT);
        String[] part = gatepass.issue(GET_ORDER, "a".getBytes(StandardCharsets.UTF_8)).split("\\.");
        String digestOfB = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Crypto.sha256("b".getBytes(StandardCharsets.UTF_8)));

        assertThat(gatepass.verify(with(part, 5, "-"), GET_ORDER).verdict()).isEqualTo(Verdict.INVALID);
        assertThat(gatepass.verify(with(part, 5, digestOfB), GET_ORDER).verdict()).isEqualTo(Verdict.INVALID);
    }

    @Test
    void passesExpireOnceOlderThanTheClockSkew() {
        String pass = hmacAt(NOW, CURRENT).issue(GET_ORDER);

        assertThat(hmacAt(NOW.plusSeconds(30), CURRENT).verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
        assertThat(hmacAt(NOW.plusSeconds(31), CURRENT).verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.EXPIRED);
    }

    @Test
    void passesFromTooFarInTheFutureAreRejected() {
        String pass = hmacAt(NOW, CURRENT).issue(GET_ORDER);

        assertThat(hmacAt(NOW.minusSeconds(30), CURRENT).verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
        assertThat(hmacAt(NOW.minusSeconds(31), CURRENT).verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.EXPIRED);
    }

    @Test
    void clockSkewIsConfigurable() {
        String pass = hmacAt(NOW, CURRENT).issue(GET_ORDER);
        Gatepass lenient = Gatepass.builder()
                .secrets(CURRENT)
                .maxClockSkew(Duration.ofMinutes(2))
                .clock(fixed(NOW.plusSeconds(100)))
                .build();

        assertThat(lenient.verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void forgedSignatureIsInvalid() {
        Gatepass gatepass = hmacAt(NOW, CURRENT);
        String[] part = gatepass.issue(GET_ORDER).split("\\.");
        String signature = part[6];
        String forged = ((signature.charAt(0) == 'A') ? 'B' : 'A') + signature.substring(1);

        assertThat(gatepass.verify(with(part, 6, forged), GET_ORDER).verdict()).isEqualTo(Verdict.INVALID);
    }

    @Test
    void timestampCannotBeChanged() {
        Gatepass gatepass = hmacAt(NOW, CURRENT);
        String[] part = gatepass.issue(GET_ORDER).split("\\.");

        assertThat(gatepass.verify(with(part, 3, String.valueOf(NOW.getEpochSecond() - 1)), GET_ORDER).verdict())
                .isEqualTo(Verdict.INVALID);
    }

    @Test
    void nonceCannotBeChangedToGetPastTheReplayGuard() {
        Gatepass gatepass = hmacAt(NOW, CURRENT);
        String pass = gatepass.issue(GET_ORDER);
        String[] part = pass.split("\\.");
        String otherNonce = ((part[4].charAt(0) == 'A') ? 'B' : 'A') + part[4].substring(1);

        assertThat(gatepass.verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
        assertThat(gatepass.verify(with(part, 4, otherNonce), GET_ORDER).verdict()).isEqualTo(Verdict.INVALID);
    }

    @Test
    void instancesSharingAReplayGuardStopReplaysAcrossThem() {
        String pass = hmacAt(NOW, CURRENT).issue(GET_ORDER);
        ReplayGuard shared = new InMemoryReplayGuard(fixed(NOW));
        Gatepass replicaA = Gatepass.builder().secrets(CURRENT).clock(fixed(NOW)).replayGuard(shared).build();
        Gatepass replicaB = Gatepass.builder().secrets(CURRENT).clock(fixed(NOW)).replayGuard(shared).build();

        assertThat(replicaA.verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
        assertThat(replicaB.verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.REPLAYED);
    }

    @Test
    void instancesWithTheirOwnReplayGuardEachAcceptThePassOnce() {
        String pass = hmacAt(NOW, CURRENT).issue(GET_ORDER);

        assertThat(hmacAt(NOW, CURRENT).verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
        assertThat(hmacAt(NOW, CURRENT).verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void replayProtectionCanBeDisabled() {
        Gatepass gatepass = Gatepass.builder().secrets(CURRENT).replayGuard(ReplayGuard.disabled()).build();
        String pass = gatepass.issue(GET_ORDER);

        assertThat(gatepass.verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
        assertThat(gatepass.verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void secretCanBeRotatedWithoutDowntime() {
        Gatepass notYetRotated = hmacAt(NOW, PREVIOUS);
        Gatepass rotating = hmacAt(NOW, CURRENT, PREVIOUS);

        assertThat(rotating.verify(notYetRotated.issue(GET_ORDER), GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
        assertThat(rotating.verify(rotating.issue(GET_ORDER), GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
    }

    @Test
    void passSignedWithASecretThisServiceDoesNotHaveIsReportedAsAnUnknownKey() {
        String pass = hmacAt(NOW, OTHER).issue(GET_ORDER);

        assertThat(hmacAt(NOW, CURRENT, PREVIOUS).verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.UNKNOWN_KEY);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void requestWithoutPassIsMissing(String pass) {
        assertThat(hmacAt(NOW, CURRENT).verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.MISSING);
    }

    @ParameterizedTest
    @MethodSource("malformedPasses")
    void anythingThatIsNotAPassIsMalformed(String pass) {
        assertThat(hmacAt(NOW, CURRENT).verify(pass, GET_ORDER).verdict()).isEqualTo(Verdict.MALFORMED);
    }

    static Stream<String> malformedPasses() {
        String[] part = hmacAt(NOW, CURRENT).issue(GET_ORDER, new byte[0]).split("\\.");
        String signature = part[6];
        String nonCanonicalSignature = signature.substring(0, 42)
                + BASE64URL.charAt(BASE64URL.indexOf(signature.charAt(42)) + 1);
        return Stream.of(
                "garbage",
                CURRENT,
                "v1......",
                String.join(".", part) + ".extra",
                with(part, 0, "v2"),
                with(part, 1, "hs512"),
                with(part, 1, "HS256"),
                with(part, 1, "ed25519"),
                with(part, 2, part[2].toUpperCase()),
                with(part, 2, part[2] + "0"),
                with(part, 3, "-" + part[3]),
                with(part, 3, "1234567890123"),
                with(part, 4, part[4].substring(1)),
                with(part, 4, "+" + part[4].substring(1)),
                with(part, 5, "abc"),
                with(part, 5, ""),
                with(part, 6, signature.substring(1)),
                with(part, 6, "+" + signature.substring(1)),
                with(part, 6, nonCanonicalSignature));
    }

    // Ed25519 passes

    @Test
    void ed25519PassMatchesTheDocumentedFormatByteForByte() {
        // Signed separately with openssl pkeyutl, following the algorithm described in the README.
        Gatepass gatepass = Gatepass.builder()
                .privateKey(TestKeys.GATEWAY_PRIVATE)
                .clock(fixed(NOW))
                .random(new CountingRandom())
                .build();

        assertThat(gatepass.issue(RequestParts.of("GET", "/orders/42", null))).isEqualTo("v1.ed25519."
                + TestKeys.GATEWAY_KEY_ID + ".1789293600.AAECAwQFBgcICQoLDA0ODw.-."
                + "54bBhjENunCJvuY-yfPcFsm3gFwxiwXCy3eOuDMdMXzpWSSWyQoik8xxe4PZJ_zLQg1XPIpMQRKIWsBHPyo7BA");
    }

    @Test
    void ed25519PassNamesTheServiceThatSentIt() {
        Gatepass orders = Gatepass.builder().privateKey(TestKeys.ORDERS_PRIVATE).build();

        Verification verification = receiver().verify(orders.issue(GET_ORDER), GET_ORDER);

        assertThat(verification.verdict()).isEqualTo(Verdict.VALID);
        assertThat(verification.caller()).isEqualTo("orders");
    }

    @Test
    void aServiceCannotPassItselfOffAsAnother() {
        Gatepass compromised = Gatepass.builder().privateKey(TestKeys.OTHER_PRIVATE).build();
        String[] part = compromised.issue(GET_ORDER).split("\\.");

        assertThat(receiver().verify(String.join(".", part), GET_ORDER).verdict()).isEqualTo(Verdict.UNKNOWN_KEY);
        assertThat(receiver().verify(with(part, 2, TestKeys.GATEWAY_KEY_ID), GET_ORDER).verdict())
                .isEqualTo(Verdict.INVALID);
    }

    @Test
    void anHmacPassCannotBeRelabelledAsEd25519() {
        Gatepass both = Gatepass.builder().secrets(CURRENT).trustedService("gateway", TestKeys.GATEWAY_PUBLIC).build();
        String[] part = both.issue(GET_ORDER).split("\\.");

        assertThat(both.verify(with(part, 1, "ed25519"), GET_ORDER).verdict()).isEqualTo(Verdict.MALFORMED);
    }

    @Test
    void aServiceOnlyNeedsItsPrivateKeyToSign() {
        Gatepass orders = Gatepass.builder().privateKey(TestKeys.ORDERS_PRIVATE).build();

        assertThat(orders.mode()).isEqualTo(GatepassMode.ED25519);
        assertThat(orders.canIssue()).isTrue();
        assertThat(Gatepass.builder().secrets(CURRENT).build().mode()).isEqualTo(GatepassMode.HMAC);
    }

    @Test
    void keysCanBeWrittenAsPem() {
        Gatepass orders = Gatepass.builder().privateKey(pem("PRIVATE KEY", TestKeys.ORDERS_PRIVATE)).build();
        Gatepass receiver = Gatepass.builder()
                .trustedService("orders", pem("PUBLIC KEY", TestKeys.ORDERS_PUBLIC).replace("\n", "\\n"))
                .build();

        assertThat(receiver.verify(orders.issue(GET_ORDER), GET_ORDER).caller()).isEqualTo("orders");
    }

    @Test
    void anExplicitPublicKeyMustBelongToThePrivateKey() {
        assertThat(Gatepass.builder().privateKey(TestKeys.ORDERS_PRIVATE).publicKey(TestKeys.ORDERS_PUBLIC).build()
                .canIssue()).isTrue();
        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> Gatepass.builder().privateKey(TestKeys.ORDERS_PRIVATE)
                        .publicKey(TestKeys.GATEWAY_PUBLIC).build())
                .satisfies(ex -> assertThat(ex.getReason()).isEqualTo(Reason.INVALID_KEY));
    }

    @Test
    void aServiceRotatesItsKeyPairWhileOthersTrustBothKeys() {
        Gatepass oldKey = Gatepass.builder().privateKey(TestKeys.ORDERS_PRIVATE).build();
        Gatepass newKey = Gatepass.builder().privateKey(TestKeys.OTHER_PRIVATE).build();
        Gatepass receiver = Gatepass.builder()
                .trustedService("orders", TestKeys.ORDERS_PUBLIC, TestKeys.OTHER_PUBLIC)
                .build();

        assertThat(receiver.verify(oldKey.issue(GET_ORDER), GET_ORDER).caller()).isEqualTo("orders");
        assertThat(receiver.verify(newKey.issue(GET_ORDER), GET_ORDER).caller()).isEqualTo("orders");
    }

    @Test
    void bothKindsOfPassAreAcceptedWhileASystemMovesFromHmacToEd25519() {
        Gatepass receiver = Gatepass.builder().secrets(CURRENT).trustedService("gateway", TestKeys.GATEWAY_PUBLIC).build();
        Gatepass hmacSender = Gatepass.builder().secrets(CURRENT).build();
        Gatepass ed25519Sender = Gatepass.builder().privateKey(TestKeys.GATEWAY_PRIVATE).build();

        assertThat(receiver.verify(hmacSender.issue(GET_ORDER), GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
        assertThat(receiver.verify(ed25519Sender.issue(GET_ORDER), GET_ORDER).caller()).isEqualTo("gateway");
    }

    @Test
    void aServiceThatOnlyReceivesCallsCannotIssue() {
        Gatepass receiver = receiver();

        assertThat(receiver.canIssue()).isFalse();
        assertThat(receiver.trustedServices()).containsExactly("gateway", "orders");
        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> receiver.issue(GET_ORDER))
                .satisfies(ex -> assertThat(ex.getReason()).isEqualTo(Reason.CANNOT_ISSUE));
    }

    // Shared-secret mode

    @Test
    void sharedSecretModeSendsTheSecretAndAcceptsAnyConfiguredOne() {
        Gatepass shared = Gatepass.builder().mode(GatepassMode.SHARED_SECRET).secrets(CURRENT, PREVIOUS).build();
        RequestParts anything = RequestParts.of("DELETE", "/anything", null);

        assertThat(shared.issue(GET_ORDER)).isEqualTo(CURRENT);
        assertThat(shared.verify(CURRENT, anything).verdict()).isEqualTo(Verdict.VALID);
        assertThat(shared.verify(CURRENT, anything).verdict()).as("no replay protection").isEqualTo(Verdict.VALID);
        assertThat(shared.verify(PREVIOUS, GET_ORDER).verdict()).isEqualTo(Verdict.VALID);
        assertThat(shared.verify(OTHER, GET_ORDER).verdict()).isEqualTo(Verdict.INVALID);
        assertThat(shared.verify(CURRENT + "x", GET_ORDER).verdict()).isEqualTo(Verdict.INVALID);
        assertThat(shared.verify(null, GET_ORDER).verdict()).isEqualTo(Verdict.MISSING);
    }

    @Test
    void sharedSecretModeCannotCoverABody() {
        Gatepass shared = Gatepass.builder().mode(GatepassMode.SHARED_SECRET).secrets(CURRENT).build();

        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> shared.issue(GET_ORDER, new byte[0]))
                .satisfies(ex -> assertThat(ex.getReason()).isEqualTo(Reason.CONFLICTING_SETTINGS));
    }

    // Configuration errors

    @Test
    void refusesToStartWithNothingToSignOrVerifyWith() {
        assertReason(Gatepass.builder(), Reason.NO_KEYS);
        assertReason(Gatepass.builder().mode(GatepassMode.ED25519), Reason.NO_KEYS);
    }

    @Test
    void sharedSecretModeNeedsASecret() {
        assertReason(Gatepass.builder().mode(GatepassMode.SHARED_SECRET), Reason.NO_SECRETS);
    }

    @Test
    void refusesBlankSecrets() {
        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> Gatepass.builder().secrets(Arrays.asList(CURRENT, "  ")).build())
                .withMessage("secrets[1] is empty.")
                .satisfies(ex -> assertThat(ex.getReason()).isEqualTo(Reason.BLANK_SECRET));
        assertReason(Gatepass.builder().secrets(Arrays.asList(CURRENT, null)), Reason.BLANK_SECRET);
    }

    @Test
    void refusesShortSecretsWithoutRevealingThem() {
        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> Gatepass.builder().secrets("too-short-secret").build())
                .withMessageContaining("16 bytes")
                .withMessageNotContaining("too-short-secret")
                .satisfies(ex -> assertThat(ex.getReason()).isEqualTo(Reason.SECRET_TOO_SHORT));
    }

    @Test
    void refusesTheSameSecretTwice() {
        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> Gatepass.builder().secrets(CURRENT, PREVIOUS, CURRENT).build())
                .withMessage("secrets[2] is the same as secrets[0].");
    }

    @Test
    void sharedSecretModeRefusesSecretsThatCannotTravelInAHeader() {
        String withSpace = CURRENT + " and more";

        assertReason(Gatepass.builder().mode(GatepassMode.SHARED_SECRET).secrets(withSpace),
                Reason.SECRET_NOT_HEADER_SAFE);
        assertThat(Gatepass.builder().mode(GatepassMode.HMAC).secrets(withSpace).build()).isNotNull();
    }

    @Test
    void refusesAClockSkewThatIsNotPositive() {
        for (Duration skew : new Duration[] { Duration.ZERO, Duration.ofSeconds(-1) }) {
            assertReason(Gatepass.builder().secrets(CURRENT).maxClockSkew(skew), Reason.INVALID_CLOCK_SKEW);
        }
    }

    @Test
    void refusesAnythingThatIsNotAnEd25519KeyWithoutRevealingIt() throws Exception {
        String rsaPublicKey = Base64.getEncoder()
                .encodeToString(KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic().getEncoded());

        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> Gatepass.builder().privateKey("not-a-key-at-all").build())
                .withMessageNotContaining("not-a-key-at-all")
                .satisfies(ex -> assertThat(ex.getReason()).isEqualTo(Reason.INVALID_KEY));
        assertReason(Gatepass.builder().privateKey(TestKeys.ORDERS_PUBLIC), Reason.INVALID_KEY);
        assertReason(Gatepass.builder().trustedService("orders", TestKeys.ORDERS_PRIVATE), Reason.INVALID_KEY);
        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> Gatepass.builder().trustedService("orders", rsaPublicKey).build())
                .withMessageContaining("trusted-services.orders[0]")
                .satisfies(ex -> assertThat(ex.getReason()).isEqualTo(Reason.INVALID_KEY));
    }

    @Test
    void refusesTrustedServicesWithoutANameOrWithoutKeys() {
        assertReason(Gatepass.builder().trustedService(" ", TestKeys.ORDERS_PUBLIC), Reason.INVALID_KEY);
        assertReason(Gatepass.builder().trustedService("orders"), Reason.INVALID_KEY);
    }

    @Test
    void refusesTheSameKeyForTwoServices() {
        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(() -> Gatepass.builder()
                        .trustedService("orders", TestKeys.ORDERS_PUBLIC)
                        .trustedService("users", TestKeys.ORDERS_PUBLIC)
                        .build())
                .withMessage("trusted-services.users[0] is the same key as trusted-services.orders[0]. Each service"
                        + " needs a key pair of its own, listed once.")
                .satisfies(ex -> assertThat(ex.getReason()).isEqualTo(Reason.DUPLICATE_KEY));
    }

    @Test
    void refusesKeySettingsThatContradictTheMode() {
        assertReason(Gatepass.builder().mode(GatepassMode.HMAC).secrets(CURRENT).privateKey(TestKeys.ORDERS_PRIVATE),
                Reason.CONFLICTING_SETTINGS);
        assertReason(Gatepass.builder().mode(GatepassMode.SHARED_SECRET).secrets(CURRENT)
                .trustedService("orders", TestKeys.ORDERS_PUBLIC), Reason.CONFLICTING_SETTINGS);
        assertReason(Gatepass.builder().secrets(CURRENT).publicKey(TestKeys.ORDERS_PUBLIC),
                Reason.CONFLICTING_SETTINGS);
    }

    private static Gatepass hmacAt(Instant now, String... secrets) {
        return Gatepass.builder().secrets(secrets).clock(fixed(now)).build();
    }

    private static Gatepass receiver() {
        return Gatepass.builder()
                .trustedService("gateway", TestKeys.GATEWAY_PUBLIC)
                .trustedService("orders", TestKeys.ORDERS_PUBLIC)
                .build();
    }

    private static Clock fixed(Instant now) {
        return Clock.fixed(now, ZoneOffset.UTC);
    }

    private static String with(String[] parts, int index, String value) {
        String[] copy = parts.clone();
        copy[index] = value;
        return String.join(".", copy);
    }

    private static String pem(String type, String base64) {
        StringBuilder pem = new StringBuilder("-----BEGIN " + type + "-----\n");
        for (int i = 0; i < base64.length(); i += 20) {
            pem.append(base64, i, Math.min(base64.length(), i + 20)).append('\n');
        }
        return pem.append("-----END ").append(type).append("-----\n").toString();
    }

    private static void assertReason(Gatepass.Builder builder, Reason reason) {
        assertThatExceptionOfType(GatepassConfigurationException.class)
                .isThrownBy(builder::build)
                .satisfies(ex -> assertThat(ex.getReason()).isEqualTo(reason));
    }

    /** Produces 0, 1, 2, ... so nonces are known in advance. */
    private static final class CountingRandom extends SecureRandom {

        private static final long serialVersionUID = 1L;

        private int next;

        @Override
        public void nextBytes(byte[] bytes) {
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) this.next++;
            }
        }

    }

}
