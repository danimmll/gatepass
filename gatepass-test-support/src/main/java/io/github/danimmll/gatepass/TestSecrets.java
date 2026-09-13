package io.github.danimmll.gatepass;

/**
 * Secrets for tests. Long enough to be accepted, obviously not for production.
 */
public final class TestSecrets {

    public static final String CURRENT = "current-test-secret-0123456789abcdefghij";

    public static final String PREVIOUS = "previous-test-secret-0123456789abcdefghij";

    public static final String OTHER = "unrelated-test-secret-0123456789abcdefghij";

    private TestSecrets() {
    }

}
