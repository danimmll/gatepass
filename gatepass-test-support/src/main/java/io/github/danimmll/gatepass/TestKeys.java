package io.github.danimmll.gatepass;

/**
 * Ed25519 key pairs for tests, generated with {@code openssl genpkey -algorithm ed25519}. Their private keys are
 * public, so never use them anywhere else.
 */
public final class TestKeys {

    public static final String GATEWAY_PRIVATE = "MC4CAQAwBQYDK2VwBCIEINM+bvg0MvLd4MiyAh4eqVjyrMj2a5AWUCAh6R5sSKN5";

    public static final String GATEWAY_PUBLIC = "MCowBQYDK2VwAyEAfY5j7ro5HiLteabA14arzexLf6RXI75QlarV8XfIb1o=";

    /** Computed with Python and with openssl from {@link #GATEWAY_PUBLIC}. */
    public static final String GATEWAY_KEY_ID = "c14c3b42";

    public static final String ORDERS_PRIVATE = "MC4CAQAwBQYDK2VwBCIEIFVT6n9twGnPgLB2eGdcnW4SvwwGlSMT2WONhMZO2jSm";

    public static final String ORDERS_PUBLIC = "MCowBQYDK2VwAyEAb8G61fNi6MCDYc9eLa5uMHhhq2vPyTlxsnWFbPOe+pk=";

    public static final String USERS_PRIVATE = "MC4CAQAwBQYDK2VwBCIEIKNh+rAumlPDua/ZucqrAuPi6X1VRjolbiaOxz6dXW4v";

    public static final String USERS_PUBLIC = "MCowBQYDK2VwAyEASK87h99v+qKw0zKruzS17MEvt/dvaoeYKOEyC7DlaM0=";

    public static final String OTHER_PRIVATE = "MC4CAQAwBQYDK2VwBCIEIB5c+yFZ1uRzEs3iZARtA8uGgrsXuUZKb/U3XIsK2TA6";

    public static final String OTHER_PUBLIC = "MCowBQYDK2VwAyEAyMyJ/C9gSyJi6hJ2Ia76W29KoVhTU7R9TyFeta3Dehc=";

    private TestKeys() {
    }

}
