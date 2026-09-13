package io.github.danimmll.gatepass;

/**
 * How passes are issued. Whatever the mode, a pass is accepted whenever a key for it is configured, which is how a
 * system moves from one mode to another without downtime.
 */
public enum GatepassMode {

    /**
     * An HMAC-SHA256 signature made with a secret every service shares. The secret never travels, but anyone who
     * holds it can issue passes, so a pass proves that a request comes from inside the system, not from which
     * service. The default when no private key is configured.
     */
    HMAC,

    /**
     * An Ed25519 signature made with this service's own private key. Services only hold each other's public keys,
     * so a pass also proves which service sent the request, and a compromised service cannot pass itself off as
     * another one. The default when a private key is configured.
     */
    ED25519,

    /**
     * The secret itself, sent as is. For callers that cannot sign (a shell script, a service in another language)
     * on a network you trust. Anyone who sees one request can reuse the secret forever, and none of the other
     * protections apply: no expiry, no replay protection, nothing bound to the request.
     */
    SHARED_SECRET

}
