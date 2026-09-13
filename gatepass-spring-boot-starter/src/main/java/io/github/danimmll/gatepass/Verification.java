package io.github.danimmll.gatepass;

import java.security.MessageDigest;

import org.jspecify.annotations.Nullable;

/**
 * The result of checking a pass: the verdict, and what a genuine pass says about the request.
 */
public final class Verification {

    private final Verdict verdict;

    private final @Nullable String caller;

    private final byte @Nullable [] bodyDigest;

    private Verification(Verdict verdict, @Nullable String caller, byte @Nullable [] bodyDigest) {
        this.verdict = verdict;
        this.caller = caller;
        this.bodyDigest = bodyDigest;
    }

    static Verification rejected(Verdict verdict) {
        return new Verification(verdict, null, null);
    }

    static Verification valid(@Nullable String caller, byte @Nullable [] bodyDigest) {
        return new Verification(Verdict.VALID, caller, bodyDigest);
    }

    /**
     * The verdict on the pass alone. When the pass covers the body, the body still has to be checked with
     * {@link #bodyMatches(byte[])}.
     *
     * @return the verdict
     */
    public Verdict verdict() {
        return this.verdict;
    }

    /**
     * Whether the pass is genuine, current and used for the first time.
     *
     * @return {@code true} for {@link Verdict#VALID}
     */
    public boolean isValid() {
        return this.verdict.isValid();
    }

    /**
     * The service that signed the pass, under the name this service trusts it by. Only an Ed25519 pass names its
     * caller: an HMAC pass can come from anyone who holds the secret.
     *
     * @return the calling service, or {@code null} if this is not a valid Ed25519 pass
     */
    public @Nullable String caller() {
        return this.caller;
    }

    /**
     * Whether the pass covers the request body, which then has to be checked with {@link #bodyMatches(byte[])}
     * before the request is let through.
     *
     * @return {@code true} if the pass carries a body digest
     */
    public boolean coversBody() {
        return this.bodyDigest != null;
    }

    /**
     * Checks the body that arrived against the digest the pass was signed with, in constant time.
     *
     * @param body the complete request body, empty if there is none
     * @return {@code true} if the pass covers the body and this is the body that was signed
     */
    public boolean bodyMatches(byte[] body) {
        return this.bodyDigest != null && MessageDigest.isEqual(this.bodyDigest, Gatepass.sha256(body));
    }

    @Override
    public String toString() {
        return "Verification[" + this.verdict + ((this.caller != null) ? ", caller=" + this.caller : "")
                + (coversBody() ? ", covers body" : "") + "]";
    }

}
