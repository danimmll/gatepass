package io.github.danimmll.gatepass;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

/**
 * Generates Ed25519 key pairs for {@link GatepassMode#ED25519} mode. From a terminal:
 *
 * <pre>{@code
 * java -jar gatepass-core-<version>.jar
 * }</pre>
 */
public final class GatepassKeys {

    private GatepassKeys() {
    }

    /**
     * Generates a new key pair.
     *
     * @return the keys, as base64 of their DER encoding, and the key id passes signed with them carry
     */
    public static GeneratedKeys generate() {
        try {
            KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            byte[] publicKey = pair.getPublic().getEncoded();
            return new GeneratedKeys(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                    Base64.getEncoder().encodeToString(publicKey), Crypto.keyId(publicKey));
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Ed25519 is not available in this JVM", ex);
        }
    }

    /**
     * Prints a new key pair and where each half goes.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        GeneratedKeys keys = generate();
        System.out.println("A new Gatepass key pair (key id " + keys.keyId() + ")");
        System.out.println();
        System.out.println("Private key. Give it to this service only, as gatepass.private-key:");
        System.out.println(keys.privateKey());
        System.out.println();
        System.out.println("Public key. Add it under gatepass.trusted-services.<name of this service>");
        System.out.println("in every service that accepts calls from this one:");
        System.out.println(keys.publicKey());
    }

    /**
     * A generated key pair.
     *
     * @param privateKey the PKCS#8 private key, as base64 of its DER encoding
     * @param publicKey the X.509 SubjectPublicKeyInfo public key, as base64 of its DER encoding
     * @param keyId the key id passes signed with this pair carry
     */
    public record GeneratedKeys(String privateKey, String publicKey, String keyId) {

        @Override
        public String toString() {
            // Never print the private key by accident.
            return "GeneratedKeys[keyId=" + this.keyId + "]";
        }

    }

}
