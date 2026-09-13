package io.github.danimmll.gatepass.it.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * A throwaway certificate for {@code localhost}, made with the JDK's keytool the first time it is needed.
 */
final class TestCertificates {

    static final String PASSWORD = "changeit";

    static final String ALIAS = "gatepass-test";

    private static Path keyStore;

    private TestCertificates() {
    }

    static synchronized Path keyStore() {
        if (keyStore == null) {
            try {
                Path file = Files.createTempDirectory("gatepass-tls").resolve("localhost.p12");
                boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
                Path keytool = Path.of(System.getProperty("java.home"), "bin", windows ? "keytool.exe" : "keytool");
                Process process = new ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", ALIAS, "-keyalg",
                        "EC", "-groupname", "secp256r1", "-dname", "CN=localhost", "-ext",
                        "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2", "-storetype", "PKCS12", "-keystore",
                        file.toString(), "-storepass", PASSWORD, "-keypass", PASSWORD, "-noprompt")
                        .redirectErrorStream(true)
                        .start();
                String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                if (process.waitFor() != 0) {
                    throw new IllegalStateException("keytool failed: " + output);
                }
                keyStore = file;
            }
            catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
            catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(ex);
            }
        }
        return keyStore;
    }

    /** An HTTP client that trusts the certificate above and nothing else. */
    static HttpClient trustingClient() {
        try (InputStream in = Files.newInputStream(keyStore())) {
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(in, PASSWORD.toCharArray());
            KeyStore trusted = KeyStore.getInstance("PKCS12");
            trusted.load(null, null);
            trusted.setCertificateEntry("localhost", keys.getCertificate(ALIAS));
            TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trusted);
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(null, trustManagers.getTrustManagers(), null);
            return HttpClient.newBuilder().sslContext(ssl).build();
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
    }

}
