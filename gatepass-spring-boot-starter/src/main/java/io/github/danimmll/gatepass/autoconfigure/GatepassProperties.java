package io.github.danimmll.gatepass.autoconfigure;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.Ordered;
import org.springframework.util.unit.DataSize;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.GatepassMode;

/**
 * Configuration of Gatepass, under the {@code gatepass} prefix.
 */
@ConfigurationProperties("gatepass")
public class GatepassProperties {

    /**
     * Whether Gatepass is enabled.
     */
    private boolean enabled = true;

    /**
     * How this application issues passes: hmac, ed25519 or shared-secret. Defaults to ed25519 when a private key is
     * set, and to hmac otherwise. Passes are accepted in whichever mode a key is configured for.
     */
    private @Nullable GatepassMode mode;

    /**
     * Header that carries the pass.
     */
    private String headerName = "X-Gatepass";

    /**
     * Secrets shared by every service, at least 32 bytes each. The first one signs HMAC passes and all of them are
     * accepted, which is how you rotate without downtime.
     */
    private List<String> secrets = new ArrayList<>();

    /**
     * This service's own Ed25519 private key, which signs its passes in ed25519 mode. PKCS#8, as PEM or as base64 of
     * the DER encoding. Generate a pair with: java -jar gatepass-spring-boot-starter.jar
     */
    private @Nullable String privateKey;

    /**
     * The public key that goes with private-key. Only needed on a JVM whose Ed25519 provider cannot derive it.
     */
    private @Nullable String publicKey;

    /**
     * Public keys of the services whose Ed25519 passes this service accepts, by the name used in caller rules. X.509
     * SubjectPublicKeyInfo, as PEM or as base64 of the DER encoding. Two keys for one service is how it rotates.
     */
    private Map<String, List<String>> trustedServices = new LinkedHashMap<>();

    /**
     * How far the issue time of a pass may be from this server's clock, in either direction.
     */
    private Duration maxClockSkew = Duration.ofSeconds(30);

    private final ReplayProtection replayProtection = new ReplayProtection();

    private final Body body = new Body();

    private final Inbound inbound = new Inbound();

    private final Gateway gateway = new Gateway();

    private final Feign feign = new Feign();

    public boolean isEnabled() {
        return this.enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public @Nullable GatepassMode getMode() {
        return this.mode;
    }

    public void setMode(@Nullable GatepassMode mode) {
        this.mode = mode;
    }

    public String getHeaderName() {
        return this.headerName;
    }

    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }

    public List<String> getSecrets() {
        return this.secrets;
    }

    public void setSecrets(List<String> secrets) {
        this.secrets = secrets;
    }

    public @Nullable String getPrivateKey() {
        return this.privateKey;
    }

    public void setPrivateKey(@Nullable String privateKey) {
        this.privateKey = privateKey;
    }

    public @Nullable String getPublicKey() {
        return this.publicKey;
    }

    public void setPublicKey(@Nullable String publicKey) {
        this.publicKey = publicKey;
    }

    public Map<String, List<String>> getTrustedServices() {
        return this.trustedServices;
    }

    public void setTrustedServices(Map<String, List<String>> trustedServices) {
        this.trustedServices = trustedServices;
    }

    public Duration getMaxClockSkew() {
        return this.maxClockSkew;
    }

    public void setMaxClockSkew(Duration maxClockSkew) {
        this.maxClockSkew = maxClockSkew;
    }

    public ReplayProtection getReplayProtection() {
        return this.replayProtection;
    }

    public Body getBody() {
        return this.body;
    }

    public Inbound getInbound() {
        return this.inbound;
    }

    public Gateway getGateway() {
        return this.gateway;
    }

    public Feign getFeign() {
        return this.feign;
    }

    BodySigning bodySigning() {
        return new BodySigning(this.body.isEnabled(), this.body.getMaxSize().toBytes());
    }

    /**
     * Rejecting passes that have already been used.
     */
    public static class ReplayProtection {

        /**
         * Whether a pass is accepted only once. Remembered in memory unless the application defines its own
         * ReplayGuard bean, for instance one backed by Redis when a service runs several instances.
         */
        private boolean enabled = true;

        public boolean isEnabled() {
            return this.enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

    }

    /**
     * Covering request bodies with the pass.
     */
    public static class Body {

        /**
         * Whether the gateway, Feign, RestClient and WebClient sign request bodies. Receivers always check a body a
         * pass covers. Multipart bodies are never signed.
         */
        private boolean enabled = false;

        /**
         * Largest body held in memory to sign it, or to check it on arrival. A gateway answers 413 to larger bodies
         * and clients fail the request; receivers answer 413.
         */
        private DataSize maxSize = DataSize.ofMegabytes(1);

        public boolean isEnabled() {
            return this.enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public DataSize getMaxSize() {
            return this.maxSize;
        }

        public void setMaxSize(DataSize maxSize) {
            this.maxSize = maxSize;
        }

    }

    /**
     * Checking passes on incoming requests.
     */
    public static class Inbound {

        /**
         * Whether to reject requests without a valid pass. When unset, on in services and off in a Spring Cloud
         * Gateway, which issues passes instead of checking them.
         */
        private @Nullable Boolean enabled;

        /**
         * Paths that require a pass, as PathPattern expressions relative to the context path.
         */
        private List<String> includePaths = new ArrayList<>(List.of("/**"));

        /**
         * Paths that never require a pass, even when included. Health checks usually hit containers directly.
         */
        private List<String> excludePaths = new ArrayList<>(List.of("/actuator/health/**"));

        /**
         * Order of the filter. The default runs it before Spring Security.
         */
        private int filterOrder = Ordered.HIGHEST_PRECEDENCE + 10;

        /**
         * Whether requests must arrive over TLS on their own connection. X-Forwarded-Proto and similar headers do not
         * count.
         */
        private boolean requireTls = false;

        /**
         * Whether every pass must cover the request body. Multipart requests are exempt.
         */
        private boolean requireSignedBody = false;

        /**
         * Which trusted services may call which paths. The first rule with a matching path decides; paths no rule
         * matches accept any valid pass. Needs Ed25519 passes, the only ones that name their caller.
         */
        private List<CallerRule> callers = new ArrayList<>();

        public @Nullable Boolean getEnabled() {
            return this.enabled;
        }

        public void setEnabled(@Nullable Boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getIncludePaths() {
            return this.includePaths;
        }

        public void setIncludePaths(List<String> includePaths) {
            this.includePaths = includePaths;
        }

        public List<String> getExcludePaths() {
            return this.excludePaths;
        }

        public void setExcludePaths(List<String> excludePaths) {
            this.excludePaths = excludePaths;
        }

        public int getFilterOrder() {
            return this.filterOrder;
        }

        public void setFilterOrder(int filterOrder) {
            this.filterOrder = filterOrder;
        }

        public boolean isRequireTls() {
            return this.requireTls;
        }

        public void setRequireTls(boolean requireTls) {
            this.requireTls = requireTls;
        }

        public boolean isRequireSignedBody() {
            return this.requireSignedBody;
        }

        public void setRequireSignedBody(boolean requireSignedBody) {
            this.requireSignedBody = requireSignedBody;
        }

        public List<CallerRule> getCallers() {
            return this.callers;
        }

        public void setCallers(List<CallerRule> callers) {
            this.callers = callers;
        }

        /**
         * Which services may call some paths.
         */
        public static class CallerRule {

            /**
             * PathPattern expressions, relative to the context path.
             */
            private List<String> paths = new ArrayList<>();

            /**
             * Names of the trusted services allowed to call them.
             */
            private List<String> services = new ArrayList<>();

            public List<String> getPaths() {
                return this.paths;
            }

            public void setPaths(List<String> paths) {
                this.paths = paths;
            }

            public List<String> getServices() {
                return this.services;
            }

            public void setServices(List<String> services) {
                this.services = services;
            }

        }

    }

    /**
     * Issuing passes from Spring Cloud Gateway.
     */
    public static class Gateway {

        /**
         * Whether the gateway attaches a pass to the requests it forwards.
         */
        private boolean enabled = true;

        /**
         * IDs of the routes that get a pass. Empty means every route with an lb:// URI; * means all routes. The pass
         * header a client sends is stripped from every route regardless.
         */
        private List<String> routes = new ArrayList<>();

        public boolean isEnabled() {
            return this.enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getRoutes() {
            return this.routes;
        }

        public void setRoutes(List<String> routes) {
            this.routes = routes;
        }

    }

    /**
     * Issuing passes from Feign clients.
     */
    public static class Feign {

        /**
         * Names of the Feign clients that attach a pass (the name or value of @FeignClient), or * for all of them.
         * Empty by default, so a client that calls a third-party API never sends one.
         */
        private List<String> clients = new ArrayList<>();

        public List<String> getClients() {
            return this.clients;
        }

        public void setClients(List<String> clients) {
            this.clients = clients;
        }

    }

}
