package io.github.danimmll.gatepass.feign;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import feign.Target;
import org.jspecify.annotations.Nullable;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;

/**
 * Attaches a pass to the requests of the Feign clients you name, and only those, so the pass never leaks to a Feign
 * client that calls a third-party API.
 *
 * <p>Feign runs interceptors again on every retry, so each attempt gets a fresh pass.
 */
public class GatepassFeignRequestInterceptor implements RequestInterceptor {

    private static final byte[] EMPTY = new byte[0];

    private final Gatepass gatepass;

    private final String headerName;

    private final List<String> clientNames;

    private final BodySigning bodySigning;

    /**
     * Creates an interceptor that does not sign request bodies.
     *
     * @param gatepass issues the passes
     * @param headerName the header that carries the pass
     * @param clientNames names of the clients that get a pass ({@code name} or {@code value} of
     * {@code @FeignClient}), or {@code *} for all of them
     */
    public GatepassFeignRequestInterceptor(Gatepass gatepass, String headerName, List<String> clientNames) {
        this(gatepass, headerName, clientNames, BodySigning.disabled());
    }

    /**
     * Creates the interceptor.
     *
     * @param gatepass issues the passes
     * @param headerName the header that carries the pass
     * @param clientNames names of the clients that get a pass ({@code name} or {@code value} of
     * {@code @FeignClient}), or {@code *} for all of them
     * @param bodySigning whether passes cover request bodies
     * @throws io.github.danimmll.gatepass.GatepassConfigurationException if {@code gatepass} cannot issue such passes
     */
    public GatepassFeignRequestInterceptor(Gatepass gatepass, String headerName, List<String> clientNames,
            BodySigning bodySigning) {
        gatepass.checkCanIssue(bodySigning);
        this.gatepass = gatepass;
        this.headerName = headerName;
        this.clientNames = List.copyOf(clientNames);
        this.bodySigning = bodySigning;
    }

    @Override
    public void apply(RequestTemplate template) {
        Target<?> target = template.feignTarget();
        if (target == null || !signs(target.name())) {
            return;
        }
        String url = finalUrl(template, target);
        if (url == null) {
            return;
        }
        RequestParts parts = RequestParts.fromUrl(template.method(), url);
        String pass;
        if (this.bodySigning.appliesTo(contentType(template))) {
            byte[] body = template.body();
            byte[] signed = (body != null) ? body : EMPTY;
            this.bodySigning.checkSize(signed.length);
            pass = this.gatepass.issue(parts, signed);
        }
        else {
            pass = this.gatepass.issue(parts);
        }
        template.removeHeader(this.headerName);
        template.header(this.headerName, pass);
    }

    private boolean signs(@Nullable String clientName) {
        return this.clientNames.contains("*") || (clientName != null && this.clientNames.contains(clientName));
    }

    private static @Nullable String contentType(RequestTemplate template) {
        for (Map.Entry<String, Collection<String>> header : template.headers().entrySet()) {
            if ("Content-Type".equalsIgnoreCase(header.getKey()) && !header.getValue().isEmpty()) {
                return header.getValue().iterator().next();
            }
        }
        return null;
    }

    /**
     * Interceptors run before the target prepends its base URL (which may carry a path of its own, such as the
     * {@code path} attribute of {@code @FeignClient}). Replaying on a copy what {@code Target.apply} is about to do
     * gives the exact URL that will go on the wire.
     */
    private static @Nullable String finalUrl(RequestTemplate template, Target<?> target) {
        try {
            RequestTemplate copy = RequestTemplate.from(template);
            if (copy.url().indexOf("http") != 0) {
                copy.target(target.url());
            }
            return copy.url();
        }
        catch (RuntimeException ex) {
            // A target without a usable URL. Feign is about to fail on it anyway, with a clearer message.
            return null;
        }
    }

}
