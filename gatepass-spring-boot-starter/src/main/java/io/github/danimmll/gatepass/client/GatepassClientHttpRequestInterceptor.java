package io.github.danimmll.gatepass.client;

import java.io.IOException;

import org.springframework.http.HttpRequest;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;

/**
 * Attaches a pass to the requests of a {@code RestClient}, a {@code RestTemplate}, or an HTTP interface client built
 * on either.
 *
 * <p>Never applied automatically: add it to the builders of the clients that call internal services, so the pass
 * never leaks to a third-party API.
 *
 * <pre>{@code
 * RestClient orders = builder.baseUrl("http://orders")
 *         .requestInterceptor(gatepassInterceptor)
 *         .build();
 * }</pre>
 */
public class GatepassClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    private final Gatepass gatepass;

    private final String headerName;

    private final BodySigning bodySigning;

    /**
     * Creates an interceptor that does not sign request bodies.
     *
     * @param gatepass issues the passes
     * @param headerName the header that carries the pass
     */
    public GatepassClientHttpRequestInterceptor(Gatepass gatepass, String headerName) {
        this(gatepass, headerName, BodySigning.disabled());
    }

    /**
     * Creates the interceptor.
     *
     * @param gatepass issues the passes
     * @param headerName the header that carries the pass
     * @param bodySigning whether passes cover request bodies
     * @throws io.github.danimmll.gatepass.GatepassConfigurationException if {@code gatepass} cannot issue such passes
     */
    public GatepassClientHttpRequestInterceptor(Gatepass gatepass, String headerName, BodySigning bodySigning) {
        gatepass.checkCanIssue(bodySigning);
        this.gatepass = gatepass;
        this.headerName = headerName;
        this.bodySigning = bodySigning;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        RequestParts parts = RequestParts.fromUri(request.getMethod().name(), request.getURI());
        MediaType contentType = request.getHeaders().getContentType();
        String pass;
        if (this.bodySigning.appliesTo((contentType != null) ? contentType.toString() : null)) {
            this.bodySigning.checkSize(body.length);
            pass = this.gatepass.issue(parts, body);
        }
        else {
            pass = this.gatepass.issue(parts);
        }
        request.getHeaders().set(this.headerName, pass);
        return execution.execute(request, body);
    }

}
