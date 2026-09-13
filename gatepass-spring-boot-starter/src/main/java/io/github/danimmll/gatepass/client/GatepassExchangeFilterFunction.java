package io.github.danimmll.gatepass.client;

import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ClientHttpRequest;
import org.springframework.http.client.reactive.ClientHttpRequestDecorator;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import io.github.danimmll.gatepass.BodySigning;
import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.RequestParts;

/**
 * Attaches a pass to the requests of a {@code WebClient}.
 *
 * <p>Never applied automatically: add it to the builders of the clients that call internal services, so the pass
 * never leaks to a third-party API.
 *
 * <pre>{@code
 * WebClient orders = builder.baseUrl("http://orders")
 *         .filter(gatepassFilter)
 *         .build();
 * }</pre>
 *
 * <p>The pass is issued when the request is actually sent, so every retry gets a fresh one. With body signing on, the
 * body is collected in memory, up to the configured limit, once the codecs have written it; a larger body fails the
 * request instead of going out unsigned.
 */
public class GatepassExchangeFilterFunction implements ExchangeFilterFunction {

    private static final byte[] EMPTY = new byte[0];

    private final Gatepass gatepass;

    private final String headerName;

    private final BodySigning bodySigning;

    /**
     * Creates a filter that does not sign request bodies.
     *
     * @param gatepass issues the passes
     * @param headerName the header that carries the pass
     */
    public GatepassExchangeFilterFunction(Gatepass gatepass, String headerName) {
        this(gatepass, headerName, BodySigning.disabled());
    }

    /**
     * Creates the filter.
     *
     * @param gatepass issues the passes
     * @param headerName the header that carries the pass
     * @param bodySigning whether passes cover request bodies
     * @throws io.github.danimmll.gatepass.GatepassConfigurationException if {@code gatepass} cannot issue such passes
     */
    public GatepassExchangeFilterFunction(Gatepass gatepass, String headerName, BodySigning bodySigning) {
        gatepass.checkCanIssue(bodySigning);
        this.gatepass = gatepass;
        this.headerName = headerName;
        this.bodySigning = bodySigning;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        String method = request.method().name();
        if (!this.bodySigning.enabled()) {
            return Mono.defer(() -> {
                String pass = this.gatepass.issue(RequestParts.fromUri(method, request.url()));
                return next.exchange(ClientRequest.from(request)
                        .headers(headers -> headers.set(this.headerName, pass))
                        .build());
            });
        }
        BodyInserter<?, ? super ClientHttpRequest> original = request.body();
        BodyInserter<Object, ClientHttpRequest> signing = (message, context) -> original
                .insert(new SigningRequest(message, RequestParts.fromUri(method, request.url())), context);
        return next.exchange(ClientRequest.from(request).body(signing).build());
    }

    private static byte[] toBytes(DataBuffer buffer, int maxBytes) {
        try {
            // join() hands a Mono back as it is, without applying its limit, and codecs write single values as one.
            if (buffer.readableByteCount() > maxBytes) {
                throw new DataBufferLimitException("Body larger than " + maxBytes + " bytes");
            }
            byte[] bytes = new byte[buffer.readableByteCount()];
            buffer.read(bytes);
            return bytes;
        }
        finally {
            DataBufferUtils.release(buffer);
        }
    }

    /** Signs once the codecs have produced the body, right before the headers are sent. */
    private final class SigningRequest extends ClientHttpRequestDecorator {

        private final RequestParts parts;

        private SigningRequest(ClientHttpRequest delegate, RequestParts parts) {
            super(delegate);
            this.parts = parts;
        }

        @Override
        public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
            if (!signsBody()) {
                sign(null);
                return super.writeWith(body);
            }
            int maxBytes = GatepassExchangeFilterFunction.this.bodySigning.maxBytesAsInt();
            return DataBufferUtils.join(body, maxBytes)
                    .map(buffer -> toBytes(buffer, maxBytes))
                    .onErrorMap(DataBufferLimitException.class, ex -> new IllegalStateException("The request body is"
                            + " over the " + maxBytes + " bytes Gatepass agrees to sign (gatepass.body.max-size)", ex))
                    .defaultIfEmpty(EMPTY)
                    .flatMap(bytes -> {
                        sign(bytes);
                        return super.writeWith(Mono.just(bufferFactory().wrap(bytes)));
                    });
        }

        @Override
        public Mono<Void> writeAndFlushWith(Publisher<? extends Publisher<? extends DataBuffer>> body) {
            if (!signsBody()) {
                sign(null);
                return super.writeAndFlushWith(body);
            }
            return writeWith(Flux.from(body).concatMap(part -> part));
        }

        @Override
        public Mono<Void> setComplete() {
            sign(signsBody() ? EMPTY : null);
            return super.setComplete();
        }

        private boolean signsBody() {
            MediaType contentType = getHeaders().getContentType();
            return GatepassExchangeFilterFunction.this.bodySigning
                    .appliesTo((contentType != null) ? contentType.toString() : null);
        }

        private void sign(byte @Nullable [] body) {
            Gatepass gatepass = GatepassExchangeFilterFunction.this.gatepass;
            String pass = (body != null) ? gatepass.issue(this.parts, body) : gatepass.issue(this.parts);
            getHeaders().set(GatepassExchangeFilterFunction.this.headerName, pass);
        }

    }

}
