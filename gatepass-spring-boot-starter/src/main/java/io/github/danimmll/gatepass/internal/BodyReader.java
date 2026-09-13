package io.github.danimmll.gatepass.internal;

import java.util.Arrays;

import org.reactivestreams.Publisher;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reads a reactive body into a single array. Each chunk is copied once, straight into the array, and released right
 * away; a body over the limit fails with {@link DataBufferLimitException} as soon as it crosses it.
 */
public final class BodyReader {

    private static final int DEFAULT_CAPACITY = 256;

    private BodyReader() {
    }

    /**
     * Reads a body.
     *
     * @param body the body
     * @param maxBytes the largest body accepted
     * @param declaredLength the {@code Content-Length}, or a negative number when unknown; it only sizes the array
     * @return the whole body, empty when there is none
     */
    public static Mono<byte[]> read(Publisher<? extends DataBuffer> body, long maxBytes, long declaredLength) {
        return Flux.from(body)
                .collect(() -> new Collector(maxBytes, declaredLength), Collector::add)
                .map(Collector::toArray)
                .doOnDiscard(DataBuffer.class, DataBufferUtils::release);
    }

    private static final class Collector {

        private final long maxBytes;

        private byte[] bytes;

        private int size;

        private Collector(long maxBytes, long declaredLength) {
            this.maxBytes = maxBytes;
            this.bytes = new byte[(int) ((declaredLength >= 0 && declaredLength <= maxBytes) ? declaredLength
                    : Math.min(DEFAULT_CAPACITY, maxBytes))];
        }

        private void add(DataBuffer buffer) {
            try {
                int readable = buffer.readableByteCount();
                if (this.size + (long) readable > this.maxBytes) {
                    throw new DataBufferLimitException("Body larger than " + this.maxBytes + " bytes");
                }
                if (this.size + readable > this.bytes.length) {
                    long grown = Math.max(this.bytes.length * 2L, (long) this.size + readable);
                    this.bytes = Arrays.copyOf(this.bytes, (int) Math.min(grown, this.maxBytes));
                }
                buffer.read(this.bytes, this.size, readable);
                this.size += readable;
            }
            finally {
                DataBufferUtils.release(buffer);
            }
        }

        private byte[] toArray() {
            return (this.size == this.bytes.length) ? this.bytes : Arrays.copyOf(this.bytes, this.size);
        }

    }

}
