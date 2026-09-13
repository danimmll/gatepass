package io.github.danimmll.gatepass.gateway.mvc;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.jspecify.annotations.Nullable;

import io.github.danimmll.gatepass.internal.ByteArrayServletInputStream;

/**
 * A request whose body can be read into memory once, on demand, and then served from there as often as needed: to
 * sign it, to proxy it, and to proxy it again on a retry. Until something asks for the body, it streams as usual.
 */
final class BufferedBodyRequest extends HttpServletRequestWrapper {

    private byte @Nullable [] body;

    private boolean tooLarge;

    BufferedBodyRequest(HttpServletRequest request) {
        super(request);
    }

    /**
     * Reads the whole body into memory, the first time only.
     *
     * @param maxBytes the largest body accepted
     * @return the body, or {@code null} if it is larger than the limit
     */
    byte @Nullable [] buffer(long maxBytes) {
        byte[] buffered = this.body;
        if (buffered != null || this.tooLarge) {
            return buffered;
        }
        if (getContentLengthLong() > maxBytes) {
            this.tooLarge = true;
            return null;
        }
        try {
            byte[] read = super.getInputStream().readNBytes((int) Math.min(maxBytes + 1, Integer.MAX_VALUE));
            if (read.length > maxBytes) {
                this.tooLarge = true;
                return null;
            }
            this.body = read;
            return read;
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        byte[] buffered = this.body;
        return (buffered != null) ? new ByteArrayServletInputStream(buffered) : super.getInputStream();
    }

    @Override
    public BufferedReader getReader() throws IOException {
        byte[] buffered = this.body;
        if (buffered == null) {
            return super.getReader();
        }
        String encoding = getCharacterEncoding();
        Charset charset = (encoding != null) ? Charset.forName(encoding) : StandardCharsets.ISO_8859_1;
        return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(buffered), charset));
    }

}
