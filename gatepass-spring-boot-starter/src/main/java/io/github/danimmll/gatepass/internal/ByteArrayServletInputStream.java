package io.github.danimmll.gatepass.internal;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;

/**
 * A request body already held in memory, served as a {@link ServletInputStream}.
 */
public final class ByteArrayServletInputStream extends ServletInputStream {

    private final ByteArrayInputStream body;

    /**
     * Serves these bytes.
     *
     * @param body the complete body
     */
    public ByteArrayServletInputStream(byte[] body) {
        this.body = new ByteArrayInputStream(body);
    }

    @Override
    public boolean isFinished() {
        return this.body.available() == 0;
    }

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public void setReadListener(ReadListener listener) {
        try {
            listener.onDataAvailable();
            listener.onAllDataRead();
        }
        catch (IOException ex) {
            listener.onError(ex);
        }
    }

    @Override
    public int read() {
        return this.body.read();
    }

    @Override
    public int read(byte[] buffer, int offset, int length) {
        return this.body.read(buffer, offset, length);
    }

    @Override
    public int available() {
        return this.body.available();
    }

}
