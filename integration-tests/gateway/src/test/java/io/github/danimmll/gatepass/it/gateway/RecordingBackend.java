package io.github.danimmll.gatepass.it.gateway;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.sun.net.httpserver.HttpServer;

/**
 * A bare JDK HTTP server standing in for a service: it records what reached it, exactly as it arrived.
 */
final class RecordingBackend {

    record Received(String method, String rawPath, String rawQuery, List<String> passes, byte[] body) {
    }

    private final HttpServer server;

    private final BlockingQueue<Received> received = new LinkedBlockingQueue<>();

    private final Queue<Integer> statuses = new ConcurrentLinkedQueue<>();

    private RecordingBackend() {
        try {
            this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        this.server.createContext("/", exchange -> {
            List<String> passes = exchange.getRequestHeaders().get("X-Gatepass");
            String rawQuery = exchange.getRequestURI().getRawQuery();
            byte[] body = exchange.getRequestBody().readAllBytes();
            this.received.add(new Received(exchange.getRequestMethod(), exchange.getRequestURI().getRawPath(),
                    (rawQuery != null) ? rawQuery : "", (passes != null) ? List.copyOf(passes) : List.of(), body));
            Integer status = this.statuses.poll();
            byte[] response = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders((status != null) ? status : 200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
    }

    static RecordingBackend start() {
        RecordingBackend backend = new RecordingBackend();
        backend.server.start();
        return backend;
    }

    String url() {
        return "http://127.0.0.1:" + this.server.getAddress().getPort();
    }

    /** The next request gets this status instead of 200. */
    void respondNextWith(int status) {
        this.statuses.add(status);
    }

    Received next() throws InterruptedException {
        Received next = this.received.poll(5, TimeUnit.SECONDS);
        if (next == null) {
            throw new AssertionError("Nothing reached the backend");
        }
        return next;
    }

    void expectNothing() throws InterruptedException {
        Received unexpected = this.received.poll(500, TimeUnit.MILLISECONDS);
        if (unexpected != null) {
            throw new AssertionError("Expected nothing to reach the backend, but got " + unexpected.method() + " "
                    + unexpected.rawPath());
        }
    }

    void clear() {
        this.received.clear();
        this.statuses.clear();
    }

    void stop() {
        this.server.stop(0);
    }

}
