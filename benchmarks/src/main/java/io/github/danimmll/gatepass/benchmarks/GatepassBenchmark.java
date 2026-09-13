package io.github.danimmll.gatepass.benchmarks;

import java.net.URI;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import io.github.danimmll.gatepass.Gatepass;
import io.github.danimmll.gatepass.GatepassKeys;
import io.github.danimmll.gatepass.ReplayGuard;
import io.github.danimmll.gatepass.RequestParts;
import io.github.danimmll.gatepass.Verification;

/**
 * What issuing and checking a pass costs, per request.
 *
 * <p>Replay protection is off in the receivers so the same pass can be checked again and again; its own cost is
 * measured by {@link ReplayGuardBenchmark}.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
public class GatepassBenchmark {

    private static final String SECRET = "benchmark-secret-0123456789abcdefghijklmnop";

    private final RequestParts request = RequestParts.of("GET", "/orders/42", "expand=true");

    private final URI uri = URI.create("http://orders:8080/orders/42?expand=true");

    private final byte[] body = new byte[1024];

    private Gatepass hmac;

    private Gatepass ed25519Sender;

    private Gatepass ed25519Receiver;

    private String hmacPass;

    private String hmacPassWithBody;

    private String ed25519Pass;

    @Setup
    public void setUp() {
        new Random(42).nextBytes(this.body);
        this.hmac = Gatepass.builder()
                .secrets(SECRET)
                .replayGuard(ReplayGuard.disabled())
                .maxClockSkew(Duration.ofDays(1))
                .build();
        GatepassKeys.GeneratedKeys keys = GatepassKeys.generate();
        this.ed25519Sender = Gatepass.builder().privateKey(keys.privateKey()).build();
        this.ed25519Receiver = Gatepass.builder()
                .trustedService("orders", keys.publicKey())
                .replayGuard(ReplayGuard.disabled())
                .maxClockSkew(Duration.ofDays(1))
                .build();
        this.hmacPass = this.hmac.issue(this.request);
        this.hmacPassWithBody = this.hmac.issue(this.request, this.body);
        this.ed25519Pass = this.ed25519Sender.issue(this.request);
    }

    @Benchmark
    public String issueHmac() {
        return this.hmac.issue(this.request);
    }

    @Benchmark
    public Verification verifyHmac() {
        return this.hmac.verify(this.hmacPass, this.request);
    }

    @Benchmark
    public boolean verifyHmacWithOneKilobyteBody() {
        return this.hmac.verify(this.hmacPassWithBody, this.request).bodyMatches(this.body);
    }

    @Benchmark
    public String issueEd25519() {
        return this.ed25519Sender.issue(this.request);
    }

    @Benchmark
    public Verification verifyEd25519() {
        return this.ed25519Receiver.verify(this.ed25519Pass, this.request);
    }

    @Benchmark
    public RequestParts requestPartsFromUri() {
        return RequestParts.fromUri("GET", this.uri);
    }

}
