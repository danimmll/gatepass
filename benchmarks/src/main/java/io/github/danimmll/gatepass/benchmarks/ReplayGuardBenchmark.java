package io.github.danimmll.gatepass.benchmarks;

import java.time.Instant;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import io.github.danimmll.gatepass.InMemoryReplayGuard;

/**
 * What remembering a pass costs, with several threads recording passes at once.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
@Threads(4)
public class ReplayGuardBenchmark {

    private static final int PASSES = 1 << 20;

    private final String[] passIds = new String[PASSES];

    private final AtomicInteger next = new AtomicInteger();

    private InMemoryReplayGuard guard;

    private Instant expiresAt;

    @Setup(Level.Trial)
    public void createPassIds() {
        Random random = new Random(42);
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        byte[] nonce = new byte[16];
        for (int i = 0; i < PASSES; i++) {
            random.nextBytes(nonce);
            this.passIds[i] = "hs256.ec609b60." + encoder.encodeToString(nonce);
        }
    }

    @Setup(Level.Iteration)
    public void createGuard() {
        this.guard = new InMemoryReplayGuard();
        this.expiresAt = Instant.now().plusSeconds(30);
    }

    @Benchmark
    public boolean firstUse() {
        return this.guard.firstUse(this.passIds[this.next.getAndIncrement() & (PASSES - 1)], this.expiresAt);
    }

}
