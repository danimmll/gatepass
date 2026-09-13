package io.github.danimmll.gatepass.benchmarks;

import java.time.Instant;
import java.util.Base64;
import java.util.Random;

import io.github.danimmll.gatepass.InMemoryReplayGuard;

/**
 * How much heap each remembered pass takes. Not a JMH benchmark:
 * {@code java -cp benchmarks/target/benchmarks.jar io.github.danimmll.gatepass.benchmarks.ReplayGuardFootprint}
 */
public final class ReplayGuardFootprint {

    private ReplayGuardFootprint() {
    }

    public static void main(String[] args) throws InterruptedException {
        int passes = (args.length > 0) ? Integer.parseInt(args[0]) : 1_000_000;
        Random random = new Random(42);
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        byte[] nonce = new byte[16];
        Instant now = Instant.now();

        long before = usedHeap();
        InMemoryReplayGuard guard = new InMemoryReplayGuard();
        for (int i = 0; i < passes; i++) {
            random.nextBytes(nonce);
            // Built inside the loop, as Gatepass builds each id per request, so the ids the guard keeps are counted.
            String passId = "hs256.ec609b60." + encoder.encodeToString(nonce);
            // Spread over a minute, like real traffic with the default clock skew.
            guard.firstUse(passId, now.plusSeconds(1 + (i % 60)));
        }
        long after = usedHeap();

        long bytes = after - before;
        System.out.printf("%,d passes remembered in %,d bytes: about %d bytes each%n", guard.size(), bytes,
                bytes / passes);
    }

    private static long usedHeap() throws InterruptedException {
        Runtime runtime = Runtime.getRuntime();
        for (int i = 0; i < 5; i++) {
            System.gc();
            Thread.sleep(100);
        }
        return runtime.totalMemory() - runtime.freeMemory();
    }

}
