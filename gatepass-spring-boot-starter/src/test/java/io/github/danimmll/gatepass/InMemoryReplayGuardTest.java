package io.github.danimmll.gatepass;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryReplayGuardTest {

    private static final Instant NOW = Instant.parse("2026-09-13T10:00:00Z");

    private final TestClock clock = new TestClock(NOW);

    private final InMemoryReplayGuard guard = new InMemoryReplayGuard(this.clock);

    @Test
    void acceptsAPassOnceOnly() {
        assertThat(this.guard.firstUse("hs256.ec609b60.nonce", NOW.plusSeconds(30))).isTrue();
        assertThat(this.guard.firstUse("hs256.ec609b60.nonce", NOW.plusSeconds(30))).isFalse();
        assertThat(this.guard.firstUse("hs256.ec609b60.another", NOW.plusSeconds(30))).isTrue();
    }

    @Test
    void remembersAPassUntilItHasBeenExpiredForTheGracePeriod() {
        this.guard.firstUse("pass", NOW.plusSeconds(30));

        this.clock.advance(Duration.ofSeconds(35));
        assertThat(this.guard.firstUse("pass", NOW.plusSeconds(30))).isFalse();
    }

    @Test
    void forgetsPassesOnceTheyCanNoLongerBeAccepted() {
        this.guard.firstUse("old", NOW.plusSeconds(30));
        this.guard.firstUse("older", NOW.plusSeconds(29));

        this.clock.advance(Duration.ofSeconds(36));
        this.guard.firstUse("new", NOW.plusSeconds(66));

        assertThat(this.guard.size()).isEqualTo(1);
    }

    @Test
    void letsExactlyOneOfManySimultaneousUsesThrough() throws Exception {
        int threads = 16;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                results.add(executor.submit(() -> {
                    start.await();
                    return this.guard.firstUse("contended", NOW.plusSeconds(30));
                }));
            }
            start.countDown();
            int accepted = 0;
            for (Future<Boolean> result : results) {
                accepted += result.get() ? 1 : 0;
            }
            assertThat(accepted).isEqualTo(1);
        }
        finally {
            executor.shutdownNow();
        }
    }

    @Test
    void theDisabledGuardAcceptsEverythingAgain() {
        ReplayGuard disabled = ReplayGuard.disabled();

        assertThat(disabled.firstUse("pass", NOW)).isTrue();
        assertThat(disabled.firstUse("pass", NOW)).isTrue();
    }

}
