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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

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
    void remembersEveryOneOfManyPassesAsItsTablesGrow() {
        int passes = 100_000;
        for (int i = 0; i < passes; i++) {
            assertThat(this.guard.firstUse("hs256.ec609b60.nonce-" + i, NOW.plusSeconds(1 + (i % 60)))).isTrue();
        }

        assertThat(this.guard.size()).isEqualTo(passes);
        for (int i = 0; i < passes; i++) {
            assertThat(this.guard.firstUse("hs256.ec609b60.nonce-" + i, NOW.plusSeconds(1 + (i % 60)))).isFalse();
        }
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

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            // Computed with Guava's Hashing.murmur3_128() over the UTF-16LE bytes of each input.
            "''                                     | 0x0000000000000000 | 0x0000000000000000",
            "a                                      | 0x96a698500b4e98bd | 0xb278c9bfc754677d",
            "abcd                                   | 0x548cfc581a584f48 | 0x076f42dc4bbe30df",
            "abcde                                  | 0xef8464c206cb30ec | 0xcc827c3e934dfa4b",
            "abcdefg                                | 0xa0c7451959a72be9 | 0xa2e258a1ac2474a2",
            "abcdefgh                               | 0x2803a5bc696daeb2 | 0xa2b1eb7540d6d1fa",
            "abcdefghi                              | 0x1ac6acfe7367072e | 0xceacd682c36f564a",
            "hs256.ec609b60.AAECAwQFBgcICQoLDA0ODw  | 0x1993a760fec88a32 | 0x29d154f7e596cb6e",
    })
    void hashesPassIdsWithMurmurHash3(String input, String h1, String h2) {
        assertThat(InMemoryReplayGuard.murmur3(input))
                .containsExactly(Long.parseUnsignedLong(h1.substring(2), 16), Long.parseUnsignedLong(h2.substring(2), 16));
    }

    @Test
    void hashesNonAsciiPassIdsWithMurmurHash3() {
        assertThat(InMemoryReplayGuard.murmur3("café € 𝄞"))
                .containsExactly(0x6dcf29eb117e02aaL, 0x71d1a7b72d34d137L);
    }

    @Test
    void theDisabledGuardAcceptsEverythingAgain() {
        ReplayGuard disabled = ReplayGuard.disabled();

        assertThat(disabled.firstUse("pass", NOW)).isTrue();
        assertThat(disabled.firstUse("pass", NOW)).isTrue();
    }

}
