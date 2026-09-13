package io.github.danimmll.gatepass;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Remembers used passes in this JVM until they expire.
 *
 * <p>Only passes whose signature has already been checked are recorded, so the memory it uses grows with legitimate
 * traffic alone: at most one entry per request received during twice the maximum clock skew. Each entry is a 128-bit
 * hash of the pass id, stored flat in open-addressing tables, grouped by the second the pass expires in; forgetting
 * drops whole seconds at once.
 *
 * <p>Pass ids carry a random nonce, so two different ids share a hash with a probability of about 2<sup>-128</sup>.
 * The hash is MurmurHash3 (x64, 128 bits) over the UTF-16LE encoding of the id: fast, and unpredictable collisions are
 * all that is needed, since only genuine passes, with nonces nobody can choose in advance, are ever recorded.
 *
 * <p>It protects one instance. See {@link ReplayGuard} for services that run several.
 */
public final class InMemoryReplayGuard implements ReplayGuard {

    /** How long a second is kept once it has expired, so a request that stalled between its checks is still covered. */
    private static final long GRACE_SECONDS = 5;

    private static final int STRIPES = 16;

    private final Clock clock;

    private final ConcurrentHashMap<Long, Second> bySecond = new ConcurrentHashMap<>();

    private final AtomicLong lastPurge = new AtomicLong(Long.MIN_VALUE);

    /**
     * Creates a guard that uses the system clock.
     */
    public InMemoryReplayGuard() {
        this(Clock.systemUTC());
    }

    /**
     * Creates a guard.
     *
     * @param clock tells when remembered passes can be forgotten
     */
    public InMemoryReplayGuard(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public boolean firstUse(String passId, Instant expiresAt) {
        purge(this.clock.instant().getEpochSecond());
        long[] hash = murmur3(passId);
        return this.bySecond.computeIfAbsent(expiresAt.getEpochSecond(), second -> new Second()).add(hash[0], hash[1]);
    }

    /**
     * How many passes are remembered right now.
     *
     * @return the number of remembered passes
     */
    public int size() {
        int size = 0;
        for (Second second : this.bySecond.values()) {
            size += second.size();
        }
        return size;
    }

    private void purge(long now) {
        long last = this.lastPurge.get();
        if (now > last && this.lastPurge.compareAndSet(last, now)) {
            this.bySecond.keySet().removeIf(second -> second < now - GRACE_SECONDS);
        }
    }

    /** MurmurHash3_x64_128 of the UTF-16LE bytes of {@code value}, with seed 0. */
    static long[] murmur3(String value) {
        final long c1 = 0x87c37b91114253d5L;
        final long c2 = 0x4cf5ad432745937fL;
        int chars = value.length();
        long h1 = 0;
        long h2 = 0;
        int blocks = chars / 8;
        for (int block = 0; block < blocks; block++) {
            int i = block * 8;
            long k1 = value.charAt(i) | ((long) value.charAt(i + 1) << 16) | ((long) value.charAt(i + 2) << 32)
                    | ((long) value.charAt(i + 3) << 48);
            long k2 = value.charAt(i + 4) | ((long) value.charAt(i + 5) << 16) | ((long) value.charAt(i + 6) << 32)
                    | ((long) value.charAt(i + 7) << 48);
            k1 *= c1;
            k1 = Long.rotateLeft(k1, 31);
            k1 *= c2;
            h1 ^= k1;
            h1 = Long.rotateLeft(h1, 27);
            h1 += h2;
            h1 = h1 * 5 + 0x52dce729;
            k2 *= c2;
            k2 = Long.rotateLeft(k2, 33);
            k2 *= c1;
            h2 ^= k2;
            h2 = Long.rotateLeft(h2, 31);
            h2 += h1;
            h2 = h2 * 5 + 0x38495ab5;
        }
        int tail = blocks * 8;
        int remaining = chars - tail;
        long k1 = 0;
        long k2 = 0;
        for (int j = 0; j < remaining; j++) {
            long c = value.charAt(tail + j);
            if (j < 4) {
                k1 |= c << (16 * j);
            }
            else {
                k2 |= c << (16 * (j - 4));
            }
        }
        if (remaining > 4) {
            k2 *= c2;
            k2 = Long.rotateLeft(k2, 33);
            k2 *= c1;
            h2 ^= k2;
        }
        if (remaining > 0) {
            k1 *= c1;
            k1 = Long.rotateLeft(k1, 31);
            k1 *= c2;
            h1 ^= k1;
        }
        long length = 2L * chars;
        h1 ^= length;
        h2 ^= length;
        h1 += h2;
        h2 += h1;
        h1 = fmix64(h1);
        h2 = fmix64(h2);
        h1 += h2;
        h2 += h1;
        return new long[] { h1, h2 };
    }

    private static long fmix64(long k) {
        k ^= k >>> 33;
        k *= 0xff51afd7ed558ccdL;
        k ^= k >>> 33;
        k *= 0xc4ceb9fe1a85ec53L;
        k ^= k >>> 33;
        return k;
    }

    /** The passes that expire in one second, split into independently locked tables. */
    private static final class Second {

        private final Stripe[] stripes = new Stripe[STRIPES];

        private Second() {
            for (int i = 0; i < STRIPES; i++) {
                this.stripes[i] = new Stripe();
            }
        }

        boolean add(long hi, long lo) {
            return this.stripes[(int) (lo >>> 60) & (STRIPES - 1)].add(hi, lo);
        }

        int size() {
            int size = 0;
            for (Stripe stripe : this.stripes) {
                size += stripe.size();
            }
            return size;
        }

    }

    /** A set of 128-bit hashes: pairs of longs with linear probing. (0, 0) marks a free slot. */
    private static final class Stripe {

        private long[] slots = new long[4];

        private int size;

        synchronized boolean add(long hi, long lo) {
            if (hi == 0 && lo == 0) {
                lo = 1;
            }
            if ((this.size + 1) * 4 > (this.slots.length / 2) * 3) {
                grow();
            }
            return insert(this.slots, hi, lo);
        }

        synchronized int size() {
            return this.size;
        }

        private boolean insert(long[] table, long hi, long lo) {
            int mask = (table.length / 2) - 1;
            int index = (int) hi & mask;
            while (true) {
                int at = index * 2;
                if (table[at] == 0 && table[at + 1] == 0) {
                    table[at] = hi;
                    table[at + 1] = lo;
                    if (table == this.slots) {
                        this.size++;
                    }
                    return true;
                }
                if (table[at] == hi && table[at + 1] == lo) {
                    return false;
                }
                index = (index + 1) & mask;
            }
        }

        private void grow() {
            long[] old = this.slots;
            long[] grown = new long[old.length * 2];
            for (int at = 0; at < old.length; at += 2) {
                if (old[at] != 0 || old[at + 1] != 0) {
                    insert(grown, old[at], old[at + 1]);
                }
            }
            this.slots = grown;
        }

    }

}
