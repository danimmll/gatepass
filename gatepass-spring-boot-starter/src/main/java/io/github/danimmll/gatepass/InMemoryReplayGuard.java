package io.github.danimmll.gatepass;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Remembers used passes in this JVM until they expire.
 *
 * <p>Only passes whose signature has already been checked are recorded, so the memory it uses grows with legitimate
 * traffic alone: at most one entry per request received during twice the maximum clock skew. Forgetting is cheap,
 * because passes are grouped by the second they expire in and whole seconds are dropped at once.
 *
 * <p>It protects one instance. See {@link ReplayGuard} for services that run several.
 */
public final class InMemoryReplayGuard implements ReplayGuard {

    /** How long a second is kept once it has expired, so a request that stalled between its checks is still covered. */
    private static final long GRACE_SECONDS = 5;

    private final Clock clock;

    private final ConcurrentHashMap<Long, Set<String>> byExpirySecond = new ConcurrentHashMap<>();

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
        return this.byExpirySecond.computeIfAbsent(expiresAt.getEpochSecond(), second -> ConcurrentHashMap.newKeySet())
                .add(passId);
    }

    /**
     * How many passes are remembered right now.
     *
     * @return the number of remembered passes
     */
    public int size() {
        int size = 0;
        for (Set<String> passes : this.byExpirySecond.values()) {
            size += passes.size();
        }
        return size;
    }

    private void purge(long now) {
        long last = this.lastPurge.get();
        if (now > last && this.lastPurge.compareAndSet(last, now)) {
            this.byExpirySecond.keySet().removeIf(second -> second < now - GRACE_SECONDS);
        }
    }

}
