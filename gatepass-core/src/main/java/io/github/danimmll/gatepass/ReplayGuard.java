package io.github.danimmll.gatepass;

import java.time.Instant;

/**
 * Remembers which passes have already been used, so that each one is accepted only once.
 *
 * <p>{@link InMemoryReplayGuard} is the default, and it is enough while each service runs as a single instance.
 * With several instances of the same service, a pass copied from a request could still be sent to an instance that
 * has not seen it: back the guard with a store they all share instead, such as Redis
 * ({@code SET key value NX EXAT seconds}) or a database table with a unique key.
 */
@FunctionalInterface
public interface ReplayGuard {

    /**
     * Records the use of a pass, atomically.
     *
     * @param passId identifies the pass: unique per pass, at most 64 ASCII characters, safe as a key in any store
     * @param expiresAt when the pass stops being accepted anyway, so it can be forgotten from then on
     * @return {@code true} the first time this pass is seen, {@code false} every time after that
     */
    boolean firstUse(String passId, Instant expiresAt);

    /**
     * A guard that remembers nothing and accepts a pass again and again.
     *
     * @return a guard that always answers {@code true}
     */
    static ReplayGuard disabled() {
        return (passId, expiresAt) -> true;
    }

}
