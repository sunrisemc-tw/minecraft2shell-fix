package dev.duckducktw.m2sfix.agent;

import dev.duckducktw.m2sfix.core.FixPolicy;
import dev.duckducktw.m2sfix.core.ImageGuard;
import java.nio.ByteBuffer;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thin adapter between {@link AgentBridge} and {@link ImageGuard}.
 *
 * <p>Kept separate so the bridge stays readable and so the "log once per distinct complaint"
 * bookkeeping has one home. It also means the agent and the mod can share the same core decision
 * code while differing only in how they are wired.</p>
 */
final class ImageGuardAdapters {

    private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();
    private static final int MAX_LOG_ENTRIES = 64;

    private ImageGuardAdapters() {
    }

    static boolean isDisabled() {
        try {
            return !FixPolicy.enabled() || !FixPolicy.imageGuardEnabled();
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * @return {@code true} when the image must not reach the native decoder
     */
    static boolean inspect(ByteBuffer image, StringBuilder reason) {
        try {
            return ImageGuard.inspect(image, FixPolicy.imageMaxPixels(),
                    ImageGuard.DEFAULT_MAX_BYTES, reason) == ImageGuard.Verdict.REJECT;
        } catch (Throwable ignored) {
            return false;
        }
    }

    static void logRejection(String reason) {
        try {
            if (!FixPolicy.logEnabled()) {
                return;
            }
            String key = reason == null ? "unknown" : reason;
            if (LOGGED.size() > MAX_LOG_ENTRIES) {
                LOGGED.clear();
            }
            if (LOGGED.add(key)) {
                System.err.println("[m2sfix] refused image: " + key);
            }
        } catch (Throwable ignored) {
            // Logging must never be the reason a texture fails to load.
        }
    }
}
