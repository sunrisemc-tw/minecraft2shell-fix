package dev.duckducktw.m2sfix.core;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Shared policy brain used by both the Java agent and the Mixin mod.
 *
 * <p>Every public method is defensive: it must never throw into Minecraft. A
 * face is remembered by its native address only after the scanner flags it, so
 * clean fonts have zero further overhead and are never touched.</p>
 */
public final class FaceGuard {

    public static final int FT_LOAD_NO_HINTING = 0x2;
    public static final int FT_LOAD_NO_AUTOHINT = 0x8000;
    /**
     * What we OR into the load flags. {@code FT_LOAD_NO_HINTING} alone is not enough for every face:
     * {@code tt_glyph_load} (ttdriver.c) can clear it unless {@code FT_LOAD_NO_AUTOHINT} is also set.
     */
    public static final int NO_HINTING_FLAGS = FT_LOAD_NO_HINTING | FT_LOAD_NO_AUTOHINT;
    public static final int FT_ERR_INVALID_FILE_FORMAT = 0x02;
    public static final int MAX_ENTRIES = 4096;
    public static final int MAX_FONT_BYTES = 64 * 1024 * 1024;

    private static final ConcurrentHashMap<Long, ScanResult> FLAGGED_FACES = new ConcurrentHashMap<>();
    private static final Set<String> LOGGED_FONT_HASHES = ConcurrentHashMap.newKeySet();
    private static final AtomicBoolean DISABLED = new AtomicBoolean(false);
    private static final AtomicBoolean LOGGED_FACE_HOOK = new AtomicBoolean();
    private static final AtomicBoolean LOGGED_GLYPH_HOOK = new AtomicBoolean();
    private static final AtomicBoolean LOGGED_CHAR_HOOK = new AtomicBoolean();

    private FaceGuard() {
    }

    /** Returns a FreeType error code when block policy rejects the font before native loading. */
    public static int beforeNewFace(ByteBuffer fontData) {
        try {
            if (DISABLED.get()) {
                return 0;
            }
            FixPolicy.Settings settings = FixPolicy.current();
            logIntercept(LOGGED_FACE_HOOK, "FT_New_Memory_Face", settings);
            if (settings.policy() == FixPolicy.Policy.BLOCK && fontData != null
                    && inspectNewFace(0L, fontData, fontData.remaining())) {
                return FT_ERR_INVALID_FILE_FORMAT;
            }
        } catch (Throwable ignored) {
            // Leave native validation in charge on guard failure.
        }
        return 0;
    }

    /** Records the verdict for a face successfully created by FreeType. */
    public static void afterNewFace(long faceAddress, ByteBuffer fontData) {
        // Also under BLOCK: faces it lets through (RISKY, UNPARSABLE) must still lose hinting.
        if (fontData != null) {
            inspectNewFace(faceAddress, fontData, fontData.remaining());
        }
    }

    /**
     * Inspects a face right after FreeType created it.
     *
     * @param faceAddress native {@code FT_Face} address (may be 0 if unknown)
     * @param fontData    font bytes as passed to {@code FT_New_Memory_Face}
     * @param size        declared font size
     * @return {@code true} when this face must lose hinting
     */
    public static boolean inspectNewFace(long faceAddress, ByteBuffer fontData, long size) {
        try {
            if (DISABLED.get()) {
                return false;
            }

            FixPolicy.Settings settings = FixPolicy.current();
            if (!settings.enabled() || settings.policy() == FixPolicy.Policy.OFF) {
                FLAGGED_FACES.remove(faceAddress);
                return false;
            }
            if (fontData == null || size <= 0 || !fontData.hasRemaining()) {
                return false;
            }

            int scanLimit = FixPolicy.maxScanBytes();
            long available = Math.min(size, fontData.remaining());
            boolean capped = available > scanLimit;
            int bytesToRead = (int) Math.min(available, scanLimit);
            if (bytesToRead <= 0) {
                return false;
            }

            byte[] bytes = new byte[bytesToRead];
            ByteBuffer view = fontData.duplicate();
            view.get(bytes, 0, bytesToRead);

            String hash = sha256Hex(bytes);
            if (hash != null && settings.sha256Allowlist().contains(hash)) {
                FLAGGED_FACES.remove(faceAddress);
                return false;
            }

            ScanResult result = TtfScanner.scan(bytes);
            if (capped && result.verdict() == ScanResult.Verdict.CLEAN) {
                result = new ScanResult(
                        ScanResult.Verdict.UNPARSABLE,
                        "font exceeds the " + scanLimit + "-byte scan limit");
            }

            boolean degradeHinting = switch (result.verdict()) {
                case CLEAN -> false;
                case RISKY, SUSPICIOUS -> true;
                case UNPARSABLE -> settings.unparsablePolicy() == FixPolicy.UnparsablePolicy.HINTLESS;
            };
            if (!degradeHinting) {
                FLAGGED_FACES.remove(faceAddress);
                return false;
            }

            if (faceAddress != 0L) {
                remember(faceAddress, result);
            }
            if (settings.logEnabled()
                    && (result.verdict() != ScanResult.Verdict.RISKY
                            || settings.policy() == FixPolicy.Policy.HINTLESS)) {
                logOnce(hash, result);
            }
            if (result.verdict() == ScanResult.Verdict.SUSPICIOUS && seenOnce(hash, "notified")) {
                Notify.warnAboutBlockedFont();
            }
            if (settings.policy() == FixPolicy.Policy.BLOCK) {
                return result.verdict() == ScanResult.Verdict.SUSPICIOUS;
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Returns the load flags to use for a face.
     *
     * <p>In the default {@link FixPolicy.Policy#SAFE} mode every face gets
     * {@link #NO_HINTING_FLAGS}, flagged or not: the interpreter simply never runs, so no font can
     * reach the {@code SHZ} primitive and no future variant has to be recognised first. In
     * {@code hintless} mode only flagged faces are affected.</p>
     *
     * @param faceAddress native {@code FT_Face} address
     * @param flags       caller-supplied {@code FT_Load_Glyph} flags
     * @return the flags to use
     */
    public static int adjustLoadFlags(long faceAddress, int flags) {
        return adjustLoadFlags(faceAddress, flags, LOGGED_GLYPH_HOOK, "FT_Load_Glyph");
    }

    public static int adjustCharLoadFlags(long faceAddress, int flags) {
        return adjustLoadFlags(faceAddress, flags, LOGGED_CHAR_HOOK, "FT_Load_Char");
    }

    private static int adjustLoadFlags(long faceAddress, int flags, AtomicBoolean logged, String hook) {
        try {
            if (DISABLED.get()) {
                return flags;
            }
            FixPolicy.Settings settings = FixPolicy.current();
            logIntercept(logged, hook, settings);
            if (!settings.enabled() || settings.policy() == FixPolicy.Policy.OFF) {
                return flags;
            }
            if (settings.policy() == FixPolicy.Policy.SAFE) {
                return flags | NO_HINTING_FLAGS;
            }
            if (faceAddress == 0L || !FLAGGED_FACES.containsKey(faceAddress)) {
                return flags;
            }
            return flags | NO_HINTING_FLAGS;
        } catch (Throwable ignored) {
            return flags;
        }
    }

    /**
     * Called before the native {@code FT_Load_Glyph}.
     *
     * @param faceAddress native {@code FT_Face} address
     * @return {@code 0} to continue, or a FreeType error code to return early
     */
    public static int beforeLoadGlyph(long faceAddress) {
        try {
            if (DISABLED.get()) {
                return 0;
            }
            FixPolicy.Settings settings = FixPolicy.current();
            if (!settings.enabled() || settings.policy() != FixPolicy.Policy.BLOCK) {
                return 0;
            }
            ScanResult result = FLAGGED_FACES.get(faceAddress);
            return result != null && result.verdict() == ScanResult.Verdict.SUSPICIOUS
                    ? FT_ERR_INVALID_FILE_FORMAT
                    : 0;
        } catch (Throwable ignored) {
            return 0;
        }
    }

    /**
     * @param faceAddress native {@code FT_Face} address
     * @return whether that face was judged hostile (used by tests and by the warning path)
     */
    public static boolean wasFlaggedForTests(long faceAddress) {
        return FLAGGED_FACES.containsKey(faceAddress);
    }

    /** Clears remembered faces and reloads policy. Test-only. */
    public static void clearForTests() {
        try {
            FLAGGED_FACES.clear();
            LOGGED_FONT_HASHES.clear();
            DISABLED.set(false);
            LOGGED_FACE_HOOK.set(false);
            LOGGED_GLYPH_HOOK.set(false);
            LOGGED_CHAR_HOOK.set(false);
            FixPolicy.reloadForTests();
        } catch (Throwable ignored) {
            // Test helper: never throw.
        }
    }

    /**
     * Permanently disables the guard. Used by the agent if its own installation
     * fails; a disabled guard is always preferable to a broken client.
     */
    public static void disableForFailure() {
        DISABLED.set(true);
        FLAGGED_FACES.clear();
    }

    private static void logIntercept(AtomicBoolean logged, String hook, FixPolicy.Settings settings) {
        if (!logged.get() && logged.compareAndSet(false, true)) {
            String policy = settings.enabled() ? settings.policy().name().toLowerCase(Locale.ROOT) : "off";
            System.err.println("[m2sfix] guard active: " + hook + " intercepted (policy=" + policy + ")");
        }
    }

    private static void remember(long faceAddress, ScanResult result) {
        if (!FLAGGED_FACES.containsKey(faceAddress) && FLAGGED_FACES.size() >= MAX_ENTRIES) {
            Iterator<Long> iterator = FLAGGED_FACES.keySet().iterator();
            if (iterator.hasNext()) {
                FLAGGED_FACES.remove(iterator.next());
            }
        }
        FLAGGED_FACES.put(faceAddress, result);
    }

    /**
     * @return {@code true} the first time this key is seen, {@code false} afterwards
     */
    private static boolean seenOnce(String hash, String purpose) {
        String key = purpose + ":" + (hash == null ? "unknown" : hash);
        if (!LOGGED_FONT_HASHES.add(key)) {
            return false;
        }
        if (LOGGED_FONT_HASHES.size() > MAX_ENTRIES) {
            LOGGED_FONT_HASHES.clear();
        }
        return true;
    }

    private static void logOnce(String hash, ScanResult result) {
        String key = hash == null ? "unknown" : hash;
        if (!LOGGED_FONT_HASHES.add(key)) {
            return;
        }
        if (LOGGED_FONT_HASHES.size() > MAX_ENTRIES) {
            LOGGED_FONT_HASHES.clear();
        }
        System.err.println("[m2sfix] flagged font " + key
                + " (" + result.verdict() + "): " + result.reason());
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(bytes));
        } catch (NoSuchAlgorithmException | RuntimeException ignored) {
            return null;
        }
    }
}
