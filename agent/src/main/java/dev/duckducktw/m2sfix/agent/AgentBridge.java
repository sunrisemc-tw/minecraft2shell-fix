package dev.duckducktw.m2sfix.agent;

import dev.duckducktw.m2sfix.core.FaceGuard;
import java.nio.ByteBuffer;

/**
 * Glue between the injected bytecode and {@link FaceGuard}.
 *
 * <p>Every method here is called from bytecode that this agent spliced into
 * {@code org.lwjgl.util.freetype.FreeType}, so it must be cheap and it must
 * never throw: an exception would escape into the game's font loader.</p>
 */
public final class AgentBridge {

    private AgentBridge() {
    }

    public static int beforeNewFace(ByteBuffer file) {
        return FaceGuard.beforeNewFace(file);
    }

    /**
     * Called right after a face was created from memory.
     *
     * @param result the value {@code FT_New_Memory_Face} is about to return
     * @return the original FreeType result
     */
    public static int afterNewFace(ByteBuffer file, Object facePointerBuffer, int result) {
        try {
            if (result == 0) {
                FaceGuard.afterNewFace(readPointer(facePointerBuffer), file);
            }
        } catch (Throwable ignored) {
            // Keep the native result on guard failure.
        }
        return result;
    }

    /**
     * Called right before {@code FT_Load_Glyph} reads the glyph.
     *
     * @param flags the caller's {@code FT_Load_Glyph} flags
     * @return the flags to actually use
     */
    public static int adjustFlags(Object face, int flags) {
        try {
            return FaceGuard.adjustLoadFlags(readAddress(face), flags);
        } catch (Throwable ignored) {
            return flags;
        }
    }

    public static int adjustCharFlags(Object face, int flags) {
        try {
            return FaceGuard.adjustCharLoadFlags(readAddress(face), flags);
        } catch (Throwable ignored) {
            return flags;
        }
    }

    private static long readAddress(Object face) {
        if (face == null) {
            return 0L;
        }
        try {
            Object value = face.getClass().getMethod("address").invoke(face);
            return value instanceof Number number ? number.longValue() : 0L;
        } catch (Throwable ignored) {
            return 0L;
        }
    }

    private static long readPointer(Object pointerBuffer) {
        if (pointerBuffer == null) {
            return 0L;
        }
        try {
            Class<?> type = pointerBuffer.getClass();
            int position = (int) type.getMethod("position").invoke(pointerBuffer);
            Object value = type.getMethod("get", int.class).invoke(pointerBuffer, position);
            return value instanceof Number number ? number.longValue() : 0L;
        } catch (Throwable ignored) {
            return 0L;
        }
    }
}
