package dev.duckducktw.m2sfix.mod;

import dev.duckducktw.m2sfix.core.FaceGuard;
import java.nio.ByteBuffer;
import org.lwjgl.PointerBuffer;
import org.lwjgl.util.freetype.FT_Face;
import org.lwjgl.util.freetype.FreeType;

public final class FreeTypeHooks {

    private FreeTypeHooks() {
    }

    public static int FT_New_Memory_Face(long library, ByteBuffer file, long faceIndex, PointerBuffer out) {
        int rejection = FaceGuard.beforeNewFace(file);
        if (rejection != 0) {
            return rejection;
        }
        int result = FreeType.FT_New_Memory_Face(library, file, faceIndex, out);
        afterNewFace(file, out, result);
        return result;
    }

    public static int FT_Load_Glyph(FT_Face face, int index, int flags) {
        return FreeType.FT_Load_Glyph(face, index, adjustFlags(face, flags));
    }

    public static void afterNewFace(ByteBuffer file, PointerBuffer out, int result) {
        if (result == 0) {
            long address = out != null && out.hasRemaining() ? out.get(out.position()) : 0L;
            FaceGuard.afterNewFace(address, file);
        }
    }

    public static int adjustFlags(FT_Face face, int flags) {
        return FaceGuard.adjustLoadFlags(face == null ? 0L : face.address(), flags);
    }

    public static void verifyFabricHook() {
        try {
            // Resolving the class forces transformation without initializing FreeType.
            Class<?> type = Class.forName("org.lwjgl.util.freetype.FreeType", false, FreeTypeHooks.class.getClassLoader());
            type.getDeclaredMethod("m2sfix$hookInstalled");
        } catch (ReflectiveOperationException | RuntimeException | LinkageError failure) {
            throw new IllegalStateException(
                    "[m2sfix] FreeType guard did not apply on Fabric. Use the -javaagent route.", failure);
        }
    }
}
