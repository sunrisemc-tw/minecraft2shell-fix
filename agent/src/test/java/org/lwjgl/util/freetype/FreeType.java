package org.lwjgl.util.freetype;

import java.nio.ByteBuffer;
import org.lwjgl.PointerBuffer;

/**
 * Test-only stub with the exact descriptors of the two verified LWJGL
 * methods. The agent instruments this class just like it would instrument the
 * real one.
 */
public final class FreeType {

    public static int newFaceCalls;
    public static int loadGlyphCalls;
    public static int newFaceResult;
    public static int loadGlyphResult;
    public static int lastLoadFlags = Integer.MIN_VALUE;
    public static long lastFaceAddress = -1L;
    public static long lastFileSize = -1L;
    public static ByteBuffer lastFile;

    private FreeType() {
    }

    public static int FT_New_Memory_Face(
            long library, ByteBuffer file, long file_size, PointerBuffer aface) {
        newFaceCalls++;
        lastFile = file;
        lastFileSize = file_size;
        return newFaceResult;
    }

    public static int FT_Load_Glyph(FT_Face face, int glyph_index, int load_flags) {
        loadGlyphCalls++;
        lastFaceAddress = face == null ? 0L : face.address();
        lastLoadFlags = load_flags;
        return loadGlyphResult;
    }

    public static int FT_Load_Char(FT_Face face, long character_code, int load_flags) {
        lastLoadFlags = load_flags;
        return loadGlyphResult;
    }

    public static void reset() {
        newFaceCalls = 0;
        loadGlyphCalls = 0;
        newFaceResult = 0;
        loadGlyphResult = 0;
        lastLoadFlags = Integer.MIN_VALUE;
        lastFaceAddress = -1L;
        lastFileSize = -1L;
        lastFile = null;
    }
}
