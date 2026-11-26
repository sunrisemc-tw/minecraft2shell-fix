package dev.duckducktw.m2sfix.core;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

final class TestFonts {

    static final String CLEAN = "clean.ttf";
    static final String MALICIOUS = "malicious-idef.ttf";
    static final String PUSHB_DECOY = "pushb-decoy.ttf";
    static final String NESTED_COMPOSITE = "nested-composite.ttf";
    static final String SIMPLE_GLYPH_IDEF = "simple-glyph-idef.ttf";
    static final String NO_SHZ_CLEAN = "no-shz-clean.ttf";
    static final String SHZ_PUSH_PAYLOAD_ONLY = "shz-push-payload-only.ttf";
    static final String SHZ_IN_GLYPH = "shz-in-glyph.ttf";
    static final String SHZ1_IN_GLYPH = "shz1-in-glyph.ttf";
    static final String SHZ_PAYLOAD_WITH_JMPR = "shz-payload-with-jmpr.ttf";
    static final String SHZ_IN_FPGM = "shz-in-fpgm.ttf";
    static final String SHZ_AFTER_UNINSTRUCTED_COMPOSITE = "shz-after-uninstructed-composite.ttf";
    static final String MALICIOUS_IDEF_MULTIPUSH = "malicious-idef-multipush.ttf";
    static final String CLEAN_IDEF_MULTIPUSH = "clean-idef-multipush.ttf";
    static final String RISKY_IDEF_COMPUTED = "risky-idef-computed.ttf";
    static final String MALFORMED_MID_GLYPH = "malformed-mid-glyph.ttf";
    static final String MALFORMED_GLYPH_BEFORE_SHZ = "malformed-glyph-before-shz.ttf";

    private TestFonts() {
    }

    static byte[] read(String name) {
        String resource = "/fonts/" + name;
        try (InputStream stream = TestFonts.class.getResourceAsStream(resource)) {
            if (stream == null) {
                throw new IllegalStateException("missing test font " + resource);
            }
            return stream.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException("cannot read test font " + resource, e);
        }
    }

    static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    static int s32(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, 4).order(ByteOrder.BIG_ENDIAN).getInt();
    }

    static void putInt(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >>> 24);
        data[offset + 1] = (byte) (value >>> 16);
        data[offset + 2] = (byte) (value >>> 8);
        data[offset + 3] = (byte) value;
    }

    static int tableOffset(byte[] data, String tag) {
        int numTables = u16(data, 4);
        int tagValue = tagValue(tag);
        for (int i = 0; i < numTables; i++) {
            int record = 12 + i * 16;
            if (s32(data, record) == tagValue) {
                return s32(data, record + 8);
            }
        }
        return -1;
    }

    static int tableLength(byte[] data, String tag) {
        int numTables = u16(data, 4);
        int tagValue = tagValue(tag);
        for (int i = 0; i < numTables; i++) {
            int record = 12 + i * 16;
            if (s32(data, record) == tagValue) {
                return s32(data, record + 12);
            }
        }
        return -1;
    }

    static byte[] patchTable(byte[] original, String tag, byte[] replacement) {
        byte[] copy = original.clone();
        int offset = tableOffset(copy, tag);
        int length = tableLength(copy, tag);
        if (offset < 0 || length != replacement.length) {
            throw new IllegalArgumentException("cannot patch " + tag + ": offset=" + offset + " length=" + length);
        }
        System.arraycopy(replacement, 0, copy, offset, replacement.length);
        return copy;
    }

    static byte[] withoutGlyf(byte[] original) {
        byte[] copy = original.clone();
        int numTables = u16(copy, 4);
        int glyf = tagValue("glyf");
        for (int i = 0; i < numTables; i++) {
            int record = 12 + i * 16;
            if (s32(copy, record) == glyf) {
                putInt(copy, record, tagValue("zzzz"));
                return copy;
            }
        }
        throw new IllegalArgumentException("no glyf table");
    }

    static byte[] withSfntVersion(byte[] original, String version) {
        byte[] copy = original.clone();
        putInt(copy, 0, tagValue(version));
        return copy;
    }

    static byte[] collection(byte[]... faces) {
        int header = 12 + 4 * faces.length;
        int total = header + Arrays.stream(faces).mapToInt(face -> face.length).sum();
        byte[] out = new byte[total];
        putInt(out, 0, tagValue("ttcf"));
        putInt(out, 4, 0x00010000);
        putInt(out, 8, faces.length);

        int cursor = header;
        for (int i = 0; i < faces.length; i++) {
            byte[] face = faces[i].clone();
            putInt(out, 12 + i * 4, cursor);

            int numTables = u16(face, 4);
            for (int table = 0; table < numTables; table++) {
                int record = 12 + table * 16;
                putInt(face, record + 8, s32(face, record + 8) + cursor);
            }
            System.arraycopy(face, 0, out, cursor, face.length);
            cursor += face.length;
        }
        return out;
    }

    private static int tagValue(String tag) {
        return ((tag.charAt(0) & 0xFF) << 24)
                | ((tag.charAt(1) & 0xFF) << 16)
                | ((tag.charAt(2) & 0xFF) << 8)
                | (tag.charAt(3) & 0xFF);
    }
}
