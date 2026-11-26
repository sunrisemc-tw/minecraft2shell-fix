package dev.duckducktw.m2sfix.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import org.junit.jupiter.api.Test;

/**
 * The image guard has to refuse the geometry that makes {@code stb_image} overflow, and leave
 * ordinary textures alone. Every case below is built here rather than checked in, so the exact
 * numbers that matter (dimensions, bit depth, palette size) are visible in the test.
 */
class ImageGuardTest {

    private static int inspect(byte[] image) {
        return inspect(image, ImageGuard.DEFAULT_MAX_PIXELS, ImageGuard.DEFAULT_MAX_BYTES);
    }

    private static int inspect(byte[] image, int maxPixels, int maxBytes) {
        StringBuilder reason = new StringBuilder();
        ImageGuard.Verdict verdict = ImageGuard.inspect(ByteBuffer.wrap(image), maxPixels, maxBytes, reason);
        if (verdict == ImageGuard.Verdict.REJECT) {
            assertTrue(reason.length() > 0, "a rejection must explain itself");
        }
        return verdict == ImageGuard.Verdict.OK ? 0 : 1;
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] chunk(String tag, byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeInt(out, data.length);
        byte[] tagBytes = tag.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        out.write(tagBytes, 0, tagBytes.length);
        out.write(data, 0, data.length);
        CRC32 crc = new CRC32();
        crc.update(tagBytes);
        crc.update(data);
        writeInt(out, (int) crc.getValue());
        return out.toByteArray();
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static byte[] png(int width, int height, int bitDepth, int colourType, byte[] palette, int rows) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x89);
        out.write('P');
        out.write('N');
        out.write('G');
        out.write('\r');
        out.write('\n');
        out.write(0x1A);
        out.write('\n');

        byte[] ihdr = new byte[13];
        ihdr[0] = (byte) (width >>> 24);
        ihdr[1] = (byte) (width >>> 16);
        ihdr[2] = (byte) (width >>> 8);
        ihdr[3] = (byte) width;
        ihdr[4] = (byte) (height >>> 24);
        ihdr[5] = (byte) (height >>> 16);
        ihdr[6] = (byte) (height >>> 8);
        ihdr[7] = (byte) height;
        ihdr[8] = (byte) bitDepth;
        ihdr[9] = (byte) colourType;
        byte[] ihdrChunk = chunk("IHDR", ihdr);
        out.write(ihdrChunk, 0, ihdrChunk.length);

        if (palette != null) {
            byte[] plte = chunk("PLTE", palette);
            out.write(plte, 0, plte.length);
        }

        // Compressed pixel data: `rows` scanlines of zeros is enough for the header logic.
        Deflater deflater = new Deflater(Deflater.BEST_SPEED);
        deflater.setInput(new byte[Math.max(1, rows)]);
        deflater.finish();
        byte[] buffer = new byte[64];
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        while (!deflater.finished()) {
            int n = deflater.deflate(buffer);
            compressed.write(buffer, 0, n);
        }
        deflater.end();
        byte[] idat = chunk("IDAT", compressed.toByteArray());
        out.write(idat, 0, idat.length);
        byte[] iend = chunk("IEND", new byte[0]);
        out.write(iend, 0, iend.length);
        return out.toByteArray();
    }

    // -------------------------------------------------------------------- cases

    @Test
    void ordinaryTextureIsAccepted() {
        assertEquals(0, inspect(png(64, 64, 8, 6, null, 64 * 64)));
    }

    @Test
    void thePublishedOverflowShapeIsRefused() {
        // 16-bit greyscale, 23,171 x 23,171: 4 GiB of output from a 192 KiB allocation.
        assertEquals(1, inspect(png(23171, 23171, 16, 0, null, 1)));
    }

    @Test
    void sixteenBitImagesBeyondThePixelBudgetAreRefused() {
        assertEquals(1, inspect(png(4096, 4096, 16, 0, null, 1)));
    }

    @Test
    void smallSixteenBitImagesAreStillAllowed() {
        assertEquals(0, inspect(png(256, 256, 16, 0, null, 256)));
    }

    @Test
    void hugeDimensionsAreRefusedEvenWhenTheProductLooksSmall() {
        // 0 x 0 and absurd axes are refused before any multiplication.
        assertEquals(1, inspect(png(1 << 25, 1, 8, 6, null, 1)));
    }

    @Test
    void pixelBudgetIsHonoured() {
        byte[] image = png(2048, 2048, 8, 6, null, 1);
        assertEquals(0, inspect(image));
        assertEquals(1, inspect(image, 1024 * 1024, ImageGuard.DEFAULT_MAX_BYTES));
    }

    @Test
    void shortPaletteOnAnIndexedImageIsRefused() {
        byte[] palette = new byte[3 * 4]; // four entries, but indices may go to 255
        assertEquals(1, inspect(png(16, 16, 8, 3, palette, 16)));
    }

    @Test
    void fullPaletteOnAnIndexedImageIsAccepted() {
        byte[] palette = new byte[3 * 256];
        assertEquals(0, inspect(png(16, 16, 8, 3, palette, 16)));
    }

    @Test
    void unknownFormatsAreLeftToTheDecoder() {
        assertEquals(0, inspect(new byte[]{1, 2, 3, 4, 5, 6, 7, 8}));
        assertEquals(0, inspect(new byte[0]));
    }

    @Test
    void truncatedPngIsLeftToTheDecoder() {
        byte[] full = png(64, 64, 8, 6, null, 64 * 64);
        byte[] truncated = java.util.Arrays.copyOf(full, 20); // signature only, no IHDR
        assertEquals(0, inspect(truncated));
    }

    @Test
    void jpegDimensionsAreChecked() {
        // SOI + SOF0 with 40000 x 40000
        byte[] jpeg = new byte[]{
                (byte) 0xFF, (byte) 0xD8,
                (byte) 0xFF, (byte) 0xC0, 0x00, 0x11, 0x08,
                (byte) 0x9C, 0x40,             // height 40000
                (byte) 0x9C, 0x40,             // width 40000
                0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00,
                (byte) 0xFF, (byte) 0xD9
        };
        assertEquals(1, inspect(jpeg));
    }

    @Test
    void readingTheHeaderDoesNotConsumeTheCallersBuffer() {
        byte[] image = png(64, 64, 8, 6, null, 64 * 64);
        ByteBuffer buffer = ByteBuffer.wrap(image);
        buffer.position(4);
        int before = buffer.position();
        ImageGuard.inspect(buffer, ImageGuard.DEFAULT_MAX_PIXELS, ImageGuard.DEFAULT_MAX_BYTES,
                new StringBuilder());
        assertEquals(before, buffer.position(), "the guard must not move the decoder's buffer");
    }
}
