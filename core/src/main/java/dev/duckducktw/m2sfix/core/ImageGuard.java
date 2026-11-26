package dev.duckducktw.m2sfix.core;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Header-level sanity check for images that arrive from a resource pack.
 *
 * <p>Texture and bitmap-font images are decoded by {@code stb_image} through {@code lwjgl-stb}
 * ({@code com.mojang.blaze3d.platform.NativeImage} → {@code STBImage.stbi_load_from_memory}). That
 * decoder is native code with a known class of bug: a PNG that declares huge dimensions and 16-bit
 * samples makes the 16→8-bit conversion write far past the buffer it allocated. Primitive One
 * published a write-up of exactly that (plus an uninitialised-palette read that leaks ASLR-relevant
 * pointers), and the shape is identical to the font bug: server-supplied bytes reaching C.</p>
 *
 * <p>This class never decodes anything. It reads the PNG / JPEG header, does the arithmetic in
 * {@code long}, and refuses the images whose declared geometry cannot possibly fit — which is the
 * precondition for the overflow. Rejected images are handed to the decoder as an empty buffer, so
 * {@code stb_image} fails normally and Minecraft renders a missing texture instead of corrupting the
 * heap.</p>
 *
 * <p>Deliberately <em>not</em> claimed: this does not close the uninitialised-palette information leak
 * (that needs to look at decoded pixel data), and it cannot help if a decoder bug is reachable with a
 * perfectly reasonable header.</p>
 */
public final class ImageGuard {

    /** Largest image we accept, as a pixel count. Vanilla's biggest textures are far below this. */
    public static final int DEFAULT_MAX_PIXELS = 16 * 1024 * 1024;
    /** Largest decoded size we accept, in bytes (RGBA8 or 16-bit equivalent). */
    public static final int DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
    /** Per-axis limit; also the PNG spec's own limit. */
    public static final int MAX_AXIS = 1 << 24;

    private static final byte[] PNG_SIGNATURE = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    private static final int TAG_IHDR = 0x49484452;
    private static final int TAG_PLTE = 0x504C5445;

    private ImageGuard() {
    }

    /** What the guard decided about one image. */
    public enum Verdict {
        /** Header looks sane (or the format was not recognised and is left to the decoder). */
        OK,
        /** Geometry cannot fit; the decoder would overflow. */
        REJECT
    }

    /**
     * Inspects an image header.
     *
     * @param data     the encoded image, position/limit must not be relied on (the caller's buffer is
     *                 not modified: a duplicate is read)
     * @param maxPixels pixel budget
     * @param maxBytes decoded byte budget
     * @return {@link Verdict#REJECT} when the declared size overflows or exceeds the budgets
     */
    public static Verdict inspect(ByteBuffer data, int maxPixels, int maxBytes, StringBuilder reasonOut) {
        try {
            if (data == null) {
                return Verdict.OK;
            }
            ByteBuffer view = data.duplicate();
            view.order(ByteOrder.BIG_ENDIAN);
            if (view.remaining() < 8) {
                return Verdict.OK; // too short to judge; the decoder will reject it
            }

            if (isPng(view)) {
                return inspectPng(view, maxPixels, maxBytes, reasonOut);
            }
            if (isJpeg(view)) {
                return inspectJpeg(view, maxPixels, maxBytes, reasonOut);
            }
            return Verdict.OK;
        } catch (Throwable ignored) {
            // A guard that throws is worse than a guard that abstains.
            return Verdict.OK;
        }
    }

    private static Verdict inspectPng(ByteBuffer view, int maxPixels, int maxBytes, StringBuilder reason) {
        int base = view.position();
        // signature (8) + length (4) + "IHDR" (4) + width/height/bitDepth/colourType (10)
        // 8 signature + 4 length + 4 tag + 10 of IHDR data = 26 bytes we need to read.
        if (view.limit() - base < 26 || view.getInt(base + 12) != TAG_IHDR) {
            return Verdict.OK;
        }
        long width = view.getInt(base + 16) & 0xFFFFFFFFL;
        long height = view.getInt(base + 20) & 0xFFFFFFFFL;
        int bitDepth = view.get(base + 24) & 0xFF;
        int colourType = view.get(base + 25) & 0xFF;

        if (width == 0 || height == 0 || width > MAX_AXIS || height > MAX_AXIS) {
            reason.append("PNG declares ").append(width).append('x').append(height);
            return Verdict.REJECT;
        }

        // Samples per pixel for the PNG colour types, before any bit packing.
        int channels = switch (colourType) {
            case 0 -> 1;      // greyscale
            case 2 -> 3;      // truecolour
            case 3 -> 1;      // indexed
            case 4 -> 2;      // greyscale + alpha
            case 6 -> 4;      // truecolour + alpha
            default -> 0;
        };
        if (channels == 0) {
            reason.append("PNG colour type ").append(colourType);
            return Verdict.REJECT;
        }

        long pixels = width * height;
        if (pixels > maxPixels) {
            reason.append("PNG is ").append(width).append('x').append(height)
                    .append(" = ").append(pixels).append(" pixels (limit ").append(maxPixels).append(')');
            return Verdict.REJECT;
        }

        // The decoder is asked for four components; 16-bit samples are converted through a
        // temporary buffer twice that size. Both are computed in long so nothing can wrap.
        long bytesAtRequestedDepth = pixels * 4L;
        long bytesAtWorstDepth = pixels * 4L * 2L;
        long bytes = bitDepth == 16 ? bytesAtWorstDepth : bytesAtRequestedDepth;
        if (bytes > maxBytes) {
            reason.append("PNG decodes to ").append(bytes).append(" bytes (limit ").append(maxBytes).append(')');
            return Verdict.REJECT;
        }
        if (bitDepth == 16 && pixels > 1024L * 1024L) {
            // 16-bit art this large is not something a resource pack needs; the conversion path is
            // exactly where the published overflow lives.
            reason.append("16-bit PNG with ").append(pixels).append(" pixels");
            return Verdict.REJECT;
        }

        if (colourType == 3) {
            Verdict palette = inspectPngPalette(view, (int) pixels, reason);
            if (palette == Verdict.REJECT) {
                return Verdict.REJECT;
            }
        }
        return Verdict.OK;
    }

    /**
     * Indexed PNGs build an RGBA palette on the stack. A file whose palette is shorter than an index
     * it uses makes the decoder copy uninitialised stack memory into the image — the disclosure half
     * of the published bug. A full 256-entry palette cannot trigger it.
     */
    private static Verdict inspectPngPalette(ByteBuffer view, int pixels, StringBuilder reason) {
        int base = view.position();
        int limit = view.limit();
        int cursor = base + 8;
        while (cursor + 8 <= limit) {
            long length = view.getInt(cursor) & 0xFFFFFFFFL;
            int tag = view.getInt(cursor + 4);
            if (tag == TAG_IHDR) {
                cursor += 12 + (int) length;
                continue;
            }
            if (tag == IDAT_FIRST) {
                // Ran out of chunks before PLTE: nothing to compare against.
                return Verdict.OK;
            }
            if (tag == TAG_PLTE) {
                long entries = length / 3;
                if (entries < 256) {
                    // Only a problem if the image actually indexes past the palette, which needs the
                    // pixel data. Small images are cheap to check conservatively: refuse the shape.
                    reason.append("indexed PNG with a ").append(entries)
                            .append("-entry palette (").append(pixels).append(" pixels)");
                    return Verdict.REJECT;
                }
                return Verdict.OK;
            }
            cursor += 12 + (int) length;
        }
        return Verdict.OK;
    }

    private static final int IDAT_FIRST = 0x49444154;

    private static Verdict inspectJpeg(ByteBuffer view, int maxPixels, int maxBytes, StringBuilder reason) {
        int base = view.position();
        int limit = view.limit();
        int cursor = base + 2;
        while (cursor + 9 <= limit) {
            if ((view.get(cursor) & 0xFF) != 0xFF) {
                cursor++;
                continue;
            }
            int marker = view.get(cursor + 1) & 0xFF;
            if (marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
                cursor += 2;
                continue;
            }
            if (marker == 0xD9 || marker == 0xDA) {
                return Verdict.OK; // start of scan without a frame header: let the decoder decide
            }
            int length = view.getShort(cursor + 2) & 0xFFFF;
            boolean isFrame = marker >= 0xC0 && marker <= 0xCF
                    && marker != 0xC4 && marker != 0xC8 && marker != 0xCC;
            if (isFrame && length >= 7 && cursor + 7 < limit) {
                long height = view.getShort(cursor + 5) & 0xFFFF;
                long width = view.getShort(cursor + 7) & 0xFFFF;
                if (width == 0 || height == 0) {
                    return Verdict.OK;
                }
                long pixels = width * height;
                if (pixels > maxPixels || pixels * 4L > maxBytes) {
                    reason.append("JPEG is ").append(width).append('x').append(height);
                    return Verdict.REJECT;
                }
                return Verdict.OK;
            }
            cursor += 2 + length;
        }
        return Verdict.OK;
    }

    private static boolean isPng(ByteBuffer view) {
        if (view.remaining() < PNG_SIGNATURE.length) {
            return false;
        }
        int base = view.position();
        for (int i = 0; i < PNG_SIGNATURE.length; i++) {
            if (view.get(base + i) != PNG_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }

    private static boolean isJpeg(ByteBuffer view) {
        int base = view.position();
        return view.remaining() >= 3
                && (view.get(base) & 0xFF) == 0xFF
                && (view.get(base + 1) & 0xFF) == 0xD8;
    }
}
