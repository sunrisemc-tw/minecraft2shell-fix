package dev.duckducktw.m2sfix.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Defensive, allocation-light TrueType scanner.
 *
 * <p>The scanner walks {@code fpgm}, {@code prep}, and every glyph instruction stream in
 * {@code glyf} without executing font code. Its instruction decoder mirrors FreeType's
 * {@code opcode_length} table so push payloads are not decoded as opcodes unless a relative jump
 * ({@code JMPR}/{@code JROT}/{@code JROF}) appears in the same instruction stream, in which case
 * raw {@code 0x36}/{@code 0x37} ({@code SHZ}) bytes in that stream are also counted.</p>
 *
 * <p>Verdicts distinguish two threat tiers: high-confidence exploit-shaped {@code IDEF} usage
 * ({@link ScanResult.Verdict#SUSPICIOUS}) and faces that can reach {@code Ins_SHZ} without that
 * signature ({@link ScanResult.Verdict#RISKY}). Unusable sfnt or glyph-table structures fail
 * closed as {@link ScanResult.Verdict#UNPARSABLE}. This class never throws to its caller.</p>
 */
public final class TtfScanner {

    private static final int TAG_TTCF = 0x74746366; // 'ttcf'
    private static final int TAG_TRUE = 0x74727565; // 'true'
    private static final int TAG_OTTO = 0x4F54544F; // 'OTTO'
    private static final int TAG_TYP1 = 0x74797031; // 'typ1'
    private static final int TAG_VERSION_1 = 0x00010000;

    private static final int TAG_FPGM = 0x6670676D; // 'fpgm'
    private static final int TAG_PREP = 0x70726570; // 'prep'
    private static final int TAG_GLYF = 0x676C7966; // 'glyf'
    private static final int TAG_LOCA = 0x6C6F6361; // 'loca'
    private static final int TAG_HEAD = 0x68656164; // 'head'
    private static final int TAG_MAXP = 0x6D617870; // 'maxp'
    private static final int TAG_CVT = 0x63767420;  // 'cvt '

    private static final int OP_JMPR = 0x1C;
    private static final int OP_FDEF = 0x2C;
    private static final int OP_SHZ_0 = 0x36;
    private static final int OP_SHZ_1 = 0x37;
    private static final int OP_NPUSHB = 0x40;
    private static final int OP_NPUSHW = 0x41;
    private static final int OP_JROT = 0x78;
    private static final int OP_JROF = 0x79;
    private static final int OP_IDEF = 0x89;

    private static final int COMPOSITE_WE_HAVE_INSTRUCTIONS = 0x0100;
    private static final int MAX_COMPOSITE_COMPONENTS = 0xFFFF;
    private static final int UNKNOWN_OPCODE = Integer.MIN_VALUE;

    private TtfScanner() {
    }

    /**
     * Scans a complete font file.
     *
     * @param font font bytes, may be {@code null}
     * @return a non-null result; never throws
     */
    public static ScanResult scan(byte[] font) {
        try {
            if (font == null) {
                return unparsable("font data is null");
            }
            if (font.length < 4) {
                return unparsable("font is too short for an sfnt header");
            }

            int version = u32(font, 0);
            if (version == TAG_TTCF) {
                return scanCollection(font);
            }
            if (!isSfntVersion(version)) {
                return unparsable("unsupported sfnt version 0x" + Integer.toHexString(version));
            }
            return toResult(scanFace(font, 0, font.length));
        } catch (RuntimeException e) {
            return unparsable("font scan failed: " + safeMessage(e));
        }
    }

    private static ScanResult scanCollection(byte[] data) {
        if (data.length < 12) {
            return unparsable("truncated TrueType collection header");
        }
        long faceCount = u32Long(data, 8);
        if (faceCount <= 0) {
            return unparsable("TrueType collection contains no faces");
        }
        long offsetsEnd = 12L + faceCount * 4L;
        if (offsetsEnd > data.length) {
            return unparsable("truncated TrueType collection offset table");
        }

        int faces = (int) faceCount;
        String firstSuspicious = null;
        String firstRisky = null;
        List<String> failures = new ArrayList<>();

        for (int i = 0; i < faces; i++) {
            long offset = u32Long(data, (int) (12L + i * 4L));
            if (offset + 12L > data.length) {
                failures.add("face " + i + " has an out-of-range offset");
                continue;
            }
            FaceOutcome outcome = scanFace(data, (int) offset, data.length);
            switch (outcome.verdict) {
                case SUSPICIOUS -> {
                    if (firstSuspicious == null) {
                        firstSuspicious = "face " + i + ": " + outcome.reason;
                    }
                }
                case RISKY -> {
                    if (firstRisky == null) {
                        firstRisky = "face " + i + ": " + outcome.reason;
                    }
                }
                case UNPARSABLE -> failures.add("face " + i + ": " + outcome.reason);
                case CLEAN -> {
                    // Nothing to record.
                }
            }
        }

        if (firstSuspicious != null) {
            return new ScanResult(ScanResult.Verdict.SUSPICIOUS, firstSuspicious);
        }
        if (firstRisky != null) {
            return new ScanResult(ScanResult.Verdict.RISKY, firstRisky);
        }
        if (!failures.isEmpty()) {
            return unparsable(String.join("; ", failures));
        }
        return clean(0);
    }

    private static FaceOutcome scanFace(byte[] data, int faceOffset, int faceLimit) {
        int limit = Math.min(faceLimit, data.length);
        if (faceOffset < 0 || (long) faceOffset + 12L > limit) {
            return FaceOutcome.unparsable("truncated sfnt header");
        }

        int version = u32(data, faceOffset);
        if (!isSfntVersion(version)) {
            return FaceOutcome.unparsable("unsupported sfnt version 0x" + Integer.toHexString(version));
        }

        int numTables = u16(data, faceOffset + 4);
        long directoryStart = (long) faceOffset + 12L;
        long directoryEnd = directoryStart + (long) numTables * 16L;
        if (directoryEnd > limit) {
            return FaceOutcome.unparsable("truncated table directory");
        }

        Map<Integer, Table> tables = new HashMap<>();
        for (int i = 0; i < numTables; i++) {
            int record = (int) (directoryStart + (long) i * 16L);
            int tag = u32(data, record);
            long offset = u32Long(data, record + 8);
            long length = u32Long(data, record + 12);
            if (length > 0
                    && length <= Integer.MAX_VALUE
                    && offset <= data.length
                    && offset + length <= data.length) {
                tables.putIfAbsent(tag, new Table((int) offset, (int) length));
            }
        }

        Stats stats = new Stats();
        scanTable(data, tables.get(TAG_FPGM), "fpgm", stats);
        scanTable(data, tables.get(TAG_PREP), "prep", stats);

        Table glyf = tables.get(TAG_GLYF);
        Table loca = tables.get(TAG_LOCA);
        Table head = tables.get(TAG_HEAD);
        Table maxp = tables.get(TAG_MAXP);
        tables.get(TAG_CVT); // located for completeness; not needed for the verdict
        if (glyf != null) {
            if (loca == null || head == null || maxp == null) {
                stats.markUnparsable("glyf table present without valid loca/head/maxp");
            } else {
                scanGlyphs(data, glyf, loca, head, maxp, stats);
            }
        }

        String hostile = stats.firstExploitShapedIdef();
        if (hostile != null) {
            return new FaceOutcome(ScanResult.Verdict.SUSPICIOUS, hostile, stats.shzCount);
        }
        if (stats.shzCount > 0) {
            return new FaceOutcome(ScanResult.Verdict.RISKY, stats.describeRiskyShz(), stats.shzCount);
        }
        String unknownIdef = stats.firstUnknownIdef();
        if (unknownIdef != null) {
            return new FaceOutcome(ScanResult.Verdict.RISKY, unknownIdef, 0);
        }
        if (stats.unparsableReason != null) {
            return FaceOutcome.unparsable(stats.unparsableReason);
        }
        if (stats.idefCount > 0) {
            // Some fonts legitimately define their own instructions (Korean Hanja/Hangul faces and
            // Apple GX faces like Skia do this). Redefining a point-moving opcode is the exploit's
            // signature; defining a statically known non-point-zone opcode with no reachable SHZ
            // stays clean.
            return new FaceOutcome(
                    ScanResult.Verdict.CLEAN,
                    "IDEF present for " + stats.describeIdefOpcodes()
                            + " (not a point-zone instruction); SHZ count=0",
                    0);
        }
        return new FaceOutcome(
                ScanResult.Verdict.CLEAN,
                "no IDEF instruction; SHZ count=0",
                0);
    }

    private static void scanTable(byte[] data, Table table, String label, Stats stats) {
        if (table == null || table.length <= 0) {
            return;
        }
        scanInstructions(data, table.offset, table.offset + table.length, label, stats);
    }

    private static void scanGlyphs(byte[] data, Table glyf, Table loca, Table head, Table maxp, Stats stats) {
        if (head.length < 54 || maxp.length < 6) {
            stats.markUnparsable("truncated head or maxp table");
            return;
        }

        int indexToLocFormat = s16(data, head.offset + 50);
        if (indexToLocFormat != 0 && indexToLocFormat != 1) {
            stats.markUnparsable("invalid head.indexToLocFormat " + indexToLocFormat);
            return;
        }

        int numGlyphs = u16(data, maxp.offset + 4);
        int entrySize = indexToLocFormat == 0 ? 2 : 4;
        long locaBytesNeeded = (long) (numGlyphs + 1) * entrySize;
        int scanCount = numGlyphs;
        if (locaBytesNeeded > loca.length) {
            // FreeType may still load glyphs when loca is shorter than maxp.numGlyphs; fail closed
            // unless a higher-priority verdict is found in the glyphs we can still inspect.
            stats.markUnparsable("loca table shorter than maxp numGlyphs");
            scanCount = Math.max(0, loca.length / entrySize - 1);
        }
        if (scanCount == 0) {
            return;
        }

        long[] offsets = new long[scanCount + 1];
        for (int i = 0; i <= scanCount; i++) {
            offsets[i] = indexToLocFormat == 0
                    ? (long) u16(data, loca.offset + i * 2) * 2L
                    : u32Long(data, loca.offset + i * 4);
        }

        for (int i = 0; i < scanCount; i++) {
            long start = offsets[i];
            long end = offsets[i + 1];
            if (start == end) {
                continue;
            }
            if (start > glyf.length) {
                stats.markUnparsable("out-of-range loca offset for glyph " + i);
                continue;
            }
            if (end > glyf.length) {
                // Mirrors FreeType tt_face_get_location: the final entry is clamped to glyf_len,
                // while an earlier out-of-range end yields an empty glyph; fail closed if malformed.
                stats.markUnparsable("out-of-range loca end for glyph " + i);
                if (i == scanCount - 1) {
                    end = glyf.length;
                } else {
                    continue;
                }
            }
            if (end < start) {
                // Mirrors FreeType tt_face_get_location for unordered loca entries, and fail closed.
                stats.markUnparsable("unordered loca entry for glyph " + i);
                end = glyf.length;
            }
            if (end - start < 10) {
                stats.markUnparsable("truncated glyph header for glyph " + i);
                continue;
            }

            int glyphOffset = glyf.offset + (int) start;
            int glyphEnd = glyf.offset + (int) end;
            int numberOfContours = s16(data, glyphOffset);

            InstructionRange instructions = numberOfContours >= 0
                    ? simpleGlyphInstructions(data, glyphOffset, glyphEnd, numberOfContours)
                    : compositeGlyphInstructions(data, glyphOffset, glyphEnd, stats);
            if (instructions == null) {
                stats.markUnparsable("malformed glyph " + i);
                continue;
            }
            if (instructions.start >= instructions.end) {
                continue;
            }
            scanInstructions(data, instructions.start, instructions.end, "glyph " + i, stats);
        }
    }

    private static InstructionRange simpleGlyphInstructions(
            byte[] data, int glyphOffset, int glyphEnd, int numberOfContours) {
        long cursor = (long) glyphOffset + 10L + (long) numberOfContours * 2L;
        if (cursor + 2L > glyphEnd) {
            return null;
        }
        int length = u16(data, (int) cursor);
        cursor += 2L;
        if (cursor + length > glyphEnd) {
            return null;
        }
        return new InstructionRange((int) cursor, (int) cursor + length);
    }

    private static InstructionRange compositeGlyphInstructions(
            byte[] data, int glyphOffset, int glyphEnd, Stats stats) {
        long cursor = (long) glyphOffset + 10L;
        int guard = 0;
        boolean anyHasInstructions = false;
        boolean lastHasInstructions = false;

        while (true) {
            if (cursor + 4L > glyphEnd) {
                return null;
            }
            int flags = u16(data, (int) cursor);
            cursor += 4L; // flags + glyphIndex
            lastHasInstructions = (flags & COMPOSITE_WE_HAVE_INSTRUCTIONS) != 0;
            if (lastHasInstructions) {
                anyHasInstructions = true;
            }

            cursor += (flags & 0x0001) != 0 ? 4L : 2L; // ARG_1_AND_2_ARE_WORDS
            if ((flags & 0x0008) != 0) {
                cursor += 2L; // WE_HAVE_A_SCALE
            } else if ((flags & 0x0040) != 0) {
                cursor += 4L; // WE_HAVE_AN_X_AND_Y_SCALE
            } else if ((flags & 0x0080) != 0) {
                cursor += 8L; // WE_HAVE_A_TWO_BY_TWO
            }

            if (cursor > glyphEnd) {
                return null;
            }
            if ((flags & 0x0020) == 0) { // MORE_COMPONENTS
                break;
            }
            if (++guard > MAX_COMPOSITE_COMPONENTS) {
                stats.markUnparsable("composite glyph exceeded component limit");
                return null;
            }
        }

        if (!anyHasInstructions) {
            return InstructionRange.EMPTY;
        }
        // FreeType TT_Process_Composite_Glyph checks WE_HAVE_INSTR on the last component
        // (ttgload.c:1899) and bounds n_ins by loader->byte_len (glyphEnd - glyphOffset) and the
        // backing stream length. If only an earlier component set the bit and no trailing bytes
        // exist, FreeType will not run composite instructions.
        if (!lastHasInstructions && cursor + 2L > glyphEnd) {
            return InstructionRange.EMPTY;
        }
        if (cursor + 2L > data.length) {
            return null;
        }
        int length = u16(data, (int) cursor);
        cursor += 2L;
        if (length == 0) {
            return InstructionRange.EMPTY;
        }
        long glyphByteLen = (long) glyphEnd - (long) glyphOffset;
        if (length > glyphByteLen || cursor + length > data.length) {
            return null;
        }
        return new InstructionRange((int) cursor, (int) cursor + length);
    }

    /**
     * Decodes a TrueType instruction stream without executing it.
     *
     * <p>Only the PUSH family carries inline data (matching FreeType's {@code opcode_length}
     * table). {@code FDEF} and {@code IDEF} take their definition number from the top of the
     * <em>stack</em> (FreeType's {@code Ins_FDEF}/{@code Ins_IDEF} read {@code args[0]}), which is
     * the last value of an immediately preceding push instruction. Any intervening non-push
     * instruction makes the top of stack statically unknown. If the stream contains any relative
     * jump ({@code JMPR}, {@code JROT}, {@code JROF}), a jump target can land inside push payloads
     * or count bytes of the same stream, so raw {@code 0x36}/{@code 0x37} bytes in
     * {@code [start, end)} are also counted as reachable {@code SHZ}.</p>
     */
    private static void scanInstructions(byte[] data, int start, int end, String location, Stats stats) {
        int streamStart = Math.max(0, start);
        int limit = Math.min(end, data.length);
        int ip = streamStart;
        int lastPushed = UNKNOWN_OPCODE;
        int linearShz = 0;
        boolean sawJump = false;

        while (ip < limit) {
            int opcode = data[ip] & 0xFF;

            if (opcode == OP_IDEF) {
                // The definition number is on the top of the stack; the body starts at the next byte.
                stats.addIdef(location, lastPushed);
                lastPushed = UNKNOWN_OPCODE;
                ip++;
                continue;
            }
            if (opcode == OP_FDEF) {
                lastPushed = UNKNOWN_OPCODE;
                ip++;
                continue;
            }
            if (opcode == OP_SHZ_0 || opcode == OP_SHZ_1) {
                linearShz++;
                stats.addLinearShz(location);
                lastPushed = UNKNOWN_OPCODE;
                ip++;
                continue;
            }
            if (opcode == OP_JMPR || opcode == OP_JROT || opcode == OP_JROF) {
                sawJump = true;
                lastPushed = UNKNOWN_OPCODE;
                ip++;
                continue;
            }
            if (opcode == OP_NPUSHB || opcode == OP_NPUSHW) {
                int count = ip + 1 < limit ? data[ip + 1] & 0xFF : 0;
                long skip = opcode == OP_NPUSHB ? 2L + count : 2L + 2L * count;
                if (count >= 1) {
                    if (opcode == OP_NPUSHB) {
                        lastPushed = ip + 1 + count < limit ? data[ip + 1 + count] & 0xFF : UNKNOWN_OPCODE;
                    } else {
                        lastPushed = ip + 1 + 2 * count < limit ? s16(data, ip + 2 * count) : UNKNOWN_OPCODE;
                    }
                } else {
                    lastPushed = UNKNOWN_OPCODE;
                }
                ip = (int) Math.min((long) limit, (long) ip + skip);
                continue;
            }
            if (opcode >= 0xB0 && opcode <= 0xB7) {
                int count = (opcode & 0x07) + 1;
                lastPushed = ip + count < limit ? data[ip + count] & 0xFF : UNKNOWN_OPCODE;
                ip = Math.min(limit, ip + 1 + count);
                continue;
            }
            if (opcode >= 0xB8 && opcode <= 0xBF) {
                int count = (opcode & 0x07) + 1;
                lastPushed = ip + 2 * count < limit ? s16(data, ip + 2 * count - 1) : UNKNOWN_OPCODE;
                ip = Math.min(limit, ip + 1 + 2 * count);
                continue;
            }
            // Any other instruction (arithmetic, stack manipulation, control flow, etc.) can change
            // the top of stack, so the next IDEF's definition number is no longer statically known.
            lastPushed = UNKNOWN_OPCODE;
            ip++;
        }

        if (sawJump) {
            int rawShz = 0;
            for (int i = streamStart; i < limit; i++) {
                int value = data[i] & 0xFF;
                if (value == OP_SHZ_0 || value == OP_SHZ_1) {
                    rawShz++;
                }
            }
            int hiddenShz = rawShz - linearShz;
            if (hiddenShz > 0) {
                stats.addJumpShz(location, hiddenShz);
            }
        }
    }

    private static ScanResult toResult(FaceOutcome outcome) {
        return switch (outcome.verdict) {
            case SUSPICIOUS -> new ScanResult(ScanResult.Verdict.SUSPICIOUS, outcome.reason);
            case RISKY -> new ScanResult(ScanResult.Verdict.RISKY, outcome.reason);
            case UNPARSABLE -> unparsable(outcome.reason);
            // The reason carries the diagnostics, including any harmless IDEF opcodes.
            case CLEAN -> new ScanResult(ScanResult.Verdict.CLEAN, outcome.reason);
        };
    }

    private static boolean isSfntVersion(int version) {
        return version == TAG_VERSION_1
                || version == TAG_TRUE
                || version == TAG_OTTO
                || version == TAG_TYP1;
    }

    private static ScanResult clean(int shzCount) {
        return new ScanResult(
                ScanResult.Verdict.CLEAN,
                "no IDEF instruction; SHZ count=" + shzCount);
    }

    private static ScanResult unparsable(String reason) {
        return new ScanResult(ScanResult.Verdict.UNPARSABLE, reason);
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank() ? throwable.getClass().getSimpleName() : message;
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static int s16(byte[] data, int offset) {
        return (short) u16(data, offset);
    }

    private static int u32(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    private static long u32Long(byte[] data, int offset) {
        return u32(data, offset) & 0xFFFFFFFFL;
    }

    private record Table(int offset, int length) {
    }

    private record InstructionRange(int start, int end) {
        static final InstructionRange EMPTY = new InstructionRange(0, 0);
    }

    private record FaceOutcome(
            ScanResult.Verdict verdict,
            String reason,
            int shzCount) {

        static FaceOutcome unparsable(String reason) {
            return new FaceOutcome(ScanResult.Verdict.UNPARSABLE, reason, 0);
        }
    }

    private static final class Stats {
        int idefCount;
        int shzCount;
        int linearShzCount;
        int jumpShzCount;
        String firstShzLocation;
        String unparsableReason;
        /** Opcodes redefined through IDEF, keyed to the table or glyph they appeared in. */
        final List<IdefRecord> idefs = new ArrayList<>();

        /** @return a human-readable reason when a definition matches the high-confidence exploit shape */
        String firstExploitShapedIdef() {
            for (IdefRecord record : idefs) {
                // IDEF is only legal in fpgm/prep; a glyph program defining instructions is
                // already out of spec and FreeType rejects it with DEF_In_Glyf_Bytecode.
                if (!"fpgm".equals(record.location()) && !"prep".equals(record.location())) {
                    return "IDEF instruction in " + record.location()
                            + " (only legal in fpgm/prep)";
                }
                int opcode = record.definedOpcode();
                if (opcode != UNKNOWN_OPCODE && isPointZoneOpcode(opcode)) {
                    return String.format(
                            "IDEF redefines point-zone opcode 0x%02X in %s", opcode, record.location());
                }
            }
            return null;
        }

        /** @return a reason when fpgm/prep executes an IDEF whose opcode cannot be determined statically */
        String firstUnknownIdef() {
            for (IdefRecord record : idefs) {
                if (record.definedOpcode() == UNKNOWN_OPCODE) {
                    return "IDEF with statically unknown opcode in " + record.location();
                }
            }
            return null;
        }

        String describeRiskyShz() {
            String loc = Objects.requireNonNullElse(firstShzLocation, "unknown");
            if (linearShzCount > 0 && jumpShzCount > 0) {
                return "reachable SHZ in " + loc
                        + " (linear=" + linearShzCount + ", via-jump=" + jumpShzCount + ")";
            }
            if (jumpShzCount > 0) {
                return "jump-reachable SHZ byte in " + loc + " (count=" + jumpShzCount + ")";
            }
            return "reachable SHZ instruction in " + loc + " (count=" + linearShzCount + ")";
        }

        String describeIdefOpcodes() {
            java.util.TreeSet<String> opcodes = new java.util.TreeSet<>();
            for (IdefRecord record : idefs) {
                int opcode = record.definedOpcode();
                if (opcode == UNKNOWN_OPCODE) {
                    opcodes.add("unknown");
                } else {
                    opcodes.add(String.format("0x%02X", opcode));
                }
            }
            return String.join(",", opcodes);
        }

        void addIdef(String location, int definedOpcode) {
            idefCount++;
            idefs.add(new IdefRecord(location, definedOpcode));
        }

        void addLinearShz(String location) {
            shzCount++;
            linearShzCount++;
            if (firstShzLocation == null) {
                firstShzLocation = location;
            }
        }

        void addJumpShz(String location, int count) {
            shzCount += count;
            jumpShzCount += count;
            if (firstShzLocation == null) {
                firstShzLocation = location;
            }
        }

        void markUnparsable(String reason) {
            if (unparsableReason == null) {
                unparsableReason = reason;
            }
        }
    }

    /**
     * Opcodes whose FreeType handlers read or write the point zones. Redefining one of these is how
     * the published exploit hijacks the error dispatch: the out-of-bounds write corrupts
     * {@code exc->error}, and the recovery lookup then matches the font's {@code IDEF} for the
     * instruction that was executing.
     *
     * <p>Legitimate custom instructions live outside this range — the two Korean faces in the
     * Google Fonts corpus that use {@code IDEF} redefine {@code 0x00-0x04} and {@code 0x93}.</p>
     */
    private static boolean isPointZoneOpcode(int opcode) {
        // MDAP..ALIGNRP: MDAP, IUP, SHP, SHC, SHZ, SHPIX, IP, MSIRP, ALIGNRP
        if (opcode >= 0x2E && opcode <= 0x3C) {
            return true;
        }
        // MIAP (0x3E/0x3F) also moves points through the zone arrays.
        return opcode >= 0x3E && opcode <= 0x3F;
    }

    /**
     * One {@code IDEF} seen in a font.
     *
     * @param location      where it was found ({@code fpgm}, {@code prep} or {@code glyph N})
     * @param definedOpcode the opcode number the font defined, taken from the top of stack;
     *                      {@link #UNKNOWN_OPCODE} when the value cannot be determined statically
     */
    private record IdefRecord(String location, int definedOpcode) {
    }
}
