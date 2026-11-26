package dev.duckducktw.m2sfix.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class TtfScannerTest {

    @Test
    void cleanFontIsCleanAndReportsShzDiagnostics() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.CLEAN));

        assertEquals(ScanResult.Verdict.CLEAN, result.verdict());
        assertTrue(result.reason().contains("SHZ count=0"), result.reason());
    }

    @Test
    void shzInGlyphWithoutIdefIsRisky() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.SHZ_IN_GLYPH));

        assertEquals(ScanResult.Verdict.RISKY, result.verdict(), result.reason());
        assertTrue(result.reason().contains("SHZ"), result.reason());
        assertTrue(result.reason().contains("glyph"), result.reason());
    }

    @Test
    void shz1InCompositeGlyphWithoutIdefIsRisky() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.SHZ1_IN_GLYPH));

        assertEquals(ScanResult.Verdict.RISKY, result.verdict(), result.reason());
        assertTrue(result.reason().contains("SHZ"), result.reason());
    }

    @Test
    void shzOnlyInPushPayloadWithoutJumpIsClean() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.SHZ_PUSH_PAYLOAD_ONLY));

        assertEquals(ScanResult.Verdict.CLEAN, result.verdict(), result.reason());
    }

    @Test
    void shzInPushPayloadWithJmprInSameStreamIsRisky() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.SHZ_PAYLOAD_WITH_JMPR));

        assertEquals(ScanResult.Verdict.RISKY, result.verdict(), result.reason());
        assertTrue(result.reason().contains("jump-reachable SHZ"), result.reason());
    }

    @Test
    void shzInPushPayloadWithJrotOrJrofInSameStreamIsRisky() {
        byte[] base = TestFonts.read(TestFonts.SHZ_PAYLOAD_WITH_JMPR);
        // Replace JMPR (0x1C) with JROT (0x78) and JROF (0x79) in fpgm.
        byte[] withJrot = TestFonts.patchTable(base, "fpgm", new byte[]{(byte) 0xB0, 0x02, 0x78, (byte) 0xB1, 0x36, 0x00});
        byte[] withJrof = TestFonts.patchTable(base, "fpgm", new byte[]{(byte) 0xB0, 0x02, 0x79, (byte) 0xB1, 0x37, 0x00});

        assertEquals(ScanResult.Verdict.RISKY, TtfScanner.scan(withJrot).verdict());
        assertEquals(ScanResult.Verdict.RISKY, TtfScanner.scan(withJrof).verdict());
    }

    @Test
    void shzInNpushbCountByteWithJmprIsRisky() {
        byte[] base = TestFonts.read(TestFonts.SHZ_PAYLOAD_WITH_JMPR);
        // PUSHB 2; JMPR; NPUSHB; 0x36 (count byte = 54, truncated payload); 0x00 -> jump can land on 0x36.
        byte[] font = TestFonts.patchTable(base, "fpgm", new byte[]{(byte) 0xB0, 0x02, 0x1C, 0x40, 0x36, 0x00});

        assertEquals(ScanResult.Verdict.RISKY, TtfScanner.scan(font).verdict());
    }

    @Test
    void jumpInOneStreamDoesNotTaintPushPayloadInAnotherStream() {
        // shz-push-payload-only.ttf has 0x36/0x37 in prep/glyph push payloads and 3-byte fpgm;
        // replacing fpgm with PUSHB 1; JMPR (no 0x36/0x37 in fpgm) must stay CLEAN.
        byte[] font = TestFonts.patchTable(
                TestFonts.read(TestFonts.SHZ_PUSH_PAYLOAD_ONLY), "fpgm", new byte[]{(byte) 0xB0, 0x01, 0x1C});

        ScanResult result = TtfScanner.scan(font);
        assertEquals(ScanResult.Verdict.CLEAN, result.verdict(), result.reason());
    }

    @Test
    void shzOnlyInFpgmReachableViaCallIsRisky() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.SHZ_IN_FPGM));

        assertEquals(ScanResult.Verdict.RISKY, result.verdict(), result.reason());
        assertTrue(result.reason().contains("fpgm"), result.reason());
    }

    @Test
    void noShzAtAllIsClean() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.NO_SHZ_CLEAN));

        assertEquals(ScanResult.Verdict.CLEAN, result.verdict(), result.reason());
    }

    @Test
    void shzAfterUninstructedCompositeIsNotSkipped() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.SHZ_AFTER_UNINSTRUCTED_COMPOSITE));

        assertEquals(ScanResult.Verdict.RISKY, result.verdict(), result.reason());
        assertTrue(result.reason().contains("glyph 4"), result.reason());
    }

    @Test
    void collectionWithRiskySecondFaceIsRisky() {
        byte[] clean = TestFonts.read(TestFonts.CLEAN);
        byte[] risky = TestFonts.read(TestFonts.SHZ_IN_GLYPH);

        ScanResult result = TtfScanner.scan(TestFonts.collection(clean, risky));

        assertEquals(ScanResult.Verdict.RISKY, result.verdict(), result.reason());
        assertTrue(result.reason().contains("face 1"), result.reason());
    }

    @Test
    void idefInFpgmIsSuspicious() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.MALICIOUS));

        assertEquals(ScanResult.Verdict.SUSPICIOUS, result.verdict());
        assertTrue(result.reason().contains("IDEF"), result.reason());
        assertTrue(result.reason().contains("0x36"), "the hijacked opcode must be named: " + result.reason());
        assertTrue(result.reason().contains("fpgm"), result.reason());
    }

    @Test
    void pushPayloadBytesAreNeverDecodedAsOpcodes() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.PUSHB_DECOY));

        assertEquals(ScanResult.Verdict.CLEAN, result.verdict(), result.reason());
    }

    @Test
    void idefInCompositeGlyphIsSuspicious() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.NESTED_COMPOSITE));

        assertEquals(ScanResult.Verdict.SUSPICIOUS, result.verdict());
        assertTrue(result.reason().contains("IDEF instruction in glyph"), result.reason());
    }

    @Test
    void idefInSimpleGlyphIsSuspicious() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.SIMPLE_GLYPH_IDEF));

        assertEquals(ScanResult.Verdict.SUSPICIOUS, result.verdict());
        assertTrue(result.reason().contains("IDEF instruction in glyph"), result.reason());
    }

    @Test
    void fdefDoesNotTreatNextByteAsInlineOperand() {
        // FDEF (0x2C) pops its function number from the stack (not inline), so a following 0x89 is
        // decoded as an IDEF with a statically unknown opcode and degrades to RISKY (not CLEAN).
        byte[] font = TestFonts.patchTable(
                TestFonts.read(TestFonts.CLEAN), "fpgm", new byte[]{0x2C, (byte) 0x89});

        ScanResult result = TtfScanner.scan(font);

        assertEquals(ScanResult.Verdict.RISKY, result.verdict(), result.reason());
        assertTrue(result.reason().contains("unknown opcode"), result.reason());
    }

    @Test
    void multiValuePushBeforeIdefUsesTopOfStack() {
        ScanResult hostile = TtfScanner.scan(TestFonts.read(TestFonts.MALICIOUS_IDEF_MULTIPUSH));
        assertEquals(ScanResult.Verdict.SUSPICIOUS, hostile.verdict(), hostile.reason());
        assertTrue(hostile.reason().contains("0x36"), hostile.reason());

        ScanResult benign = TtfScanner.scan(TestFonts.read(TestFonts.CLEAN_IDEF_MULTIPUSH));
        assertEquals(ScanResult.Verdict.CLEAN, benign.verdict(), benign.reason());
        assertTrue(benign.reason().contains("0x91"), benign.reason());
    }

    @Test
    void computedIdefOpcodeIsRiskyNotClean() {
        ScanResult result = TtfScanner.scan(TestFonts.read(TestFonts.RISKY_IDEF_COMPUTED));

        assertEquals(ScanResult.Verdict.RISKY, result.verdict(), result.reason());
        assertTrue(result.reason().contains("unknown opcode"), result.reason());
    }

    @Test
    void malformedGlyphMidWalkFailsClosedAndContinuesScanning() {
        ScanResult failedClosed = TtfScanner.scan(TestFonts.read(TestFonts.MALFORMED_MID_GLYPH));
        assertEquals(ScanResult.Verdict.UNPARSABLE, failedClosed.verdict(), failedClosed.reason());

        ScanResult continuedToShz = TtfScanner.scan(TestFonts.read(TestFonts.MALFORMED_GLYPH_BEFORE_SHZ));
        assertEquals(ScanResult.Verdict.RISKY, continuedToShz.verdict(), continuedToShz.reason());
    }

    @Test
    void missingGlyfStillScansFpgm() {
        byte[] font = TestFonts.withoutGlyf(TestFonts.read(TestFonts.MALICIOUS));

        ScanResult result = TtfScanner.scan(font);

        assertEquals(ScanResult.Verdict.SUSPICIOUS, result.verdict());
        assertTrue(result.reason().contains("fpgm"), result.reason());
    }

    @Test
    void acceptsAllSfntVersionTags() {
        byte[] clean = TestFonts.read(TestFonts.CLEAN);

        for (String version : List.of("true", "OTTO", "typ1")) {
            ScanResult result = TtfScanner.scan(TestFonts.withSfntVersion(clean, version));
            assertEquals(ScanResult.Verdict.CLEAN, result.verdict(), version + ": " + result.reason());
        }
    }

    @Test
    void scansEveryFaceInATrueTypeCollection() {
        byte[] clean = TestFonts.read(TestFonts.CLEAN);
        byte[] malicious = TestFonts.read(TestFonts.MALICIOUS);

        ScanResult onlyClean = TtfScanner.scan(TestFonts.collection(clean, clean));
        assertEquals(ScanResult.Verdict.CLEAN, onlyClean.verdict(), onlyClean.reason());

        ScanResult withMalicious = TtfScanner.scan(TestFonts.collection(clean, malicious));
        assertEquals(ScanResult.Verdict.SUSPICIOUS, withMalicious.verdict());
        assertTrue(withMalicious.reason().contains("face 1"), withMalicious.reason());
    }

    @Test
    void truncatedCollectionIsUnparsable() {
        byte[] ttc = TestFonts.collection(TestFonts.read(TestFonts.CLEAN));
        byte[] truncated = new byte[16];
        System.arraycopy(ttc, 0, truncated, 0, truncated.length);
        TestFonts.putInt(truncated, 8, 1000);

        assertEquals(ScanResult.Verdict.UNPARSABLE, TtfScanner.scan(truncated).verdict());
    }

    @Test
    void badInputsAreUnparsableAndNeverThrow() {
        assertEquals(ScanResult.Verdict.UNPARSABLE, TtfScanner.scan(null).verdict());
        assertEquals(ScanResult.Verdict.UNPARSABLE, TtfScanner.scan(new byte[0]).verdict());
        assertEquals(ScanResult.Verdict.UNPARSABLE, TtfScanner.scan(new byte[]{1, 2, 3}).verdict());
        assertEquals(ScanResult.Verdict.UNPARSABLE, TtfScanner.scan("wOFFnot-a-font".getBytes()).verdict());

        byte[] clean = TestFonts.read(TestFonts.CLEAN);
        byte[] truncatedDirectory = clean.clone();
        truncatedDirectory[4] = (byte) 0xFF;
        truncatedDirectory[5] = (byte) 0xFF;
        assertEquals(ScanResult.Verdict.UNPARSABLE, TtfScanner.scan(truncatedDirectory).verdict());
    }

    @Test
    void realWorldFontsContainZeroSuspiciousFonts() throws IOException {
        Path fontsRoot = Path.of("/usr/share/fonts");
        Assumptions.assumeTrue(Files.isDirectory(fontsRoot), "no /usr/share/fonts on this machine");

        List<String> suspicious = new ArrayList<>();
        long scanned = 0;
        try (Stream<Path> paths = Files.walk(fontsRoot)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) {
                String filename = path.getFileName().toString().toLowerCase(Locale.ROOT);
                if (!filename.endsWith(".ttf") && !filename.endsWith(".otf")) {
                    continue;
                }
                byte[] bytes;
                try {
                    bytes = Files.readAllBytes(path);
                } catch (IOException ignored) {
                    continue;
                }
                scanned++;
                ScanResult result = TtfScanner.scan(bytes);
                assertNotNull(result);
                if (result.verdict() == ScanResult.Verdict.SUSPICIOUS) {
                    suspicious.add(path + ": " + result.reason());
                }
            }
        }

        assertTrue(suspicious.isEmpty(), "suspicious real-world fonts: " + suspicious);
        assertFalse(scanned < 0);
    }
}
