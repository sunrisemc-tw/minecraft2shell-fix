package dev.duckducktw.m2sfix.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.duckducktw.m2sfix.core.FaceGuard;
import dev.duckducktw.m2sfix.core.FixPolicy;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.lwjgl.PointerBuffer;
import org.lwjgl.util.freetype.FT_Face;
import org.lwjgl.util.freetype.FreeType;
import net.bytebuddy.agent.ByteBuddyAgent;

class AgentIntegrationTest {

    private static final long FACE_ADDRESS = 0x5EED_1234L;

    private byte[] malicious;
    private byte[] clean;

    @BeforeAll
    static void installAgent() {
        Instrumentation instrumentation = ByteBuddyAgent.install();
        assertTrue(instrumentation.isRetransformClassesSupported());
        FixAgent.premain("", instrumentation);
    }

    @BeforeEach
    void setUp() {
        clearProperties();
        System.setProperty(FixPolicy.PROP_LOG, "false");
        // Detect mode: the assertions below distinguish flagged from clean fonts. The safe channel
        // (default for users) is covered by safeChannelStripsHintingFromCleanFonts.
        System.setProperty(FixPolicy.PROP_POLICY, "hintless");
        FaceGuard.clearForTests();
        FreeType.reset();
        malicious = readFont("malicious-idef.ttf");
        clean = readFont("clean.ttf");
    }

    @AfterEach
    void tearDown() {
        clearProperties();
        FaceGuard.clearForTests();
        FreeType.reset();
    }

    @Test
    void maliciousFontGetsNoHintingFlag() {
        callNewFace(malicious, FACE_ADDRESS);

        int result = FreeType.FT_Load_Glyph(new FT_Face(FACE_ADDRESS), 0, 0);

        assertEquals(0, result);
        assertEquals(1, FreeType.loadGlyphCalls);
        assertEquals(0x8002, FreeType.lastLoadFlags);
        assertEquals(FACE_ADDRESS, FreeType.lastFaceAddress);
    }

    @Test
    void cleanFontFlagsAreUnchanged() {
        callNewFace(clean, FACE_ADDRESS);

        FreeType.FT_Load_Glyph(new FT_Face(FACE_ADDRESS), 0, 0);

        assertEquals(1, FreeType.loadGlyphCalls);
        assertEquals(0, FreeType.lastLoadFlags);
    }

    @Test
    void existingLoadFlagsArePreserved() {
        callNewFace(malicious, FACE_ADDRESS);

        FreeType.FT_Load_Glyph(new FT_Face(FACE_ADDRESS), 0, 0x4);

        assertEquals(0x8006, FreeType.lastLoadFlags);
    }

    @Test
    void blockPolicyRejectsTheFaceItself() {
        System.setProperty(FixPolicy.PROP_POLICY, "block");
        FaceGuard.clearForTests();

        int newFace = FreeType.FT_New_Memory_Face(
                0L, ByteBuffer.wrap(malicious), malicious.length, new PointerBuffer(FACE_ADDRESS));

        assertEquals(0, FreeType.newFaceCalls);
        assertEquals(FaceGuard.FT_ERR_INVALID_FILE_FORMAT, newFace);
    }

    @Test
    void blockPolicyDoesNotRejectCleanFonts() {
        System.setProperty(FixPolicy.PROP_POLICY, "block");
        FaceGuard.clearForTests();

        int newFace = FreeType.FT_New_Memory_Face(
                0L, ByteBuffer.wrap(clean), clean.length, new PointerBuffer(FACE_ADDRESS));

        assertEquals(0, newFace);
        assertEquals(1, FreeType.newFaceCalls);
    }

    @Test
    void recordsTheAddressAtTheOutputPointersPosition() {
        PointerBuffer pointers = new PointerBuffer(1L, FACE_ADDRESS).position(1);
        assertEquals(0, FreeType.FT_New_Memory_Face(0, ByteBuffer.wrap(malicious), 0, pointers));

        FreeType.FT_Load_Glyph(new FT_Face(FACE_ADDRESS), 0, 0);
        assertEquals(0x8002, FreeType.lastLoadFlags);
    }

    @Test
    void characterLoadsUseTheSamePolicyAsGlyphLoads() {
        callNewFace(malicious, FACE_ADDRESS);

        FreeType.FT_Load_Char(new FT_Face(FACE_ADDRESS), 'A', 4);

        assertEquals(0x8006, FreeType.lastLoadFlags);
    }

    @Test
    void safeChannelStripsHintingFromCleanFonts() {
        System.setProperty(FixPolicy.PROP_POLICY, "safe");
        FaceGuard.clearForTests();

        int newFace = FreeType.FT_New_Memory_Face(
                0L, ByteBuffer.wrap(clean), clean.length, new PointerBuffer(FACE_ADDRESS));
        assertEquals(0, newFace);
        FreeType.FT_Load_Glyph(new FT_Face(FACE_ADDRESS), 0, 0);

        assertEquals(0x8002, FreeType.lastLoadFlags,
                "with the safe channel even a clean font must be loaded without hinting");
    }

    @Test
    void safeChannelStillReportsTheAttack() {
        System.setProperty(FixPolicy.PROP_POLICY, "safe");
        FaceGuard.clearForTests();

        int newFace = FreeType.FT_New_Memory_Face(
                0L, ByteBuffer.wrap(malicious), malicious.length, new PointerBuffer(FACE_ADDRESS));
        assertEquals(0, newFace);

        assertTrue(FaceGuard.wasFlaggedForTests(FACE_ADDRESS),
                "a hostile font must still be recorded so the player can be warned");
    }

    @Test
    void offPolicyLeavesEverythingAlone() {
        System.setProperty(FixPolicy.PROP_POLICY, "off");
        FaceGuard.clearForTests();
        callNewFace(malicious, FACE_ADDRESS);

        FreeType.FT_Load_Glyph(new FT_Face(FACE_ADDRESS), 0, 0);

        assertEquals(1, FreeType.loadGlyphCalls);
        assertEquals(0, FreeType.lastLoadFlags);
    }

    @Test
    void failedNewFaceIsNotInspected() {
        FreeType.newFaceResult = 3;

        int result = FreeType.FT_New_Memory_Face(
                0L, ByteBuffer.wrap(malicious), malicious.length, new PointerBuffer(FACE_ADDRESS));

        assertEquals(3, result);

        FreeType.FT_Load_Glyph(new FT_Face(FACE_ADDRESS), 0, 0);

        assertEquals(0, FreeType.lastLoadFlags);
    }

    @Test
    void nullPointerBufferDoesNotBreakNewFace() {
        int result = FreeType.FT_New_Memory_Face(
                0L, ByteBuffer.wrap(malicious), malicious.length, null);

        assertEquals(0, result);
        assertEquals(1, FreeType.newFaceCalls);
    }

    private static void callNewFace(byte[] font, long address) {
        int result = FreeType.FT_New_Memory_Face(
                0L, ByteBuffer.wrap(font), font.length, new PointerBuffer(address));

        assertEquals(0, result);
        assertEquals(1, FreeType.newFaceCalls);
        assertEquals(font.length, FreeType.lastFileSize);
    }

    private static byte[] readFont(String name) {
        String configured = System.getProperty("m2sfix.core.fixtures");
        Path path = configured == null
                ? Path.of("..", "core", "src", "test", "resources", "fonts", name)
                : Path.of(configured, name);
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read fixture " + path.toAbsolutePath(), e);
        }
    }

    private static void clearProperties() {
        System.clearProperty(FixPolicy.PROP_ENABLED);
        System.clearProperty(FixPolicy.PROP_POLICY);
        System.clearProperty(FixPolicy.PROP_UNPARSABLE);
        System.clearProperty(FixPolicy.PROP_LOG);
        System.clearProperty(FixPolicy.PROP_SHA256_ALLOW);
    }
}
