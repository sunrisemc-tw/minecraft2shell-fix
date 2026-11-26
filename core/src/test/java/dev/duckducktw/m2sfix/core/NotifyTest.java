package dev.duckducktw.m2sfix.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.ConfirmScreen;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Exercises {@link Notify} against Minecraft stand-ins: the reflection path it uses inside the agent
 * has to build a real confirm screen with the two buttons and wire the callback correctly.
 */
class NotifyTest {

    private Minecraft client;

    @BeforeEach
    void setUp() {
        client = Minecraft.getInstance();
        client.reset();
        Notify.resetForTests();
        FaceGuard.clearForTests();
        System.clearProperty(FixPolicy.PROP_NOTIFY);
    }

    @AfterEach
    void tearDown() {
        client.reset();
        System.clearProperty(FixPolicy.PROP_NOTIFY);
        FaceGuard.clearForTests();
    }

    @Test
    void warningShowsAConfirmScreenWithBothButtons() {
        Notify.warnAboutBlockedFont();

        assertTrue(client.currentScreen instanceof ConfirmScreen, "expected a confirm screen");
        ConfirmScreen screen = (ConfirmScreen) client.currentScreen;
        assertEquals("minecraft2shell-fix", screen.title.getString());
        assertTrue(screen.message.getString().contains("minecraft2shell"), screen.message.getString());
        assertTrue(screen.message.getString().contains("已經攔截"), screen.message.getString());
        assertTrue(screen.yesButton.getString().contains("繼續遊玩"), screen.yesButton.getString());
        assertTrue(screen.noButton.getString().contains("中斷連線"), screen.noButton.getString());
        assertFalse(client.disconnectCalled, "showing the dialog must not disconnect anyone");
    }

    @Test
    void messageDoesNotPromiseACommandItCannotKnow() {
        Notify.warnAboutBlockedFont();

        ConfirmScreen screen = (ConfirmScreen) client.currentScreen;
        assertNotNull(screen);
        assertFalse(screen.message.getString().contains("{"),
                "no placeholder may leak into the dialog: " + screen.message.getString());
        assertFalse(screen.message.getString().contains("指令"),
                "the dialog must not claim to know the command: " + screen.message.getString());
    }

    @Test
    void continueButtonKeepsThePlayerConnected() {
        Notify.warnAboutBlockedFont();

        ((ConfirmScreen) client.currentScreen).callback.accept(true);

        assertFalse(client.disconnectCalled);
        assertEquals(null, client.currentScreen);
    }

    @Test
    void disconnectButtonDropsTheConnection() {
        Notify.warnAboutBlockedFont();

        ((ConfirmScreen) client.currentScreen).callback.accept(false);

        assertTrue(client.disconnectCalled);
    }

    @Test
    void notifyCanBeTurnedOff() {
        System.setProperty(FixPolicy.PROP_NOTIFY, "false");
        FaceGuard.clearForTests();

        Notify.warnAboutBlockedFont();

        assertEquals(null, client.currentScreen);
    }

    @Test
    void aFlaggedFontTriggersTheWarningOnceOnly() throws Exception {
        byte[] hostile = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(
                NotifyTest.class.getResource("/fonts/malicious-idef.ttf").toURI()));

        FaceGuard.inspectNewFace(0x1234L, java.nio.ByteBuffer.wrap(hostile), hostile.length);
        ConfirmScreen first = (ConfirmScreen) client.currentScreen;
        assertNotNull(first, "the first flagged font must warn");

        client.reset();
        FaceGuard.inspectNewFace(0x5678L, java.nio.ByteBuffer.wrap(hostile), hostile.length);
        assertEquals(null, client.currentScreen, "the same font must not warn twice");
    }

    @Test
    void aRiskyShzFontDoesNotTriggerTheWarningDialog() throws Exception {
        System.setProperty(FixPolicy.PROP_POLICY, "detect");
        FaceGuard.clearForTests();
        byte[] risky = TestFonts.read(TestFonts.SHZ_IN_GLYPH);

        boolean degraded = FaceGuard.inspectNewFace(0x9999L, java.nio.ByteBuffer.wrap(risky), risky.length);

        assertTrue(degraded, "detect mode must strip hinting from RISKY SHZ faces");
        assertEquals(null, client.currentScreen, "RISKY faces must not trigger the malicious-pack dialog");
    }

}
