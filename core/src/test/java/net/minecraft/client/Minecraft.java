package net.minecraft.client;

import java.util.ArrayDeque;
import java.util.Deque;
import net.minecraft.client.gui.screens.Screen;

/** Test-only stand-in: records screens, and runs tasks immediately like the real client loop would. */
public class Minecraft {

    private static final Minecraft INSTANCE = new Minecraft();

    public Screen currentScreen;
    public boolean disconnectCalled;
    public final Deque<Runnable> pending = new ArrayDeque<>();

    public static Minecraft getInstance() {
        return INSTANCE;
    }

    public void setScreenAndShow(Screen screen) {
        this.currentScreen = screen;
    }

    public void setScreen(Screen screen) {
        this.currentScreen = screen;
    }

    public void execute(Runnable task) {
        pending.add(task);
        task.run();
    }

    public void disconnectWithSavingScreen() {
        disconnectCalled = true;
    }

    public void disconnect() {
        disconnectCalled = true;
    }

    public void reset() {
        currentScreen = null;
        disconnectCalled = false;
        pending.clear();
    }
}
