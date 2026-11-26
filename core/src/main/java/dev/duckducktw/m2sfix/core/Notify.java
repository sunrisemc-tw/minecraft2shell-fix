package dev.duckducktw.m2sfix.core;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Shows the in-game warning when a malicious font was caught.
 *
 * <p>Everything here is reflection on purpose: the same code runs inside the javaagent (which must
 * not link against Minecraft classes) and inside the mod, and no Minecraft compile-time dependency
 * is wanted in {@code core}. The dialog is the vanilla {@code ConfirmScreen} with two buttons —
 * "continue anyway" and "disconnect" — because it already looks like a Minecraft dialog and needs no
 * screen implementation of our own.</p>
 *
 * <p>If the dialog is unavailable, the warning is logged.</p>
 */
public final class Notify {

    private static final AtomicBoolean SHOWN_FOR_SESSION = new AtomicBoolean(false);

    private static final String CLS_MINECRAFT = "net.minecraft.client.Minecraft";
    private static final String CLS_COMPONENT = "net.minecraft.network.chat.Component";
    private static final String CLS_SCREEN = "net.minecraft.client.gui.screens.Screen";
    private static final String CLS_CONFIRM = "net.minecraft.client.gui.screens.ConfirmScreen";
    private static final String CLS_BOOLEAN_CONSUMER = "it.unimi.dsi.fastutil.booleans.BooleanConsumer";

    private Notify() {
    }

    /**
     * Warns the player that a font from the server's resource pack was blocked.
     *
     * <p>No command is shown: the published exploit assembles its payload inside the font's own
     * bytecode, so there is no reliable way to recover "what it would have run" for an arbitrary
     * sample — and showing a guess would be worse than showing nothing.</p>
     */
    public static void warnAboutBlockedFont() {
        try {
            if (!FixPolicy.notifyEnabled()) {
                return;
            }
            String body = body();
            if (showConfirmScreen(body)) {
                return;
            }
            log(body);
        } catch (Throwable ignored) {
            // A warning is never worth breaking a client over.
        }
    }

    /** Test hook: forgets that a warning was already shown. */
    public static void resetForTests() {
        SHOWN_FOR_SESSION.set(false);
    }

    /** @return {@code true} when the modal dialog was installed */
    private static boolean showConfirmScreen(String body) {
        try {
            Class<?> minecraft = minecraftClass();
            ClassLoader loader = minecraft.getClassLoader();
            Object client = minecraft.getMethod("getInstance").invoke(null);
            if (client == null) {
                return false;
            }

            Class<?> component = Class.forName(CLS_COMPONENT, false, loader);
            Class<?> screen = Class.forName(CLS_SCREEN, false, loader);
            Class<?> confirm = Class.forName(CLS_CONFIRM, false, loader);
            Class<?> booleanConsumer = Class.forName(CLS_BOOLEAN_CONSUMER, false, loader);

            Method setScreen = findMethod(minecraft, "setScreen", "setScreenAndShow", screen);
            Method disconnect = findMethod(minecraft, "disconnectWithSavingScreen", "disconnect");

            Object title = literal(component, "minecraft2shell-fix");
            Object message = literal(component, body);
            Object yes = literal(component, "我了解，繼續遊玩 / Continue");
            Object no = literal(component, "中斷連線 / Disconnect");

            Constructor<?> constructor = confirm.getConstructor(
                    booleanConsumer, component, component, component, component);
            Object dialog = constructor.newInstance(screenCallback(client, booleanConsumer, setScreen, disconnect, body),
                    title, message, yes, no);

            Runnable show = () -> {
                try {
                    setScreen.invoke(client, dialog);
                    if (FixPolicy.logEnabled()) {
                        System.err.println("[m2sfix] warning dialog opened");
                    }
                } catch (Throwable ignored) {
                    log(body);
                }
            };

            if (SHOWN_FOR_SESSION.compareAndSet(false, true)) {
                minecraft.getMethod("execute", Runnable.class).invoke(client, show);
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Builds the {@code BooleanConsumer} that the confirm screen calls back with: {@code true} for
     * "continue", {@code false} for "disconnect".
     */
    private static Object screenCallback(Object client, Class<?> booleanConsumer, Method setScreen,
            Method disconnect, String body) {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("accept".equals(method.getName()) && args != null && args.length == 1) {
                try {
                    if (Boolean.TRUE.equals(args[0])) {
                        setScreen.invoke(client, (Object) null);
                    } else {
                        disconnect.invoke(client);
                    }
                } catch (Throwable ignored) {
                    log(body);
                }
            }
            return defaultValue(method.getReturnType());
        };
        return Proxy.newProxyInstance(booleanConsumer.getClassLoader(),
                new Class<?>[]{booleanConsumer}, handler);
    }

    private static Object literal(Class<?> component, String value) throws ReflectiveOperationException {
        return component.getMethod("literal", String.class).invoke(null, value);
    }

    private static Method findMethod(Class<?> owner, String name, String fallback, Class<?>... parameters)
            throws NoSuchMethodException {
        try {
            return owner.getMethod(name, parameters);
        } catch (NoSuchMethodException missing) {
            return owner.getMethod(fallback, parameters);
        }
    }

    private static String body() {
        return "檢測到伺服器的資源包疑似包含惡意內容（minecraft2shell），已經攔截。\n"
                + "這類字型可以在你的電腦上執行任意程式，這個伺服器送來的樣本沒有被執行。\n\n"
                + "This server's resource pack looks malicious (minecraft2shell). It was blocked and did "
                + "not run; fonts like this can execute arbitrary code on the client.";
    }

    private static void log(String body) {
        System.err.println("[m2sfix] " + body.replace("\n", " | "));
    }

    private static Object defaultValue(Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        return null;
    }

    private static Class<?> minecraftClass() throws ClassNotFoundException {
        try {
            return Class.forName(CLS_MINECRAFT, false, Thread.currentThread().getContextClassLoader());
        } catch (ClassNotFoundException missingFromContext) {
            return Class.forName(CLS_MINECRAFT, false, Notify.class.getClassLoader());
        }
    }
}
