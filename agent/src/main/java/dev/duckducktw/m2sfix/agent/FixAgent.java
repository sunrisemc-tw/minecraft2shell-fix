package dev.duckducktw.m2sfix.agent;

import dev.duckducktw.m2sfix.core.FaceGuard;
import dev.duckducktw.m2sfix.core.FixPolicy;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.JarFile;

/**
 * Java agent entry point: {@code -javaagent:minecraft2shell-fix-agent.jar}.
 *
 * <p>Registers the FreeType transformer and exposes its bridge to the loader
 * that defines LWJGL.</p>
 *
 * <p>Every failure path disables the guard and logs once: a mitigation that
 * breaks the client would be worse than no mitigation at all.</p>
 */
public final class FixAgent {

    private static final AtomicBoolean FAILED = new AtomicBoolean(false);

    private FixAgent() {
    }

    public static void premain(String args, Instrumentation instrumentation) {
        try {
            if (instrumentation == null) {
                fail("Instrumentation is null");
                return;
            }
            exposeBridgeToGameLoaders(instrumentation);
            System.err.println("[m2sfix] agent active (policy=" + FixPolicy.policy()
                    + ", images=" + (FixPolicy.imageGuardEnabled() ? "guarded" : "off") + ")");
            FixTransformer transformer = new FixTransformer();
            instrumentation.addTransformer(transformer, true);
            retransformIfAlreadyLoaded(instrumentation);
        } catch (Throwable throwable) {
            fail("agent installation failed: " + safeMessage(throwable));
        }
    }

    private static void exposeBridgeToGameLoaders(Instrumentation instrumentation) throws Exception {
        Path location = Path.of(FixAgent.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        if (Files.isRegularFile(location)) {
            Path bridgePath = Files.createTempFile("m2sfix-bridge-", ".jar");
            bridgePath.toFile().deleteOnExit();
            // Keep the bridge off the application class path so Knot delegates to bootstrap.
            try (var resource = FixAgent.class.getResourceAsStream("/META-INF/m2sfix-bridge.jar")) {
                Files.copy(resource, bridgePath, StandardCopyOption.REPLACE_EXISTING);
            }
            try (JarFile agent = new JarFile(location.toFile());
                    JarFile bridge = new JarFile(bridgePath.toFile())) {
                instrumentation.appendToBootstrapClassLoaderSearch(agent);
                instrumentation.appendToBootstrapClassLoaderSearch(bridge);
            }
        }
    }

    /**
     * LWJGL classes are usually not loaded yet at {@code premain} time, but an
     * agent can also be attached at runtime, so loaded copies are re-transformed
     * once to be safe.
     */
    private static void retransformIfAlreadyLoaded(Instrumentation instrumentation) {
        try {
            if (!instrumentation.isRetransformClassesSupported()) {
                return;
            }
            for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
                String name = loaded.getName();
                boolean fontBinding = FixTransformer.TARGET_BINARY_NAME.equals(name);
                boolean imageDecoder = FixTransformer.STB_BINARY_NAME.equals(name);
                if ((fontBinding || imageDecoder) && instrumentation.isModifiableClass(loaded)) {
                    instrumentation.retransformClasses(loaded);
                    System.err.println("[m2sfix] retransformed already loaded " + name);
                }
            }
        } catch (Throwable throwable) {
            fail("retransformation of an already loaded FreeType binding failed: "
                    + safeMessage(throwable));
        }
    }

    private static void fail(String message) {
        if (FAILED.compareAndSet(false, true)) {
            System.err.println("[m2sfix] " + message + " - guard disabled");
        }
        FaceGuard.disableForFailure();
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank() ? throwable.getClass().getSimpleName() : message;
    }
}
