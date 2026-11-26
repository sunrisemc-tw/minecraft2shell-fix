package dev.duckducktw.m2sfix.mod.mixin;

import dev.duckducktw.m2sfix.core.FixPolicy;
import dev.duckducktw.m2sfix.core.ImageGuard;
import java.nio.ByteBuffer;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.ModifyVariable;

/**
 * Stops resource-pack images from reaching {@code stb_image} when their declared geometry cannot fit.
 *
 * <p>Same idea as the agent side: the buffer handed to the decoder is replaced by an empty one, so
 * {@code stb_image} fails normally ("not of any known type, or corrupt") and Minecraft renders a
 * missing texture instead of writing past the buffer it allocated.</p>
 *
 * <p>Targets a library class, so nothing has to be remapped and the mixin works on every loader that
 * can host Mixin with this configuration.</p>
 */
@Mixin(targets = "org.lwjgl.stb.STBImage", remap = false)
public class StbImageMixin {

    @ModifyVariable(
            method = "stbi_load_from_memory",
            at = @At("HEAD"),
            argsOnly = true,
            index = 0,
            remap = false)
    private static ByteBuffer m2sfix$screenImage(ByteBuffer image) {
        try {
            if (image == null || !FixPolicy.enabled() || !FixPolicy.imageGuardEnabled()) {
                return image;
            }
            StringBuilder reason = new StringBuilder();
            ImageGuard.Verdict verdict = ImageGuard.inspect(image, FixPolicy.imageMaxPixels(),
                    ImageGuard.DEFAULT_MAX_BYTES, reason);
            if (verdict == ImageGuard.Verdict.REJECT) {
                if (FixPolicy.logEnabled()) {
                    System.err.println("[m2sfix] refused image: " + reason);
                }
                return EMPTY;
            }
            return image;
        } catch (Throwable ignored) {
            return image;
        }
    }

    private static final ByteBuffer EMPTY = ByteBuffer.allocateDirect(0);
}
