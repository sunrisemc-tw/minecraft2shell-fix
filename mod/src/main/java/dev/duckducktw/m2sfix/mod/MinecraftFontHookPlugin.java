package dev.duckducktw.m2sfix.mod;

import java.util.List;
import java.util.Set;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.spongepowered.asm.mixin.MixinEnvironment;
import org.spongepowered.asm.mixin.extensibility.IMixinConfigPlugin;
import org.spongepowered.asm.mixin.extensibility.IMixinInfo;
import org.spongepowered.asm.mixin.transformer.throwables.InvalidMixinException;

public final class MinecraftFontHookPlugin implements IMixinConfigPlugin {

    public static final String FACE_PROVIDER = "net.minecraft.client.gui.font.providers.TrueTypeGlyphProviderDefinition";
    public static final String GLYPH_PROVIDER = "com.mojang.blaze3d.font.TrueTypeGlyphProvider";
    public static final String NATIVE_IMAGE = "com.mojang.blaze3d.platform.NativeImage";

    private static final Set<String> TARGETS = Set.of(FACE_PROVIDER, GLYPH_PROVIDER, NATIVE_IMAGE);
    private static final String FREETYPE = "org/lwjgl/util/freetype/FreeType";
    private static final String BRIDGE = "dev/duckducktw/m2sfix/mod/FreeTypeHooks";

    @Override
    public void postApply(String targetName, ClassNode target, String mixinName, IMixinInfo mixin) {
        boolean opensFace = FACE_PROVIDER.equals(targetName);
        String hook = opensFace ? "FT_New_Memory_Face" : "FT_Load_Glyph";
        String descriptor = opensFace ? "(JLjava/nio/ByteBuffer;JLorg/lwjgl/PointerBuffer;)I"
                : "(Lorg/lwjgl/util/freetype/FT_Face;II)I";
        int intercepted = 0;
        for (MethodNode method : target.methods) {
            for (var instruction : method.instructions) {
                if (instruction instanceof MethodInsnNode call && call.getOpcode() == Opcodes.INVOKESTATIC
                        && FREETYPE.equals(call.owner) && hook.equals(call.name) && descriptor.equals(call.desc)) {
                    call.owner = BRIDGE;
                    intercepted++;
                }
            }
        }
        if (intercepted == 0) {
            throw new InvalidMixinException(mixin, reportFailure("Guard could not intercept " + hook + " in " + targetName));
        }
    }

    @Override
    public void onLoad(String mixinPackage) {
    }

    @Override
    public String getRefMapperConfig() {
        return null;
    }

    @Override
    public boolean shouldApplyMixin(String targetName, String mixinName) {
        return true;
    }

    @Override
    public void acceptTargets(Set<String> ownTargets, Set<String> otherTargets) {
        if (MixinEnvironment.getCurrentEnvironment().getSide() == MixinEnvironment.Side.CLIENT
                && !ownTargets.containsAll(TARGETS)) {
            List<String> missing = TARGETS.stream().filter(target -> !ownTargets.contains(target)).sorted().toList();
            throw new IllegalStateException(reportFailure("Missing font guard targets " + missing));
        }
    }

    private static String reportFailure(String reason) {
        String message = "[m2sfix] " + reason + ". Use the -javaagent route.";
        System.err.println(message);
        return message;
    }

    @Override
    public List<String> getMixins() {
        return null;
    }

    @Override
    public void preApply(String targetName, ClassNode target, String mixinName, IMixinInfo mixin) {
    }
}
