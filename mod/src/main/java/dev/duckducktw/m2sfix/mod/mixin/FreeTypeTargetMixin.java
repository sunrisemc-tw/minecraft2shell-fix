package dev.duckducktw.m2sfix.mod.mixin;

import dev.duckducktw.m2sfix.core.FaceGuard;
import dev.duckducktw.m2sfix.mod.FreeTypeHooks;
import java.nio.ByteBuffer;
import org.lwjgl.PointerBuffer;
import org.lwjgl.util.freetype.FT_Face;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.ModifyVariable;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

@Mixin(targets = "org.lwjgl.util.freetype.FreeType", remap = false)
public class FreeTypeTargetMixin {

    @Unique
    private static void m2sfix$hookInstalled() {
    }

    @Inject(
            method = "FT_New_Memory_Face(JLjava/nio/ByteBuffer;JLorg/lwjgl/PointerBuffer;)I",
            at = @At("HEAD"),
            cancellable = true,
            remap = false)
    private static void m2sfix$beforeNewFace(
            long library,
            ByteBuffer file,
            long faceIndex,
            PointerBuffer facePointerBuffer,
            CallbackInfoReturnable<Integer> callback) {
        int rejection = FaceGuard.beforeNewFace(file);
        if (rejection != 0) {
            callback.setReturnValue(rejection);
        }
    }

    @Inject(
            method = "FT_New_Memory_Face(JLjava/nio/ByteBuffer;JLorg/lwjgl/PointerBuffer;)I",
            at = @At("RETURN"),
            remap = false)
    private static void m2sfix$afterNewFace(
            long library,
            ByteBuffer file,
            long faceIndex,
            PointerBuffer facePointerBuffer,
            CallbackInfoReturnable<Integer> callback) {
        FreeTypeHooks.afterNewFace(file, facePointerBuffer, callback.getReturnValue());
    }

    @ModifyVariable(
            method = "FT_Load_Glyph(Lorg/lwjgl/util/freetype/FT_Face;II)I",
            at = @At("HEAD"),
            argsOnly = true,
            index = 2,
            remap = false)
    private static int m2sfix$adjustLoadFlags(int flags, FT_Face face, int glyphIndex) {
        return FreeTypeHooks.adjustFlags(face, flags);
    }

    @ModifyVariable(
            method = "FT_Load_Char(Lorg/lwjgl/util/freetype/FT_Face;JI)I",
            at = @At("HEAD"),
            argsOnly = true,
            index = 3,
            remap = false)
    private static int m2sfix$adjustCharLoadFlags(int flags, FT_Face face, long characterCode) {
        return FaceGuard.adjustCharLoadFlags(face == null ? 0L : face.address(), flags);
    }
}
