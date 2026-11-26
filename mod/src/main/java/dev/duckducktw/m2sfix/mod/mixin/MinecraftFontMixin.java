package dev.duckducktw.m2sfix.mod.mixin;

import dev.duckducktw.m2sfix.mod.MinecraftFontHookPlugin;
import org.spongepowered.asm.mixin.Mixin;

@Mixin(targets = {
    MinecraftFontHookPlugin.FACE_PROVIDER,
    MinecraftFontHookPlugin.GLYPH_PROVIDER,
    MinecraftFontHookPlugin.NATIVE_IMAGE
}, remap = false)
public class MinecraftFontMixin {
}
