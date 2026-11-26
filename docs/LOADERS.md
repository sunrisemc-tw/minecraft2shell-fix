# Fabric, Forge, and NeoForge verification

One client mod jar carries Fabric metadata, Forge's `META-INF/mods.toml`, and NeoForge's `META-INF/neoforge.mods.toml`. Forge and NeoForge accepted the `lowcodefml` entry without an `@Mod` class. Forge registered the required Mixin config through `MixinConfigs` in the manifest. NeoForge registered it through `[[mixins]]` in the TOML.

Fabric applies the hooks directly to LWJGL and checks for an injected marker at client initialization. On Forge and NeoForge the plugin intercepts the FreeType invocations in `TrueTypeGlyphProviderDefinition`, `TrueTypeGlyphProvider`, and `NativeImage`. These names appeared at runtime in the tested Forge and NeoForge clients. The plugin matches the LWJGL invocation descriptors independently of the caller method names. It fails startup with a `-javaagent` message if a required target or call is missing.

A temporary class-loading probe showed that Fabric Loader 0.20.1 loads FreeType through Knot. Forge 50.2.15 and 60.1.18 load it from a separate SecureModuleClassLoader. NeoForge 20.5.21-beta and 20.6.144 use a separate ModuleClassLoader. Both are child layers distinct from the transforming Minecraft class loader. NeoForge 21.10.64 and 26.3.0.118 load FreeType through the application class loader and Minecraft through NeoForge's transforming loader.

Both delivery paths use the shared first-intercept logs and the two no-hinting flags from main. Block policy checks before native face creation. The success hook reads the returned pointer at the buffer's current position. The agent and Fabric hook `FT_Load_Char` directly. Forge and NeoForge cover Minecraft's verified call sites. A third-party mod calling FreeType directly on Forge or NeoForge requires the agent for that call to be intercepted.

The packaged agent keeps its bridge in an embedded bootstrap jar. Fabric's Knot rejected the original bridge when it found its class resource in the outer agent jar. The same Fabric dev client passed after the bridge was moved to the embedded jar.

## Live clients

These macOS ARM64 runs used the packaged jars and a local pack with the repository's synthetic flagged font and clean font. The pack supplied TTF providers for `minecraft:default` and `minecraft:uniform`. Clients ran offline with Java 21 for Minecraft 1.x and Java 25 for 26.3.

| Route | Minecraft | Loader | Launcher |
| --- | --- | --- | --- |
| Mod | 1.21.10 | Fabric 0.20.1 | Loom 1.15.5 `runClient` and installed profile |
| Mod | 1.20.6 | Forge 50.2.15 | ForgeGradle 7.0.40 `runClient` |
| Mod | 1.21.10 | Forge 60.1.18 | ForgeGradle 7.0.40 `runClient` and installed profile |
| Mod | 1.20.5 | NeoForge 20.5.21-beta | Installed profile |
| Mod | 1.20.6 | NeoForge 20.6.144 | ModDevGradle 2.0.148 `runClient` |
| Mod | 1.21.10 | NeoForge 21.10.64 | ModDevGradle 2.0.148 `runClient` |
| Mod | 26.3 | NeoForge 26.3.0.118 | ModDevGradle 2.0.148 `runClient` |
| Agent | 1.21.10 | Fabric 0.20.1 | Loom 1.15.5 `runClient` |
| Agent | 1.21.10 | Vanilla | Mojang client with `-javaagent` |

Each row emitted these exact message bodies in safe mode. The positive mod runs had no Mixin apply errors.

```text
[m2sfix] guard active: FT_New_Memory_Face intercepted (policy=safe)
[m2sfix] flagged font af2b7c76ccf70919dd83c1f2afe0294d6bb688c4d197c514ea8ec729d297617e (SUSPICIOUS): IDEF redefines point-zone opcode 0x36 in fpgm
[m2sfix] guard active: FT_Load_Glyph intercepted (policy=safe)
```

The installed NeoForge 1.20.5 profile supplied a live test at the version floor. ModDevGradle 2.0.148 could not resolve the historical release as a dev bundle. The Forge 1.20.6 client required the Mixin config's Java 17 compatibility setting because its Mixin 0.8.5 does not recognize `JAVA_21`. The mod itself targets Java 21.

## Failure and notification checks

- Removing the Fabric Mixin registration from a temporary jar stopped startup with `[m2sfix] FreeType guard did not apply on Fabric. Use the -javaagent route.`
- Removing the client Mixin from a temporary NeoForge jar stopped startup and printed `[m2sfix] Missing font guard targets [com.mojang.blaze3d.font.TrueTypeGlyphProvider, com.mojang.blaze3d.platform.NativeImage, net.minecraft.client.gui.font.providers.TrueTypeGlyphProviderDefinition]. Use the -javaagent route.`
- Forge 60.1.18 under the block policy logged `[m2sfix] guard active: FT_New_Memory_Face intercepted (policy=block)`. Minecraft rejected the flagged provider with `FreeType error: Unrecognized error: 0x2 (Initializing font face)`. An agent regression test asserts that the underlying face creation receives zero calls for this fixture.
- `[m2sfix] warning dialog opened` confirmed that the client installed the warning screen on Forge 60.1.18 production, NeoForge 26.3.0.118 dev, and Fabric 0.20.1 dev with the agent. The obfuscated vanilla 1.21.10 and intermediary Fabric 1.21.10 clients emitted the bilingual warning to the log and continued loading fonts.
- The callback tests verify that Continue closes the screen and Disconnect invokes the client disconnect method. DesktopCtl reported that GUI operations had previously been disabled. Visual rendering and button interaction in a connected game remain unverified.

`mvn -B clean package` reported 67 passed, zero failures or errors, and one existing platform-dependent skip for the `/usr/share/fonts` test. Other loader versions, operating systems, and live calls to `FT_Load_Char` remain unverified.
