# How it works (technical)

This is the technical companion to the README. The README is written for players; everything a mod
author or anyone auditing the mitigation needs is here.

> **Status: hooks verified in live clients on macOS; the exploit itself was never run against it.** See [Verification](#verification) for
> exactly what was run.
>
> The published exploit traced step by step (delivery → trigger → font internals → the `Ins_SHZ`
> bug → which step this project cuts) is in **[EXPLOIT-ANALYSIS.md](EXPLOIT-ANALYSIS.md)**.

## 1. The bug

Minecraft 26.3 renders `ttf` fonts through FreeType **2.14.3**, bundled in LWJGL **3.4.3**. A
resource pack font with a nested composite glyph can make the `SHZ` instruction move points past the
physically allocated point buffer; in `src/truetype/ttinterp.c` the limit is taken from the zone's
last contour instead of the allocation, so `Move_Zp2_Point` writes out of bounds. The font's own
bytecode then uses `IDEF` (redefining an existing opcode, `SHZ`/`0x36`) to regain control after
FreeType's error dispatch, derives the module base from a live callback pointer, and pivots into a ROP
chain on the TrueType VM stack.

Published proof of concept: [`bikini/minecraft2shell`](https://github.com/bikini/minecraft2shell)
(Windows x64, Minecraft Java 26.3, that specific FreeType build).

Upstream FreeType fixed the `Ins_SHZ` range limit in April 2026 (Mozilla bug 2032043) and shipped it
in **2.15.0** (2026-10-12). Minecraft still bundles 2.14.3, so this project is a stopgap.

## 2. Where the mitigation hooks

Native code cannot be patched from Java, so the chain is cut one layer above, at the two Java entry
points Minecraft actually uses (verified with `javap` on the Mojang-signed 26.3 client jar):

| Minecraft call site | LWJGL method | what the hook does |
| --- | --- | --- |
| `net.minecraft.client.gui.font.providers.TrueTypeGlyphProviderDefinition.load(ResourceManager)` | `FreeType.FT_New_Memory_Face(long, ByteBuffer, long, PointerBuffer)` | lint the font bytes once, remember the verdict for that `FT_Face` address |
| `com.mojang.blaze3d.font.TrueTypeGlyphProvider.loadGlyph(int, FT_Face, int)` and `com.mojang.blaze3d.platform.NativeImage` | `FreeType.FT_Load_Glyph(FT_Face, int, int)` | OR in `FT_LOAD_NO_HINTING \| FT_LOAD_NO_AUTOHINT` (`0x8002`) — every face under `safe`, flagged faces under `detect` |

Every glyph-program execution path in `ttgload.c` is gated by `IS_HINTED(load_flags)` — the simple
glyph path, the composite path, the recursive component path — and so are `fpgm`/`prep`, which only
run from inside the same block of `tt_loader_init`. A face loaded without hinting therefore never runs
the interpreter, so there is no `SHZ` execution and no `IDEF` recovery program.

**Why `0x8002` and not just `0x2`.** For some faces `tt_glyph_load` (ttdriver.c) ignores
`FT_LOAD_NO_HINTING` unless `FT_LOAD_NO_AUTOHINT` is also set, so 2.2.0 always sets both. A full
write-up follows once upstream has shipped the same change.

All three hooks also log `[m2sfix] guard active: <hook> intercepted (policy=…)` the first time they
fire, so a hook that never applied shows up as a missing line rather than as silence.

### 2.1 The agent

`FixTransformer` is a plain `ClassFileTransformer` with a small ASM visitor. It splices exactly two
straight-line sequences, so existing stack-map frames stay valid and only `maxStack`/`maxLocals` are
recomputed:

```
FT_Load_Glyph / FT_Load_Char(face, …, flags):     // method entry
    flags = AgentBridge.adjustFlags(face, flags)

FT_New_Memory_Face(lib, file, faceIndex, aface):
    r = AgentBridge.beforeNewFace(file); if (r != 0) return r   // entry: block policy, no native call
    …
    return AgentBridge.afterNewFace(file, aface, result)        // before every IRETURN
```

At `premain` the agent appends itself and a small embedded `AgentBridge` jar to the bootstrap class
path. Fabric's Knot loader defines `FreeType` and refuses to delegate to classes it finds in the
outer agent jar, so the bridge lives only in the embedded jar; this was the difference between a
`NoClassDefFoundError` and a working guard in a live Fabric client.

`AgentBridge` is the only class that touches `FaceGuard`; it resolves the face address and the
`PointerBuffer` entry by reflection, so the injected code never links against LWJGL types. Any
failure inside the bridge returns the caller's original value: a broken guard must never break a
client.

ByteBuddy `Advice` was tried first and abandoned: in 1.14.19 it silently skips methods that have a
`ByteBuffer` parameter (no weaving, no error), and `@Advice.OnMethodEnter(skipOn = …)` silently does
nothing. See `docs/IMPLEMENTATION-NOTES.md` for the bisect.

### 2.2 The mod

One jar, two hook strategies, because the loaders put LWJGL in different places:

- **Fabric** loads LWJGL through Knot, which Mixin can transform, so `FreeTypeTargetMixin` patches
  `org.lwjgl.util.freetype.FreeType` itself (`FT_New_Memory_Face` HEAD + RETURN, `FT_Load_Glyph` and
  `FT_Load_Char` flags). A client entrypoint checks for an injected marker method and stops startup if
  the mixin did not apply.
- **Forge / NeoForge** load LWJGL in a layer Mixin cannot transform. `MinecraftFontHookPlugin`
  instead rewrites the `INVOKESTATIC FreeType.FT_*` instructions in Minecraft's own callers
  (`TrueTypeGlyphProviderDefinition`, `TrueTypeGlyphProvider`, `NativeImage`) to `FreeTypeHooks`,
  matching on the LWJGL descriptor so caller method names do not matter. A missing target or a target
  with no matching call stops startup with a message pointing to `-javaagent`. Third-party mods that
  call FreeType directly are not covered on these loaders; the agent covers them.

Metadata: `fabric.mod.json`, `META-INF/mods.toml` (Forge, `lowcodefml`) and
`META-INF/neoforge.mods.toml` (NeoForge 1.20.5+, with a `[[mixins]]` block). Loader-by-loader test
results are in [LOADERS.md](LOADERS.md).

### 2.3 A trap worth knowing

LWJGL's four-argument `FT_New_Memory_Face(long, ByteBuffer, long, PointerBuffer)` does **not** treat
its `long` as a size. Its bytecode passes `buffer.remaining()` as the size and the declared parameter
as `face_index` (`nFT_New_Memory_Face(lib, base, remaining, declared, aface)`). Passing
`bytes.length` there yields `FT_Err_Invalid_Argument (6)`, and any scanner reading the size from that
slot would inspect zero bytes and never flag anything. Both the agent and the mod derive the length
from `ByteBuffer.remaining()`.

## 3. The scanner

`core/TtfScanner` is a defensive sfnt parser with no dependencies:

- sfnt versions `0x00010000`, `true`, `OTTO`, `typ1`, plus `ttcf` collections (every face is scanned).
- Reads the table directory, then walks the instruction streams of `fpgm`, `prep` and every glyph
  (`loca`/`head`/`maxp`/`glyf`, both `indexToLocFormat` widths, simple and composite glyphs).
- The instruction decoder handles the variable-length pushes (`PUSHB`/`PUSHW`/`NPUSHB`/`NPUSHW`) and
  takes `FDEF`/`IDEF` definition numbers from the preceding push, as FreeType's `args[0]` does. Payload bytes are
  never interpreted as opcodes — there is a regression fixture for that (`pushb-decoy.ttf`).
- Verdicts, strongest first: `SUSPICIOUS` = the published exploit's shape (`IDEF` redefining a
  point-zone instruction, or `IDEF` in a glyph program) — warning dialog, rejected under `block`;
  `RISKY` = the bytecode could execute `SHZ` (`0x36`/`0x37`) at all, or defines an `IDEF` whose opcode
  cannot be read statically — loses hinting under `detect`, no dialog; `UNPARSABLE` = fails closed;
  `CLEAN`. The completeness argument for `RISKY` (linear decode plus jump targets inside push data),
  its FreeType source references and the false-positive count are in [DETECT-MODE.md](DETECT-MODE.md).
- The definition number of `IDEF`/`FDEF` is read from the value pushed immediately before it, exactly
  like FreeType's `args[0]`; the published exploit's `PUSHB 54; IDEF` is the shape being matched.

Why `IDEF` and not `SHZ`: DejaVu (and 3 more fonts on this machine) legitimately use `SHZ` inside
composite glyph programs, so an `SHZ`-based signature would false-positive on stock fonts.

Why *which* opcode matters: flagging **any** `IDEF` was measured to be too blunt. Sampling 1,042 fonts
from the Google Fonts repository produced two false positives — `KoPubBatang-Regular.ttf` and
`NanumMyeongjo-Regular.ttf`, which define custom instructions for `0x00-0x04` and `0x93`. The exploit
instead redefines `0x36` (`SHZ`), i.e. an instruction FreeType already dispatches and whose handler
moves points, because the recovery lookup matches the opcode that was executing when the corrupted
`error` field was noticed. Keying on the point-zone family removes those false positives while keeping
the whole class of "hijack a point-moving instruction" variants — verified with a `SHPIX` (`0x38`)
variant fixture.

### Variant coverage (false positives *and* false negatives)

`VariantDetectionTest` runs every fixture in both directions, and the fixtures are generated by
`tools/make_fixture_fonts.py` so the cases are explicit rather than accidental:

| case | expectation |
| --- | --- |
| `IDEF` in `fpgm` | flagged |
| `IDEF` in `prep` only | flagged |
| `IDEF` only in a simple glyph program | flagged |
| `IDEF` only in a composite glyph program | flagged |
| `0x89` inside a push payload **and** a real `IDEF` after it | flagged |
| 32-bit `loca` table | flagged |
| 1-glyph font / tiny `maxp` | flagged |
| hostile face as the **second** face of a `.ttc` collection | flagged |
| truncated font | not clean (fails closed) |
| font larger than the scan limit | not clean (fails closed) |
| `FDEF` + `SHZ` + `SHPIX` + `WS` everywhere, no `IDEF` | clean |
| `0x89` only inside push payloads | clean |
| every font installed on the build machine | clean |

Two of these were **found by the tests, not designed in**: the "decoy plus real IDEF" fixture was
initially mis-encoded (the extra `IDEF` sat inside the `PUSHB` payload, so the scanner was right and the
fixture was wrong), and the scan cap used to be a hard-coded constant that could not be exercised —
it is now `m2sfix.maxscan` (MiB, default 64) and the test shrinks it instead of allocating 64 MiB.

### The dialog does not claim to know the command

There is no `{command}` line. The published exploit assembles its command inside the font's bytecode:
`calc.exe` appears in **none** of the 144 shipped fonts in ASCII, UTF-16LE, or as two 4-byte dwords,
and `WinExec` is equally absent. Anything shown there would be a guess, so the dialog states only what
is certain: this pack was malicious, it was blocked, and it did not run.

## 4. The warning dialog

`core/Notify` shows the vanilla `net.minecraft.client.gui.screens.ConfirmScreen`
(`(BooleanConsumer, Component title, Component message, Component yesButton, Component noButton)`):

```
檢測到伺服器的資源包疑似包含惡意內容（minecraft2shell），已經攔截。
這類字型可以在你的電腦上執行任意程式，這個伺服器送來的樣本沒有被執行。

This server's resource pack looks malicious (minecraft2shell). It was blocked and did not run;
fonts like this can execute arbitrary code on the client.

[我了解，繼續遊玩 / Continue]   [中斷連線 / Disconnect]
```

- "Continue" → callback `accept(true)`, nothing happens.
- "Disconnect" → callback `accept(false)` → `Minecraft.disconnectWithSavingScreen()`.
- Everything is reflection (`Minecraft.getInstance()`, `Component.literal`, a `Proxy` for
  `it.unimi.dsi.fastutil.booleans.BooleanConsumer`, `setScreenAndShow`), because `core` must not link
  against Minecraft: the agent cannot, and the mod should not need a Minecraft dependency to compile.
- The screen is installed through `Minecraft.execute(Runnable)`, since font loading happens on a
  resource-reload worker thread.
- Degradation: no Minecraft classes → the same text is printed to the log. One dialog per game
  session, one warning per font hash; `-Dm2sfix.notify=false` disables it.
- Signatures used here were checked with `javap` on the 26.3 client jar; the dialog itself has **not**
  been seen in a real client.

## 4.5 The safe channel (default)

`m2sfix.policy=safe` is the default because it does not depend on the signature at all: every
`FT_Load_Glyph` gets `FT_LOAD_NO_HINTING | FT_LOAD_NO_AUTOHINT`, so `tt_loader_init` never builds an interpreter context and
no font program can run. The `IDEF` scan is then only used to decide whether the player gets a warning
dialog — a wrong scan costs a false alarm, not rendering, and a variant that does not look like `IDEF`
is still neutralised.

The price is measured, not guessed (`CompareHinting`, DejaVu Sans at 32 px, first 300 glyphs, hinted
vs `FT_LOAD_NO_HINTING`): **72.0% of glyph bitmaps differ, mean height difference 0.88 px, mean area
difference 14.9 px², worst case 2 px.** Small text (Minecraft's HUD) loses more apparent sharpness
than large text. `m2sfix.policy=detect` keeps hinting for fonts that provably cannot execute `SHZ`
and strips it from the rest — 85 of 792 faces (10.7%) installed on a stock macOS, see
[DETECT-MODE.md](DETECT-MODE.md).

`block` still refuses flagged faces outright; the safe channel never refuses a glyph, it only
degrades rendering.

## 4.6 Image guard (sibling bug, same delivery path)

PNGs in a pack are decoded by `stb_image` through `lwjgl-stb` — and 26.3 still ships
`lwjgl-stb:3.4.3` with no hotfix. Primitive One's write-up describes an out-of-bounds write during the
16→8-bit conversion (a PNG declaring 23,171² pixels at 16 bits asks for ~4 GiB while the decoder
allocated 192 KiB) plus an uninitialised-palette read that leaks ASLR-relevant pointers.

`core/ImageGuard` reads the PNG (`IHDR`, `PLTE`) or JPEG (`SOF`) header — never the pixels — and does
every multiplication in `long`:

| check | default | what it stops |
| --- | --- | --- |
| pixels ≤ `m2sfix.images.maxpixels` | 16,777,216 | the published geometry outright |
| decoded bytes ≤ 64 MiB | fixed | any size that cannot fit |
| axis ≤ 2^24 | fixed | absurd declared dimensions |
| 16-bit samples above 1 Mpx | fixed | the exact conversion path that overflows |
| indexed PNG with a palette < 256 entries | fixed | the uninitialised-palette disclosure |

The hook replaces the buffer argument with an empty one rather than branching, so the injected bytecode
stays straight-line (`COMPUTE_MAXS`, no invented frame): `stb_image` then fails with "not of any known
type, or corrupt" and Minecraft renders a missing texture.

Measured on the natives Minecraft 26.3 ships, same 1 MB crafted PNG both times:

```
java -javaagent:m2sfix-agent.jar      StbProbe crash16.png
  [m2sfix] agent active (policy=SAFE, images=guarded)
  [m2sfix] refused image: PNG is 23171x23171 = 536895241 pixels (limit 16777216)
  returned=NULL ... PROCESS_SURVIVED

java -Dm2sfix.images=off -javaagent:m2sfix-agent.jar StbProbe crash16.png
  SIGSEGV ... C  [liblwjgl_stb.so+0x11640]malloc(): corrupted top size
```

A 64×64 RGBA texture still loads normally with the guard on (`returned=buffer w=64 h=64 ch=4`).

Not covered: the palette *leak* (needs decoded pixels) and any decoder bug reachable with a sane
header.

## 5. Configuration

System properties (`-D...` on the JVM command line):

| property | default | meaning |
| --- | --- | --- |
| `m2sfix.enabled` | `true` | master switch |
| `m2sfix.policy` | `safe` | `safe` = **every** font loads without hinting (no detection needed, whole bug class gone) · `detect`/`hintless` = only `RISKY`/`SUSPICIOUS`/unparsable fonts · `block` = reject `SUSPICIOUS` faces before FreeType parses them, degrade the rest like `detect` · `off` = do nothing |
| `m2sfix.unparsable` | `hintless` | treatment of fonts the scanner cannot parse (`hintless` / `allow`) |
| `m2sfix.notify` | `true` | in-game warning dialog |
| `m2sfix.log` | `true` | one stderr line per flagged font |
| `m2sfix.maxscan` | `64` | how many MiB of a font are scanned; a bigger font is treated as unverifiable (fails closed) |
| `m2sfix.images` | `safe` | image-header guard for pack textures (`safe` / `off`) |
| `m2sfix.images.maxpixels` | `16777216` | largest accepted image, in pixels |
| `m2sfix.sha256.allow` | *(empty)* | comma-separated SHA-256 of fonts to always treat as clean |

## 6. Verification

Run on Linux, JDK 26, against LWJGL 3.4.3 — the exact library build and FreeType version Minecraft
26.3 bundles.

```
mvn test                # 99 tests (1 skipped off Linux): core scanner/policy/guard/notify/variants + agent
tools/verify-poc-pack.sh
java -cp core/target/m2sfix-core-2.2.0.jar dev.duckducktw.m2sfix.core.cli.ScanFonts /usr/share/fonts
```

- **98 tests green, 1 skipped** (the `/usr/share/fonts` corpus test, Linux only). The agent tests install the real transformer into a running JVM against stub
  classes with the exact LWJGL descriptors and assert: flagged font `flags 0 → 0x8002`, clean font keeps
  `flags 0`, the safe channel strips hinting from clean fonts too, `block` rejects the face, `off` changes nothing, null/short buffers and failed face
  creation are ignored. The notify tests build the dialog against Minecraft stand-ins and check both
  buttons, the disconnect callback, the once-per-font rule and the `m2sfix.notify=false` switch. The
  variant tests cover the hostile/benign fixture matrix above plus every font installed on the build
  machine.
- **Real proof-of-concept fonts:** the published `resource-pack.zip` (SHA-1
  `f2e2859318152e32fc331d2291c2ec40ffb3c372`) — **144 / 144 flagged** (`IDEF instruction in fpgm`).
- **False positives:** every font installed on this machine — **460 faces, 0 flagged** — plus
  **2,351 faces sampled from the Google Fonts repository (1,309 files, static and variable), 0 flagged**
  (that sample is what caught the earlier `IDEF`-any-opcode rule: the two Korean faces it flagged are
  now clean).
- **Real FreeType 2.14.3, real PoC font, real agent jar:** the guard flagged the font, the rewritten
  flags were observed (`0 → 2`), glyphs rendered, process exited cleanly. The same harness without the
  agent also completes, i.e. it does not reproduce the Windows-only ROP chain — the exploit was never
  executed on purpose.

- **Real clients (2.2.0, macOS ARM64):** Fabric 1.21.10, Forge 1.20.6 and 1.21.10, NeoForge 1.20.5,
  1.20.6, 1.21.10 and 26.3 with the mod jar; vanilla 1.21.10 and Fabric 1.21.10 with the agent. Each
  logged the hook-active lines and flagged the synthetic fixture font. Details in
  [LOADERS.md](LOADERS.md).

**Not verified:** Windows and Linux clients, the exploit itself against a protected client, clicking
the dialog buttons in a running game, and live `FT_Load_Char` calls.

## 7. Limits

- The warning dialog and `block` are signature-based (`IDEF`); a new variant may be neutralised
  without a warning. `safe` needs no signature, and `detect` keys on `SHZ` reachability, not on `IDEF`.
- On Forge / NeoForge the mod covers Minecraft's own FreeType calls only; use the agent if other mods
  call FreeType.
- The real fix is upstream: FreeType ≥ 2.15.0, i.e. the Minecraft version that picks it up.
- Live-tested on macOS/ARM only; Windows and Linux use the same Java hooks but were not run live.
