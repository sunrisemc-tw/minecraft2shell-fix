# `detect` Mode Completeness for FreeType `Ins_SHZ`

## Summary

`m2sfix.policy=detect` (alias `hintless`) previously stripped hinting only when `TtfScanner` matched the published exploit's `IDEF` signature (redefining a point-zone opcode, or an `IDEF` inside a glyph program) or when a font failed to parse. Any variant reaching FreeType's `Ins_SHZ` out-of-bounds write without that `IDEF` pattern was reported `CLEAN` and kept hinting.

This change introduces a `ScanResult.Verdict.RISKY` tier so that in `detect` mode a face keeps hinting **only if its bytecode provably cannot execute `Ins_SHZ` (`0x36`/`0x37`)** (and contains no statically unknown `IDEF` or unparsable glyph structure). Combined with `FaceGuard.NO_HINTING_FLAGS = 0x8002` (`FT_LOAD_NO_HINTING | FT_LOAD_NO_AUTOHINT`), every degraded face never invokes the TrueType bytecode interpreter.

| Verdict | Meaning | `detect` / `hintless` | `block` | `safe` | Warning dialog |
| --- | --- | --- | --- | --- | --- |
| `CLEAN` | No exploit-shaped or unknown `IDEF`, provably cannot execute `SHZ`, tables & glyphs parse cleanly | Hinting kept | Allowed | Hintless (`0x8002`) | No |
| `RISKY` | Can execute `SHZ` (`0x36`/`0x37`), or uses an `IDEF` in `fpgm`/`prep` whose opcode cannot be determined statically | Hintless (`0x8002`) | Allowed, hintless (`0x8002`) | Hintless (`0x8002`) | No |
| `SUSPICIOUS` | High-confidence signature: `IDEF` in a glyph program, or `IDEF` in `fpgm`/`prep` redefining a statically known point-zone opcode | Hintless (`0x8002`) | Rejected (`FT_Err_Invalid_File_Format`) | Hintless (`0x8002`) | Yes |
| `UNPARSABLE` | Unusable sfnt / `glyf` / `loca` / mid-walk glyph structure, or exceeds `m2sfix.maxscan` | Hintless (`0x8002`, unless `m2sfix.unparsable=allow`) | Allowed, hintless (unless `allow`) | Hintless (`0x8002`) | No |

`m2sfix.sha256.allow` is checked before scanning and still overrides every verdict tier (`SUSPICIOUS`, `RISKY`, and `UNPARSABLE`).

## Why `IDEF` Alone Is Insufficient (and How SHZ Reachability Makes `detect` Independent of Hijack Strategy)

The `IDEF` signature matches one specific **post-corruption control-flow recovery trick** from the published `minecraft2shell` proof of concept: corrupting `exc->error` via the `Ins_SHZ` heap write so FreeType's `Invalid_Opcode` handler dispatches into an `IDEF` body. An `IDEF` signature fundamentally **cannot** cover exploit variants that turn the exact same `Ins_SHZ` out-of-bounds write into code execution or crash/corruption some other way — for example, overwriting an adjacent heap object, function pointer, or interpreter callback directly without ever using `IDEF`, or computing the `IDEF` opcode dynamically.

The SHZ-reachability rule makes `detect` mode **independent of how an attacker hijacks control after the OOB write**:
- Rather than trying to recognise every post-corruption payload or hijack primitive, `TtfScanner` cuts the exploit chain at the **vulnerability primitive itself** (`Ins_SHZ`, opcodes `0x36` and `0x37`).
- Any font whose bytecode can reach `Ins_SHZ` — whether or not it uses `IDEF`, regardless of how it would exploit the resulting heap corruption — is classified at least `RISKY` and loaded with `NO_HINTING_FLAGS` (`0x8002`), so FreeType never runs `fpgm`, `prep`, or any glyph program for that face.
- The high-confidence `IDEF` signature (`SUSPICIOUS`) is retained solely to decide when to show the malicious-pack warning dialog and when `block` mode rejects the face outright, preventing false-alarm dialogs on legitimate fonts that happen to use `SHZ`.

## Implemented Rule (`TtfScanner`)

For every face in an sfnt font (or every face in a `ttcf` collection):

1. Inspect `fpgm`, `prep`, and every glyph instruction stream in `glyf` (`loca`/`head`/`maxp`).
2. Decode each instruction stream linearly using the exact instruction lengths from FreeType's `opcode_length[256]` table:
   - `NPUSHB` (`0x40`): `2 + count` bytes
   - `NPUSHW` (`0x41`): `2 + 2 * count` bytes
   - `PUSHB[0..7]` (`0xB0..0xB7`): `1 + ((op & 7) + 1)` bytes
   - `PUSHW[0..7]` (`0xB8..0xBF`): `1 + 2 * ((op & 7) + 1)` bytes
   - All other opcodes: `1` byte
   - `FDEF` (`0x2C`) and `IDEF` (`0x89`) bodies are walked through linearly (not skipped), so every opcode inside defined functions/instructions is inspected.
3. Track the top-of-stack literal for `IDEF`:
   - Any push instruction (`PUSHB`, `PUSHW`, `NPUSHB`, `NPUSHW`) with `count >= 1` records its **last** pushed value (the top of stack that `Ins_IDEF` pops as `args[0]`).
   - Any non-push instruction (`ADD`, `SWAP`, `DUP`, `IF`, `FDEF`, `IDEF` itself, etc.) clears `lastPushed` to `UNKNOWN_OPCODE`, because the top of stack is no longer statically known.
4. Count linear `SHZ[0]` (`0x36`) and `SHZ[1]` (`0x37`) opcodes.
5. Per stream, if the linear decode encounters any relative jump (`JMPR` `0x1C`, `JROT` `0x78`, or `JROF` `0x79`), also count all raw `0x36`/`0x37` bytes across the entire stream `[start, end)` (covering both push payloads and `NPUSHB`/`NPUSHW` count bytes).
6. Any parse failure mid-glyph-walk (`loca` out of range or unordered, truncated glyph header, malformed simple/composite glyph) records an unparsable condition (failing closed) **and continues scanning remaining glyphs** so a later `SUSPICIOUS` or `RISKY` glyph is never missed.
7. Verdict precedence per face:
   - `SUSPICIOUS`: `IDEF` in a glyph program, or `IDEF` in `fpgm`/`prep` with a statically known point-zone opcode (`0x2E..0x3C`, `0x3E..0x3F`).
   - `RISKY`: linear `SHZ` count > 0, jump-reachable raw `SHZ` count > 0, or an `IDEF` in `fpgm`/`prep` with a statically unknown opcode.
   - `UNPARSABLE`: sfnt header, table directory, `glyf`/`loca`/`head`/`maxp`, or any mid-walk glyph failed to parse cleanly.
   - `CLEAN`: none of the above (including fonts with statically known non-point-zone `IDEF`, such as Korean custom instructions or Apple `Skia.ttf`'s `0x91`, when no `SHZ` is reachable).
8. For `ttcf` collections: precedence across faces is `SUSPICIOUS` > `RISKY` > `UNPARSABLE` > `CLEAN` (so an `UNPARSABLE` face cannot mask a `RISKY` face when `m2sfix.unparsable=allow`).

### Why Unknown-Opcode `IDEF` Gets `RISKY` (Not `SUSPICIOUS`)

When an `IDEF` in `fpgm`/`prep` does not have an immediately preceding literal push (e.g. `PUSHB 53; PUSHB 1; ADD; IDEF`, or a benign font placing `DUP`/`IF` before `IDEF`), its runtime opcode cannot be determined statically without abstract interpretation:
- **Degrading via `RISKY` is fully protective**: in `detect`, `block`, and `safe` modes, the face receives `NO_HINTING_FLAGS` (`0x8002`), so `fpgm`/`prep` and glyph bytecode never run. Moreover, any exploit trying to trigger `Ins_SHZ` still requires `SHZ`, which already puts the face in `RISKY`.
- **Avoiding `SUSPICIOUS` prevents false-alarm dialogs and false blocks**: a legitimate font computing or guarding a custom instruction opcode (outside the point-zone range) via `DUP`, `SWAP`, `RS`, or `IF` would otherwise pop a "malicious resource pack" warning dialog and fail to load in `block` mode.
- **Verified zero false positives on known benign corpora**: `clean-korean-idef.ttf` (`PUSHB 0x00..0x04, 0x93; IDEF`) and all 375 installed macOS fonts — including `/System/Library/Fonts/Supplemental/Skia.ttf`, which uses multi-value `PUSHB[2] 15, 5, 145; IDEF` (opcode `0x91`) — stay `CLEAN`.

## Completeness Audit Against FreeType `VER-2-14-1`

Verified against upstream FreeType `VER-2-14-1` (`src/truetype/ttinterp.c`, `ttobjs.c`, `ttgload.c`, `ttpload.c`, `src/sfnt/ttload.c`):

### 1. Bytecode Interpreter (`src/truetype/ttinterp.c`)
- **Single dispatch path to `Ins_SHZ`**: `Ins_SHZ` is defined at `ttinterp.c:5113-5151` (OOB contour limit at `ttinterp.c:5141`: `exc->zp2.contours[exc->zp2.n_contours - 1] + 1`). Its **only** call site is `TT_RunIns` at `ttinterp.c:6994-6996` (`case 0x36` and `case 0x37`).
- **Non-self-modifying code, exactly three code ranges**: `TT_Set_CodeRange` (`ttinterp.c:147-162`) restricts `range` to `1..3` (`tt_coderange_font` from `fpgm` at `ttobjs.c:898`, `tt_coderange_cvt` from `prep` at `ttobjs.c:981`, `tt_coderange_glyph` from `glyf` at `ttgload.c:829`). No TrueType instruction writes to `exc->code` or `exc->codeRangeTable`.
- **Instruction boundaries**: `opcode_length[256]` (`ttinterp.c:1011-1032`) gives length `1` for every opcode except `0x40` (`-1`, `2 + count`), `0x41` (`-2`, `2 + 2 * count`), `0xB0..0xB7` (`2..9`), and `0xB8..0xBF` (`3..17`). Runtime advances in `Ins_NPUSHB` (`ttinterp.c:3644-3676`), `Ins_NPUSHW` (`ttinterp.c:3686-3719`), `Ins_PUSHB` (`ttinterp.c:3729-3754`), `Ins_PUSHW` (`ttinterp.c:3764-3790`), and `TT_RunIns` (`ttinterp.c:7391`) match `opcode_length[]` exactly.
- **Control flow without relative jumps preserves linear boundaries**:
  - `Ins_IF` (`ttinterp.c:3100-3137`) and `Ins_ELSE` (`ttinterp.c:3147-3173`) skip bytecode via `SkipCode` (`ttinterp.c:3068-3090`), which uses `opcode_length[]`.
  - `Ins_FDEF` (`ttinterp.c:3268-3343`) and `Ins_IDEF` (`ttinterp.c:3558-3627`) are only permitted in `fpgm`/`prep`, record `def->start = exc->IP + 1` and `def->range = exc->curRange`, and skip to `ENDF` via `SkipCode`.
  - `Ins_CALL` (`ttinterp.c:3397-3466`), `Ins_LOOPCALL` (`ttinterp.c:3476-3548`), `Ins_UNKNOWN` (`ttinterp.c:6660-6693`), and the `Invalid_Opcode` IDEF recovery handler (`ttinterp.c:7347-7381`) transfer via `Ins_Goto_CodeRange` (`ttinterp.c:1415-1453`) to a recorded `def->start`, saving `Caller_IP = exc->IP + 1`. Because `Invalid_Opcode` is thrown only by `Ins_UNKNOWN` (`ttinterp.c:6692`) and push opcodes (`0x40`, `0x41`, `0xB0..0xBF`) never invoke `Ins_UNKNOWN`, `Caller_IP` is always a linear instruction boundary. `Ins_ENDF` (`ttinterp.c:3353-3387`) only loops to `Def->start` or returns to `Caller_IP`.
- **Relative jumps are confined to their own code range**: `Ins_JMPR` (`0x1C`, `ttinterp.c:3196-3221`), `Ins_JROT` (`0x78`, `ttinterp.c:3231-3236`), and `Ins_JROF` (`0x79`, `ttinterp.c:3246-3251`) add `args[0]` to `exc->IP` without changing `exc->curRange` or `exc->code`, and bounds checks at `ttinterp.c:3206-3212` and `7394-7403` keep execution inside `[0, exc->codeSize)`. Consequently, a stream without `JMPR`/`JROT`/`JROF` can only execute opcodes at linear boundaries, while a stream with a relative jump can reach any byte offset in `[0, codeSize)` of that same stream.

### 2. Holes Found and Closed

Auditing `TtfScanner` against FreeType `VER-2-14-1` and review findings turned up six gaps, all fixed and covered by fixture tests:

1. **Missing `SHZ[1]` (`0x37`)**: The original scanner only checked `0x36` (`SHZ[0]`), missing `0x37` (`ttinterp.c:6994-6996`). Both `0x36` and `0x37` are now detected.
2. **`NPUSHB`/`NPUSHW` count byte reachable via jump**: A relative jump in a stream can target `ip + 1` (the `count` byte of `NPUSHB`/`NPUSHW`), not just push payload bytes starting at `ip + 2`. When a stream contains a jump, every raw byte in `[start, limit)` is checked for `0x36`/`0x37`.
3. **Uninstructed composite glyphs silently aborted `scanGlyphs()`**: `compositeGlyphInstructions` did not check `WE_HAVE_INSTRUCTIONS` (`0x0100`, `ttgload.c:77, 1899`). Any composite glyph without instructions ends right after its last component (`cursor == glyphEnd`), returning `null` and triggering an early `return;` in `scanGlyphs` that skipped every subsequent glyph (a false-`CLEAN` hole). `compositeGlyphInstructions` now checks `WE_HAVE_INSTRUCTIONS` (mirroring FreeType's last-component check at `ttgload.c:1899`) and returns `InstructionRange.EMPTY` when absent.
4. **Mid-walk glyph parse failure quietly stopped `scanGlyphs()`**: Previously, any malformed glyph caused `scanGlyphs` to `return;` early and leave the verdict `CLEAN`. Any mid-walk parse failure now marks the face `UNPARSABLE` (failing closed) **and** continues scanning remaining glyphs so later `SUSPICIOUS`/`RISKY` glyphs are still detected.
5. **FreeType `loca` & composite `n_ins` discrepancies**:
   - `TT_Process_Composite_Glyph` (`ttgload.c:1214-1237`) checks `n_ins <= loader->byte_len` (whole glyph length `glyphEnd - glyphOffset`) and reads from `ins_pos` in the backing stream rather than capping at `glyphEnd - cursor`. `compositeGlyphInstructions` mirrors that exact bound.
   - `tt_face_get_location` (`ttpload.c:224-276`) clamps the last glyph's `pos2` to `glyf_len` and treats unordered `pos2 < pos1` as `glyf_len - pos1`. `scanGlyphs` mirrors both while also marking the malformed `loca` fail-closed.
   - Missing/truncated `head`/`maxp`/`loca` when `glyf` is present fails closed as `UNPARSABLE`.
6. **`IDEF` stack-top tracking bugs**:
   - Multi-value pushes (`PUSHB[1] 0x00, 0x36; IDEF`, `PUSHW`, `NPUSHB`, `NPUSHW`) previously set `lastPushed = -1`, which `Math.max(-1, 0)` turned into `0x00` — hiding `0x36` as non-point-zone (and misreporting real-world macOS `Skia.ttf`'s `PUSHB[2] 15, 5, 145; IDEF` as `0x00` instead of `0x91`). Now the **last** value pushed (top of stack) is tracked.
   - Non-push instructions (`ADD`, etc., e.g. `PUSHB 53; PUSHB 1; ADD; IDEF`) previously left `lastPushed` stale instead of marking the opcode unknown. All non-push opcodes now clear `lastPushed` to `UNKNOWN_OPCODE`, and unknown-opcode `IDEF` in `fpgm`/`prep` degrades as `RISKY`.
   - Note: `TtfScannerTest.fdefOperandIsNotAnOpcode` (`fpgm = {0x2C, 0x89}`) previously passed only by accident because `Math.max(-1, 0) == 0` hid the unknown-opcode `IDEF` after `FDEF`; it is now updated (`fdefDoesNotTreatNextByteAsInlineOperand`) to assert `RISKY`.

## Real-World Impact Measurement (macOS Installed Fonts)

Measured with `dev.duckducktw.m2sfix.core.cli.ScanFonts` and per-face `.ttc` expansion over `/System/Library/Fonts` (including `/System/Library/Fonts/Supplemental`), `/Library/Fonts`, and `~/Library/Fonts` (deduplicated) on macOS 26.6.2 (arm64):

| Metric | Before (IDEF-only `detect`) | After (SHZ-complete `detect`) |
| --- | --- | --- |
| Total font files scanned | 375 | 375 |
| `CLEAN` files | 375 (100.0%) | 324 (86.4%) |
| `RISKY` files (hintless in `detect`, no dialog, not blocked) | 0 (0.0%) | **51 (13.6%)** (20 linear `SHZ`, 30 jump-only payload `SHZ`, 1 both; 0 unknown-`IDEF`) |
| `SUSPICIOUS` files (dialog + `block`) | 0 (0.0%) | 0 (0.0%) |
| `UNPARSABLE` files | 0 (0.0%) | 0 (0.0%) |
| Total individual faces across files (expanding `.ttc`) | 792 | 792 |
| `CLEAN` faces (individual face scan) | 792 (100.0%) | 707 (89.3%) |
| `RISKY` faces (individual face scan) | 0 (0.0%) | **85 (10.7%)** (43 linear `SHZ`, 41 jump-only payload `SHZ`, 1 both) |

- `/System/Library/Fonts/Supplemental/Skia.ttf` (the sole installed macOS font containing `IDEF`) uses `PUSHB[2] 15, 5, 145; IDEF` and now scans as `CLEAN` with diagnostic `IDEF present for 0x91 (not a point-zone instruction); SHZ count=0`.
- **Collection granularity note**: `TtfScanner.scan(byte[])` inspects every face in a `.ttc` file and returns the worst verdict for the whole container (since `FaceGuard.inspectNewFace` receives the file bytes without a `face_index`). Six of the 51 `RISKY` files are mixed `.ttc` collections containing both `RISKY` and `CLEAN` faces (`Helvetica.ttc` 2/6, `LucidaGrande.ttc` 3/4, `AmericanTypewriter.ttc` 4/7, `Charter.ttc` 1/6, `Shree714.ttc` 2/4, `Times.ttc` 3/4), which adds 16 clean sibling faces if all faces are loaded from those `.ttc` containers (101 / 792 faces = 12.8% at container granularity).

### All 51 Degraded (`RISKY`) Font Files on This Mac

| File | Faces `RISKY` | Scanner reason |
| --- | --- | --- |
| `/Library/Fonts/Artifakt Element Bold Italic.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=6)` |
| `/Library/Fonts/Artifakt Element Bold.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=6)` |
| `/Library/Fonts/Artifakt Element Italic.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=6)` |
| `/Library/Fonts/Artifakt Element Regular.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=6)` |
| `/System/Library/Fonts/Geneva.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=76)` |
| `/System/Library/Fonts/Helvetica.ttc` | 2/6 | `face 0: jump-reachable SHZ byte in prep (count=56)` |
| `/System/Library/Fonts/LucidaGrande.ttc` | 3/4 | `face 0: reachable SHZ instruction in glyph 919 (count=2)` |
| `/System/Library/Fonts/Menlo.ttc` | 4/4 | `face 0: reachable SHZ instruction in glyph 614 (count=20)` |
| `/System/Library/Fonts/Monaco.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=54)` |
| `/System/Library/Fonts/Noteworthy.ttc` | 2/2 | `face 0: reachable SHZ instruction in glyph 0 (count=358)` |
| `/System/Library/Fonts/NotoSansKannada.ttc` | 9/9 | `face 0: jump-reachable SHZ byte in fpgm (count=7)` |
| `/System/Library/Fonts/Supplemental/AlBayan.ttc` | 4/4 | `face 0: reachable SHZ instruction in fpgm (count=197)` |
| `/System/Library/Fonts/Supplemental/AmericanTypewriter.ttc` | 4/7 | `face 0: reachable SHZ instruction in glyph 0 (count=442)` |
| `/System/Library/Fonts/Supplemental/AppleMyungjo.ttf` | 1/1 | `reachable SHZ instruction in fpgm (count=23)` |
| `/System/Library/Fonts/Supplemental/Arial Bold Italic.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=31)` |
| `/System/Library/Fonts/Supplemental/Arial Bold.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=3)` |
| `/System/Library/Fonts/Supplemental/Arial Italic.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=11)` |
| `/System/Library/Fonts/Supplemental/Arial Narrow Bold Italic.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=17)` |
| `/System/Library/Fonts/Supplemental/Arial Narrow Bold.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=3)` |
| `/System/Library/Fonts/Supplemental/Arial Narrow Italic.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=3)` |
| `/System/Library/Fonts/Supplemental/Arial Narrow.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=43)` |
| `/System/Library/Fonts/Supplemental/Arial.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=106)` |
| `/System/Library/Fonts/Supplemental/Ayuthaya.ttf` | 1/1 | `reachable SHZ instruction in glyph 0 (count=224)` |
| `/System/Library/Fonts/Supplemental/Baghdad.ttc` | 2/2 | `face 0: reachable SHZ instruction in glyph 0 (count=408)` |
| `/System/Library/Fonts/Supplemental/Bodoni 72 OS.ttc` | 3/3 | `face 0: reachable SHZ instruction in glyph 0 (count=486)` |
| `/System/Library/Fonts/Supplemental/Bodoni 72 Smallcaps Book.ttf` | 1/1 | `reachable SHZ instruction in glyph 0 (count=486)` |
| `/System/Library/Fonts/Supplemental/Bodoni 72.ttc` | 3/3 | `face 0: reachable SHZ instruction in glyph 0 (count=486)` |
| `/System/Library/Fonts/Supplemental/Bradley Hand Bold.ttf` | 1/1 | `reachable SHZ instruction in glyph 0 (count=362)` |
| `/System/Library/Fonts/Supplemental/Charter.ttc` | 1/6 | `face 5: jump-reachable SHZ byte in fpgm (count=1)` |
| `/System/Library/Fonts/Supplemental/Courier New Bold Italic.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=9)` |
| `/System/Library/Fonts/Supplemental/Courier New Bold.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=54)` |
| `/System/Library/Fonts/Supplemental/Courier New Italic.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=19)` |
| `/System/Library/Fonts/Supplemental/Courier New.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=125)` |
| `/System/Library/Fonts/Supplemental/Diwan Thuluth.ttf` | 1/1 | `reachable SHZ instruction in glyph 0 (count=1974)` |
| `/System/Library/Fonts/Supplemental/Impact.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=19)` |
| `/System/Library/Fonts/Supplemental/InaiMathi-MN.ttc` | 2/2 | `face 0: reachable SHZ instruction in glyph 0 (count=104)` |
| `/System/Library/Fonts/Supplemental/Krungthep.ttf` | 1/1 | `reachable SHZ instruction in glyph 0 (count=224)` |
| `/System/Library/Fonts/Supplemental/Mishafi.ttf` | 1/1 | `reachable SHZ instruction in glyph 0 (count=2418)` |
| `/System/Library/Fonts/Supplemental/Mshtakan.ttc` | 4/4 | `face 0: reachable SHZ instruction in glyph 0 (count=324)` |
| `/System/Library/Fonts/Supplemental/Shree714.ttc` | 2/4 | `face 0: reachable SHZ instruction in fpgm (count=3)` |
| `/System/Library/Fonts/Supplemental/Silom.ttf` | 1/1 | `reachable SHZ instruction in glyph 0 (count=218)` |
| `/System/Library/Fonts/Supplemental/Times New Roman Bold Italic.ttf` | 1/1 | `reachable SHZ in fpgm (linear=2, via-jump=1)` |
| `/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=57)` |
| `/System/Library/Fonts/Supplemental/Times New Roman Italic.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=9)` |
| `/System/Library/Fonts/Supplemental/Times New Roman.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=213)` |
| `/System/Library/Fonts/Supplemental/Waseem.ttc` | 2/2 | `face 0: reachable SHZ instruction in glyph 0 (count=916)` |
| `/System/Library/Fonts/Supplemental/Webdings.ttf` | 1/1 | `jump-reachable SHZ byte in prep (count=3)` |
| `/System/Library/Fonts/Supplemental/Wingdings 2.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=3)` |
| `/System/Library/Fonts/Supplemental/Wingdings 3.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=2)` |
| `/System/Library/Fonts/Supplemental/Wingdings.ttf` | 1/1 | `jump-reachable SHZ byte in fpgm (count=6)` |
| `/System/Library/Fonts/Times.ttc` | 3/4 | `face 0: jump-reachable SHZ byte in glyph 34 (count=111)` |

## Verification

- `mvn -B clean package` (after merging `main` with `NO_HINTING_FLAGS = 0x8002`): **95 tests total** (85 in `core`, with 1 skipped because `/usr/share/fonts` does not exist on macOS; 10 in `agent`), **0 failures, 0 errors**.
- Added 12 new binary fixtures via `tools/make_fixture_fonts.py` (`no-shz-clean.ttf`, `shz-push-payload-only.ttf`, `shz-in-glyph.ttf`, `shz1-in-glyph.ttf`, `shz-payload-with-jmpr.ttf`, `shz-in-fpgm.ttf`, `shz-after-uninstructed-composite.ttf`, `malicious-idef-multipush.ttf`, `clean-idef-multipush.ttf`, `risky-idef-computed.ttf`, `malformed-mid-glyph.ttf`, `malformed-glyph-before-shz.ttf`) and updated `clean.ttf`, `clean-hinting-heavy.ttf`, and `mixed-collection.ttc`.
