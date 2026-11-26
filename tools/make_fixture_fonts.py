#!/usr/bin/env python3
"""Generate the binary TrueType fixtures used by the core unit tests.

Run with the fontTools virtualenv, from any directory:

    /home/user/.venvs/fonttools/bin/python tools/make_fixture_fonts.py

The generated fonts are tiny, valid sfnt files.  They are intentionally
committed so that `mvn test` does not need Python or network access.

Fixtures:
  clean.ttf                valid fpgm/prep, no IDEF, no SHZ
  clean-hinting-heavy.ttf  FDEF + SHPIX + DELTAP2 + WS in composite and simple glyphs, no IDEF/SHZ
  clean-korean-idef.ttf    legit custom instructions (IDEF 0x00-0x04, 0x93), like KoPub/Nanum
  clean-idef-multipush.ttf legit multi-value PUSHB[2] 15,5,0x91; IDEF (macOS Skia shape, CLEAN)
  malicious-idef-multipush.ttf PUSHB[1] 0x00,0x36; IDEF (top-of-stack is 0x36, must be SUSPICIOUS)
  risky-idef-computed.ttf  PUSHB 53; PUSHB 1; ADD; IDEF (statically unknown opcode, must be RISKY)
  malformed-mid-glyph.ttf  malformed simple glyph mid-walk (must fail closed as UNPARSABLE)
  malformed-glyph-before-shz.ttf malformed glyph 2 followed by SHZ in glyph 3 (must be RISKY)
  no-shz-clean.ttf         hinted font with JMPR and no SHZ bytes anywhere (must be CLEAN)
  shz-push-payload-only.ttf 0x36/0x37 only inside push payloads, no jump (must be CLEAN)
  shz-in-glyph.ttf         SHZ (0x36) in glyph program without IDEF (must be RISKY)
  shz1-in-glyph.ttf        SHZ[1] (0x37) in composite glyph without IDEF (must be RISKY)
  shz-payload-with-jmpr.ttf 0x36 inside a push payload plus JMPR in the same stream (must be RISKY)
  shz-in-fpgm.ttf          SHZ only inside an FDEF in fpgm, called from glyph via CALL (must be RISKY)
  shz-after-uninstructed-composite.ttf uninstructed composite followed by glyph with SHZ (must be RISKY)
  malicious-idef-shpix.ttf IDEF redefines SHPIX (0x38) — a variant target, must be flagged
  pushb-decoy.ttf          0x89 hidden in PUSHB / NPUSHB / NPUSHW payloads
  malicious-idef.ttf       IDEF (0x89) in fpgm
  malicious-idef-prep.ttf  IDEF only in prep
  malicious-idef-decoyed.ttf  0x89 in a push payload *and* a real IDEF after it
  malicious-idef-longloca.ttf IDEF in fpgm with a 32-bit loca table
  malicious-small-stack.ttf   IDEF in fpgm with a 1-glyph font (maxp edge case)
  nested-composite.ttf     IDEF only in a composite glyph's instruction stream
  simple-glyph-idef.ttf    IDEF only in a simple glyph's instruction stream
  mixed-collection.ttc     two faces: clean face first, malicious face second
  truncated.ttf            first 120 bytes of malicious-idef.ttf (must be UNPARSABLE)
"""

from __future__ import annotations

from array import array
from pathlib import Path

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import TTFont, newTable
from fontTools.ttLib.tables._g_l_y_f import Glyph, GlyphComponent
from fontTools.ttLib.tables.ttProgram import Program

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "core" / "src" / "test" / "resources" / "fonts"


def _program(bytecode: bytes) -> Program:
    program = Program()
    program.fromBytecode(bytes(bytecode))
    return program


def _base_font(composite_b: bool, extra_glyph_c: bool = False) -> tuple[FontBuilder, dict[str, Glyph]]:
    builder = FontBuilder(1000, isTTF=True)
    glyph_order = [".notdef", "space", "A", "B"] + (["C"] if extra_glyph_c else [])
    cmap = {0x20: "space", 0x41: "A", 0x42: "B"}
    if extra_glyph_c:
        cmap[0x43] = "C"
    builder.setupGlyphOrder(glyph_order)
    builder.setupCharacterMap(cmap)

    pen = TTGlyphPen(None)
    pen.moveTo((100, 0))
    pen.lineTo((500, 700))
    pen.lineTo((900, 0))
    pen.closePath()
    glyph_a = pen.glyph()

    if composite_b:
        glyph_b = Glyph()
        glyph_b.numberOfContours = -1
        component = GlyphComponent()
        component.glyphName = "A"
        component.x = 0
        component.y = 0
        component.flags = 0x0004  # ARGS_ARE_XY_VALUES
        glyph_b.components = [component]
    else:
        glyph_b = TTGlyphPen(None).glyph()

    glyphs: dict[str, Glyph] = {
        ".notdef": TTGlyphPen(None).glyph(),
        "space": TTGlyphPen(None).glyph(),
        "A": glyph_a,
        "B": glyph_b,
    }
    if extra_glyph_c:
        pen_c = TTGlyphPen(None)
        pen_c.moveTo((100, 0))
        pen_c.lineTo((500, 700))
        pen_c.lineTo((900, 0))
        pen_c.closePath()
        glyphs["C"] = pen_c.glyph()
    return builder, glyphs


def build_font(
    path: Path,
    *,
    fpgm: bytes = b"",
    prep: bytes = b"",
    glyph_programs: dict[str, bytes] | None = None,
    composite_b: bool = False,
    extra_glyph_c: bool = False,
    force_long_loca: bool = False,
    max_stack_elements: int | None = None,
) -> None:
    builder, glyphs = _base_font(composite_b, extra_glyph_c=extra_glyph_c)
    for name, code in (glyph_programs or {}).items():
        glyphs[name].program = _program(code)

    builder.setupGlyf(glyphs)
    metrics = {".notdef": (500, 0), "space": (500, 0), "A": (1000, 0), "B": (1000, 0)}
    if extra_glyph_c:
        metrics["C"] = (1000, 0)
    builder.setupHorizontalMetrics(metrics)
    builder.setupHorizontalHeader(ascent=800, descent=-200)
    builder.setupNameTable(
        {
            "familyName": "M2SFix Fixture",
            "styleName": "Regular",
            "uniqueFontIdentifier": "M2SFix Fixture Regular 1.0",
            "fullName": "M2SFix Fixture Regular",
            "psName": "M2SFixFixture-Regular",
            "version": "Version 1.0",
        }
    )
    builder.setupOS2()
    builder.setupPost()
    builder.setupMaxp()

    if force_long_loca:
        builder.font["head"].indexToLocFormat = 1
    if max_stack_elements is not None:
        builder.font["maxp"].maxStackElements = max_stack_elements

    for tag, code in (("fpgm", fpgm), ("prep", prep)):
        table = newTable(tag)
        table.program = _program(code)
        builder.font[tag] = table

    cvt = newTable("cvt ")
    cvt.values = array("h", [0, 1, 2, 3])
    builder.font["cvt "] = cvt

    # Make the checked-in binaries byte-for-byte reproducible.
    builder.font["head"].created = 2082844800  # 1970-01-01, font epoch
    builder.font["head"].modified = 2082844800
    builder.font.recalcTimestamp = False

    path.parent.mkdir(parents=True, exist_ok=True)
    builder.save(path)


def _build_malformed_glyph_fixture(path: Path, glyph_b_program: bytes | None) -> None:
    """Build a font where glyph 2 ('A') has an instructionLength exceeding its glyph bounds.

    This exercises mid-walk glyph parse failure: the scanner must fail closed (never silently
    return CLEAN) and must keep scanning later glyphs so a subsequent SHZ/IDEF is still caught.
    """
    import struct

    build_font(
        path,
        fpgm=b"\xb0\x01",
        glyph_programs={"A": b"\x18", **({"B": glyph_b_program} if glyph_b_program else {})},
        composite_b=glyph_b_program is not None,
    )
    raw = bytearray(path.read_bytes())
    num_tables = struct.unpack_from(">H", raw, 4)[0]
    tables: dict[bytes, tuple[int, int]] = {}
    for i in range(num_tables):
        rec = 12 + i * 16
        tag = bytes(raw[rec : rec + 4])
        off, length = struct.unpack_from(">II", raw, rec + 8)
        tables[tag] = (off, length)
    head_off, _ = tables[b"head"]
    loca_off, _ = tables[b"loca"]
    glyf_off, _ = tables[b"glyf"]
    loc_fmt = struct.unpack_from(">h", raw, head_off + 50)[0]
    if loc_fmt == 0:
        a_start = struct.unpack_from(">H", raw, loca_off + 2 * 2)[0] * 2
    else:
        a_start = struct.unpack_from(">I", raw, loca_off + 2 * 4)[0]
    glyph_a_off = glyf_off + a_start
    n_contours = struct.unpack_from(">h", raw, glyph_a_off)[0]
    ins_len_off = glyph_a_off + 10 + n_contours * 2
    # Corrupt instructionLength to 0x7FFF so cursor + length > glyphEnd.
    struct.pack_into(">H", raw, ins_len_off, 0x7FFF)
    path.write_bytes(bytes(raw))


def _build_collection() -> None:
    """Two faces in one .ttc: the clean face first, the malicious one second.

    A scanner that only looks at face 0 of a collection would miss this.
    """
    from fontTools.ttLib import TTCollection

    clean_path = OUT_DIR / "clean.ttf"
    malicious_path = OUT_DIR / "malicious-idef.ttf"
    if not clean_path.exists():
        build_font(clean_path, fpgm=b"\xb0\x01", prep=b"\x18")
    if not malicious_path.exists():
        build_font(malicious_path, fpgm=b"\xb0\x36\x89")

    collection = TTCollection()
    collection.fonts = [
        TTFont(str(clean_path), lazy=False),
        TTFont(str(malicious_path), lazy=False),
    ]
    # Give the two faces distinguishable names so the file is not obviously
    # two copies of the same font.
    for index, font in enumerate(collection.fonts):
        name = font["name"]
        name.setName(f"M2SFix Collection Face {index}", 1, 3, 1, 0x409)
        name.setName(f"M2SFix Collection Face {index}", 4, 3, 1, 0x409)
        name.setName(f"M2SFixCollection-Face{index}", 6, 3, 1, 0x409)
    collection.save(str(OUT_DIR / "mixed-collection.ttc"))


def main() -> None:
    build_font(
        OUT_DIR / "clean.ttf",
        fpgm=b"\xb0\x01",  # PUSHB[0] with one harmless payload byte
        prep=b"\x18",      # RTG, harmless 1-byte hinting op, no SHZ
    )

    build_font(
        OUT_DIR / "malicious-idef.ttf",
        # PUSHB 54 (0x36 = SHZ), IDEF -> the exact shape of the published exploit
        fpgm=b"\xb0\x36\x89",
    )

    build_font(
        OUT_DIR / "pushb-decoy.ttf",
        # PUSHB[7] takes 8 payload bytes; 0x89 sits inside that payload.
        fpgm=b"\xb7\x01\x02\x03\x04\x05\x89\x00\x06",
        # NPUSHB (2 bytes) and NPUSHW (1 little-endian word) also contain 0x89.
        prep=b"\x40\x02\x89\x00\x41\x01\x00\x89",
    )

    build_font(
        OUT_DIR / "nested-composite.ttf",
        glyph_programs={"B": b"\xb0\x36\x89"},
        composite_b=True,
    )

    build_font(
        OUT_DIR / "simple-glyph-idef.ttf",
        glyph_programs={"A": b"\xb0\x36\x89"},
    )

    # --- variants that must still be flagged ---------------------------------
    build_font(
        OUT_DIR / "malicious-idef-prep.ttf",
        prep=b"\xb0\x36\x89",
    )

    build_font(
        OUT_DIR / "malicious-idef-decoyed.ttf",
        # PUSHB[3] swallows four payload bytes (0x89 inside), then a real PUSHB 54; IDEF follows.
        fpgm=b"\xb3\x89\x00\x11\x22\xb0\x36\x89",
    )

    build_font(
        OUT_DIR / "malicious-idef-longloca.ttf",
        fpgm=b"\xb0\x36\x89",
        glyph_programs={"A": b"\xb0\x36\x89"},
        force_long_loca=True,
    )

    build_font(
        OUT_DIR / "malicious-small-stack.ttf",
        fpgm=b"\xb0\x36\x89",
        max_stack_elements=1,
    )

    # Legitimate custom instruction definitions, as real Korean Hanja fonts ship them.
    build_font(
        OUT_DIR / "clean-korean-idef.ttf",
        fpgm=(
            b"\xb0\x00\x89\xb0\x01\x89\xb0\x02\x89"
            b"\xb0\x03\x89\xb0\x04\x89\xb0\x93\x89"
        ),
    )

    # A different point-zone opcode than the published PoC, to keep the net wide.
    build_font(
        OUT_DIR / "malicious-idef-shpix.ttf",
        fpgm=b"\xb0\x38\x89",
    )

    # --- a legitimate font that uses plenty of hinting, no IDEF and no SHZ ---
    build_font(
        OUT_DIR / "clean-hinting-heavy.ttf",
        # FDEF defining function 3, then SHPIX/DELTAP2/WS usage; no IDEF or SHZ anywhere.
        fpgm=b"\xb0\x03\x2c\xb0\x01\x2d",
        glyph_programs={
            "A": b"\xb0\x01\x38",
            "B": b"\xb0\x01\x38\xb0\x02\x71\xb0\x00\xb0\x01\x42",
        },
        composite_b=True,
    )

    # --- SHZ reachability coverage (both directions) -------------------------
    # No SHZ bytes anywhere, even with a JMPR in fpgm -> CLEAN.
    build_font(
        OUT_DIR / "no-shz-clean.ttf",
        fpgm=b"\xb0\x01\x1c\x18",  # PUSHB[0] 1; JMPR; RTG
        prep=b"\xb0\x02\x18",
        glyph_programs={"A": b"\xb0\x01\x38"},
    )

    # 0x36/0x37 appear ONLY inside push payloads with no jump in those streams -> CLEAN.
    build_font(
        OUT_DIR / "shz-push-payload-only.ttf",
        fpgm=b"\xb1\x36\x37",                        # PUSHB[1] 0x36, 0x37
        prep=b"\x40\x02\x36\x37\x41\x01\x36\x37",    # NPUSHB(2: 0x36,0x37); NPUSHW(1: 0x3637)
        glyph_programs={"A": b"\xb8\x36\x37"},       # PUSHW[0] 0x3637
    )

    # SHZ[0] (0x36) in a glyph program without IDEF -> RISKY (degraded in detect).
    build_font(
        OUT_DIR / "shz-in-glyph.ttf",
        fpgm=b"\xb0\x01",
        glyph_programs={"A": b"\xb0\x01\x36"},
    )

    # SHZ[1] (0x37) in a composite glyph program without IDEF -> RISKY.
    build_font(
        OUT_DIR / "shz1-in-glyph.ttf",
        fpgm=b"\xb0\x01",
        glyph_programs={"B": b"\xb0\x01\x37"},
        composite_b=True,
    )

    # 0x36 inside a PUSHB payload plus JMPR in the same stream -> RISKY.
    build_font(
        OUT_DIR / "shz-payload-with-jmpr.ttf",
        # PUSHB[0] 2; JMPR; PUSHB[1] 0x36, 0x00 (jump can land on 0x36 inside payload)
        fpgm=b"\xb0\x02\x1c\xb1\x36\x00",
    )

    # SHZ only inside an FDEF in fpgm (reachable via CALL from glyph) -> RISKY.
    build_font(
        OUT_DIR / "shz-in-fpgm.ttf",
        fpgm=b"\xb0\x00\x2c\xb0\x01\x36\x2d",  # PUSHB 0; FDEF; PUSHB 1; SHZ[0]; ENDF
        glyph_programs={"A": b"\xb0\x00\x2b"}, # PUSHB 0; CALL
    )

    # Uninstructed composite glyph B followed by glyph C containing SHZ -> RISKY.
    build_font(
        OUT_DIR / "shz-after-uninstructed-composite.ttf",
        fpgm=b"\xb0\x01",
        glyph_programs={"C": b"\xb0\x01\x36"},
        composite_b=True,
        extra_glyph_c=True,
    )

    # --- IDEF stack-top and mid-walk malformed glyph coverage ----------------
    # Multi-value push whose last (top-of-stack) byte is 0x36 (SHZ) -> SUSPICIOUS.
    build_font(
        OUT_DIR / "malicious-idef-multipush.ttf",
        fpgm=b"\xb1\x00\x36\x89",  # PUSHB[1] 0x00, 0x36; IDEF
    )

    # Legitimate multi-value push whose last byte is 0x91 (matches macOS Skia.ttf) -> CLEAN.
    build_font(
        OUT_DIR / "clean-idef-multipush.ttf",
        fpgm=b"\xb2\x0f\x05\x91\x89",  # PUSHB[2] 15, 5, 0x91; IDEF
    )

    # Computed IDEF opcode (53 + 1 = 54 at runtime, statically unknown) -> RISKY (degraded).
    build_font(
        OUT_DIR / "risky-idef-computed.ttf",
        fpgm=b"\xb0\x35\xb0\x01\x60\x89",  # PUSHB 53; PUSHB 1; ADD; IDEF
    )

    # Mid-walk malformed simple glyph (instructionLength exceeds glyph end) -> fails closed.
    _build_malformed_glyph_fixture(
        OUT_DIR / "malformed-mid-glyph.ttf",
        glyph_b_program=None,
    )

    # Mid-walk malformed glyph 2 followed by glyph 3 with SHZ -> scan continues, catches RISKY.
    _build_malformed_glyph_fixture(
        OUT_DIR / "malformed-glyph-before-shz.ttf",
        glyph_b_program=b"\xb0\x01\x36",
    )

    # --- edge-case containers ------------------------------------------------
    _build_collection()

    truncated = (OUT_DIR / "malicious-idef.ttf").read_bytes()[:120]
    (OUT_DIR / "truncated.ttf").write_bytes(truncated)

    for path in sorted(OUT_DIR.glob("*")):
        if path.suffix in {".ttf", ".ttc"}:
            print(f"wrote {path.relative_to(REPO_ROOT)} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
