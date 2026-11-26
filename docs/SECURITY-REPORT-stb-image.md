# Security report — `stb_image` integer overflow reachable from a Minecraft resource pack

**Status:** draft for private disclosure to Mojang. **Not for publication.** No exploit code, no
weaponised artifact and no PoC pack is included or linked here.

**Affected:** the `stb_image` copy vendored inside LWJGL, as shipped by Minecraft. Confirmed on the
natives that 26.3 delivers (`lwjgl-stb:3.4.3`); 1.20.5–1.21.10 ship `3.3.3`, which carries the same
code.

**Independent prior research:** Primitive One, "Reading Minecraft's memory through a resource pack"
(<https://primitiveone.com/blog/minecraft-resource-pack-memory>). They demonstrated a crash and a
memory disclosure and rated it 7.1 High (8.2 if the pack is already trusted). This document confirms
their crash locally, adds the byte-level primitives, and answers the question they deliberately left
open: whether it can be escalated.

---

## 1. Summary

A resource pack can contain PNG textures. Minecraft decodes them with `stb_image` through
`lwjgl-stb`. In the vendored copy, `stbi__convert_format16()` allocates with

```c
good = (stbi__uint16 *) stbi__malloc(req_comp * x * y * 2);   /* 32-bit multiply */
```

while its 8-bit sibling uses `stbi__malloc_mad4()` and checks for overflow. When
`req_comp * x * y * 2` wraps 2³², a ~190 KiB buffer is allocated and the conversion loop then writes
`req_comp * x * y * 2` bytes into it.

Consequences, in the order they were verified:

| property | verified how |
| --- | --- |
| Remote, no user interaction beyond accepting the pack | stock client, server-sent pack |
| Deterministic crash of the official client | reproduced on the shipped `liblwjgl_stb.so` |
| Attacker-controlled content in the write | measured: `42 41 42 41 42 41 ff ff` repeating = our pixel value ×3 + fixed alpha |
| Native memory disclosure (ASLR-relevant) | Primitive One's report; not re-verified here |
| **RCE** | **not achieved — and §5 argues it is not reachable through this primitive** |

## 2. Root cause, precisely

`stb_image.h`, `stbi__convert_format16()`:

```c
good = (stbi__uint16 *) stbi__malloc(req_comp * x * y * 2);   /* 32-bit arithmetic, no check */
...
for (j = 0; j < (int) y; ++j) {
    stbi__uint16 *src  = data + j * x * img_n;
    stbi__uint16 *dest = good + j * x * req_comp;
    switch (STBI__COMBO(img_n, req_comp)) {
        STBI__CASE(1,4) { dest[0]=dest[1]=dest[2]=src[0]; dest[3]=0xffff; } break;
        ...
```

Two properties matter:

1. The multiplication that decides the allocation size is 32-bit and unchecked.
2. The loop that fills it is driven by the *declared* dimensions, so the number of bytes it writes is
   the true (un-wrapped) product.

Upstream `nothings/stb` has since changed this call to `stbi__malloc_mad4(...)` (see issues #1932,
#1935, #1936). The LWJGL copy has not been refreshed, and LWJGL 3.4.3 is the newest release, so no
"just bump LWJGL" fix exists for Minecraft.

## 3. Reproduction (summary only)

Crafting is trivial: a 16-bit greyscale PNG declaring 23,171 × 23,171 pixels (`req_comp` 1 → 4 at the
call site) makes `4 · 23171 · 23171 · 2` = 4,295,161,928 wrap to 194,632 bytes. The file itself is a
few hundred kilobytes of highly compressible scanlines.

Against the natives Minecraft ships, `STBImage.stbi_load_from_memory(..., 4)` on that file:

```
SIGSEGV … C  [liblwjgl_stb.so+0x1165c]malloc(): corrupted top size
```

The identical file with a header-checking guard installed returns `NULL` and the process survives,
which isolates the decoder as the failing component.

## 4. What the primitive can actually do

Measured with a harness that places guard pages around the vulnerable allocation so the write stops at
a known boundary (local experiment; not included):

```
buffer …af000 .. …df000 (194,632 bytes requested), guard at …df000
stopped at guard: YES
bytes written before the fault: 196,608 (192.0 KiB; buffer was 196,608 bytes)
last 32 bytes written: 42 41 42 41 42 41 ff ff 42 41 42 41 42 41 ff ff …
bytes the loop still had to write: 4.00 GiB
```

Reading that:

- The write is **linear and starts at the beginning of the 192 KiB buffer**, filling it and a full 4 KiB
  beyond before the guard is hit — i.e. against the real allocator it walks into whatever follows.
- The content is **attacker-chosen**: three 16-bit samples from the pixel data plus a fixed
  `0xffff` alpha, repeating every 8 bytes.
- The loop **still had 4 GiB to write**. That number is not incidental: the wrap only happens when the
  true size is ≥ 2³², so *every* triggering image writes at least 4 GiB.

## 5. Why this does not become RCE

An exploit needs the corrupted memory to be *consumed* by code that then runs. Here:

1. **The loop cannot be shortened.** Triggering the bug requires the true write size ≥ 2³² bytes; there
   is no dimension pair where the allocation wraps but the write is small.
2. **The write cannot complete.** Completing it needs 4 GiB of contiguous, writable, mapped memory
   directly after a ~190 KiB allocation. No practical process layout provides that; the write faults at
   the first unmapped page.
3. **Nothing runs between the writes.** The conversion loop is a tight copy with no callbacks, so a
   corrupted object cannot be used before the fault. The process dies inside the same loop, which is
   what both Primitive One and this work observed.

So the reachable outcome is: remote, deterministic crash, plus corruption of whatever the first mapped
pages after the buffer hold — with the process terminating before that corruption can be acted upon.
That is a denial of service, not code execution. We looked for an escalation and did not find one; the
same conclusion the original researchers reached when they declined to claim it.

For completeness: the *disclosure* primitive (indexed PNG with a short palette, uninitialised stack
copied into the texture, exfiltrated through a pack-supplied shader by timing) is separate, read-only,
and does yield ASLR-relevant pointers. That one is worth fixing on its own merits.

## 6. Recommended fixes

**Upstream / LWJGL (root fix).** Take the `stbi__malloc_mad4()` change in `stbi__convert_format16`
already present in `nothings/stb` master. Until LWJGL ships a release containing it, Minecraft needs
its own rebuild of the native — the same route already used for FreeType.

**Mojang (immediate, cheap).** Validate declared image geometry before the decoder is reached:

- reject `width`/`height` of 0 or above 2²⁴, and any image above a sane pixel budget
  (vanilla's largest textures are orders of magnitude below 16 Mpx);
- reject 16-bit images whose `req_comp · w · h · 2` exceeds a byte budget, computing in 64-bit;
- for indexed PNGs, reject a palette shorter than 256 entries, or decode with a bound index check.

Our own mitigation (`minecraft2shell-fix` 2.3.0, MIT) does exactly this in front of
`STBImage.stbi_load_from_memory` and can serve as a reference implementation.

## 7. Severity

- Remote DoS of the official client: **high** — trivial to trigger, no privileges needed.
- Information disclosure (ASLR-relevant pointers, server-readable timing channel): **high** — it is the
  half that turns other bugs into exploits.
- Code execution through this primitive: **not demonstrated, and §5 argues it is unreachable**.

Suggested classification: CWE-190 (integer overflow) → CWE-787 (out-of-bounds write), with the impact
capped at DoS + information disclosure rather than RCE.

## 8. What is deliberately not in this document

No crafted PNG, no harness, no offsets, no gadget discussion. We will share the artifact with Mojang
on request through a private channel and will not publish it, per the same terms the original
researchers set.
