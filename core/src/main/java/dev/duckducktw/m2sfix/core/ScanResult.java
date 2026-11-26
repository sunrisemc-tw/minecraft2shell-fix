package dev.duckducktw.m2sfix.core;

/**
 * Result of a defensive TrueType font scan.
 *
 * @param verdict what the scanner concluded
 * @param reason  a short human-readable explanation, safe to log
 */
public record ScanResult(Verdict verdict, String reason) {

    public enum Verdict {
        /** No exploit-shaped IDEF and bytecode provably cannot execute SHZ. */
        CLEAN,
        /** Bytecode can execute SHZ (0x36/0x37) or uses a statically unknown IDEF opcode. */
        RISKY,
        /** An exploit-shaped IDEF instruction (high-confidence signature) was found. */
        SUSPICIOUS,
        /** The input is not a font structure we can fully inspect. */
        UNPARSABLE
    }

    public ScanResult {
        if (verdict == null) {
            verdict = Verdict.UNPARSABLE;
        }
        if (reason == null || reason.isBlank()) {
            reason = verdict == Verdict.CLEAN ? "no IDEF or reachable SHZ" : verdict.name().toLowerCase();
        }
    }

    public static ScanResult clean() {
        return new ScanResult(Verdict.CLEAN, "no IDEF instruction; SHZ count=0");
    }
}
