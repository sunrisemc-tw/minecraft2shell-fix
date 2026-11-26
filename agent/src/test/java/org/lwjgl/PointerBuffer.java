package org.lwjgl;

/** Minimal test-only stand-in for LWJGL's PointerBuffer. */
public final class PointerBuffer {

    private final long[] values;
    private int position;

    public PointerBuffer(long... values) {
        this.values = values.clone();
    }

    public long get(int index) {
        return values[index];
    }

    public int position() {
        return position;
    }

    public PointerBuffer position(int index) {
        position = index;
        return this;
    }
}
