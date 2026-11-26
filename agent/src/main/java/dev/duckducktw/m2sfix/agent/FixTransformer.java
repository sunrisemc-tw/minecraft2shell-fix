package dev.duckducktw.m2sfix.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Adds a face check and load flag adjustments to {@code org.lwjgl.util.freetype.FreeType}.
 *
 * <pre>
 * FT_Load_Glyph and FT_Load_Char:
 *     flags = AgentBridge.adjustFlags(face, flags); // entry
 *
 * FT_New_Memory_Face(library, file, faceIndex, aface):
 *     return the guard's error when it rejects the font before the native call;
 *     otherwise call AgentBridge.afterNewFace(file, aface, result) before returning.
 * </pre>
 *
 */
public final class FixTransformer implements ClassFileTransformer {

    static final String TARGET_INTERNAL_NAME = "org/lwjgl/util/freetype/FreeType";
    public static final String TARGET_BINARY_NAME = "org.lwjgl.util.freetype.FreeType";

    /** Second target: the image decoder that resource-pack PNGs go through. */
    static final String STB_INTERNAL_NAME = "org/lwjgl/stb/STBImage";
    public static final String STB_BINARY_NAME = "org.lwjgl.stb.STBImage";
    private static final String STBI_LOAD_MEMORY_DESC =
            "(Ljava/nio/ByteBuffer;Ljava/nio/IntBuffer;Ljava/nio/IntBuffer;Ljava/nio/IntBuffer;I)"
            + "Ljava/nio/ByteBuffer;";

    private static final String BRIDGE_INTERNAL_NAME = "dev/duckducktw/m2sfix/agent/AgentBridge";

    private static final String NEW_FACE_NAME = "FT_New_Memory_Face";
    private static final String NEW_FACE_DESC =
            "(JLjava/nio/ByteBuffer;JLorg/lwjgl/PointerBuffer;)I";
    private static final String LOAD_GLYPH_NAME = "FT_Load_Glyph";
    private static final String LOAD_GLYPH_DESC = "(Lorg/lwjgl/util/freetype/FT_Face;II)I";
    private static final String LOAD_CHAR_DESC = "(Lorg/lwjgl/util/freetype/FT_Face;JI)I";

    /** A free slot above the parameters of {@code FT_New_Memory_Face} (locals 0..5 are used). */
    private static final int NEW_FACE_TEMP_LOCAL = 6;

    @Override
    public byte[] transform(
            ClassLoader loader,
            String className,
            Class<?> classBeingRedefined,
            ProtectionDomain protectionDomain,
            byte[] classfileBuffer) {
        boolean fonts = TARGET_INTERNAL_NAME.equals(className);
        boolean images = STB_INTERNAL_NAME.equals(className);
        if (!fonts && !images) {
            return null;
        }
        try {
            ClassReader reader = new ClassReader(classfileBuffer);
            ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
            if (fonts) {
                reader.accept(new PatchingVisitor(writer), 0);
            } else {
                reader.accept(new StbVisitor(writer), 0);
            }
            return writer.toByteArray();
        } catch (Throwable failure) {
            System.err.println("[m2sfix] Could not install guard in " + loader + ": " + failure);
            return null;
        }
    }

    private static final class PatchingVisitor extends ClassVisitor {

        PatchingVisitor(ClassVisitor delegate) {
            super(Opcodes.ASM9, delegate);
        }

        @Override
        public MethodVisitor visitMethod(
                int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (NEW_FACE_NAME.equals(name) && NEW_FACE_DESC.equals(descriptor)) {
                return new NewFaceVisitor(delegate);
            }
            if (LOAD_GLYPH_NAME.equals(name) && LOAD_GLYPH_DESC.equals(descriptor)) {
                return new LoadFlagsVisitor(delegate, "adjustFlags", 2);
            }
            if ("FT_Load_Char".equals(name) && LOAD_CHAR_DESC.equals(descriptor)) {
                return new LoadFlagsVisitor(delegate, "adjustCharFlags", 3);
            }
            return delegate;
        }
    }

    /** Only the memory-loading entry point; file-based loads never see pack bytes. */
    private static final class StbVisitor extends ClassVisitor {

        StbVisitor(ClassVisitor delegate) {
            super(Opcodes.ASM9, delegate);
        }

        @Override
        public MethodVisitor visitMethod(
                int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
            if ("stbi_load_from_memory".equals(name) && STBI_LOAD_MEMORY_DESC.equals(descriptor)) {
                return new ScreenImageVisitor(delegate);
            }
            return delegate;
        }
    }

    /**
     * Inserts {@code image = AgentBridge.screenImage(image)} at method entry. Straight-line code, so
     * {@code COMPUTE_MAXS} is enough and no stack-map frame has to be invented.
     */
    private static final class ScreenImageVisitor extends MethodVisitor {

        ScreenImageVisitor(MethodVisitor delegate) {
            super(Opcodes.ASM9, delegate);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            super.visitVarInsn(Opcodes.ALOAD, 0);
            super.visitMethodInsn(Opcodes.INVOKESTATIC, BRIDGE_INTERNAL_NAME, "screenImage",
                    "(Ljava/nio/ByteBuffer;)Ljava/nio/ByteBuffer;", false);
            super.visitVarInsn(Opcodes.ASTORE, 0);
        }
    }

    /** Inserts {@code flags = AgentBridge.adjustFlags(face, flags)} at method entry. */
    private static final class LoadFlagsVisitor extends MethodVisitor {

        private final String hook;
        private final int flagsSlot;

        LoadFlagsVisitor(MethodVisitor delegate, String hook, int flagsSlot) {
            super(Opcodes.ASM9, delegate);
            this.hook = hook;
            this.flagsSlot = flagsSlot;
        }

        @Override
        public void visitCode() {
            super.visitCode();
            super.visitVarInsn(Opcodes.ALOAD, 0);
            super.visitVarInsn(Opcodes.ILOAD, flagsSlot);
            super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    BRIDGE_INTERNAL_NAME,
                    hook,
                    "(Ljava/lang/Object;I)I",
                    false);
            super.visitVarInsn(Opcodes.ISTORE, flagsSlot);
        }
    }

    /** Wraps every {@code IRETURN} with {@code AgentBridge.afterNewFace(...)}. */
    private static final class NewFaceVisitor extends MethodVisitor {

        NewFaceVisitor(MethodVisitor delegate) {
            super(Opcodes.ASM9, delegate);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            Label proceed = new Label();
            super.visitVarInsn(Opcodes.ALOAD, 2);
            super.visitMethodInsn(Opcodes.INVOKESTATIC, BRIDGE_INTERNAL_NAME, "beforeNewFace",
                    "(Ljava/nio/ByteBuffer;)I", false);
            super.visitInsn(Opcodes.DUP);
            super.visitJumpInsn(Opcodes.IFEQ, proceed);
            super.visitInsn(Opcodes.IRETURN);
            super.visitLabel(proceed);
            super.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[]{Opcodes.INTEGER});
            super.visitInsn(Opcodes.POP);
        }

        @Override
        public void visitInsn(int opcode) {
            if (opcode == Opcodes.IRETURN) {
                super.visitVarInsn(Opcodes.ISTORE, NEW_FACE_TEMP_LOCAL);
                super.visitVarInsn(Opcodes.ALOAD, 2); // file
                super.visitVarInsn(Opcodes.ALOAD, 5); // aface
                super.visitVarInsn(Opcodes.ILOAD, NEW_FACE_TEMP_LOCAL);
                super.visitMethodInsn(
                        Opcodes.INVOKESTATIC,
                        BRIDGE_INTERNAL_NAME,
                        "afterNewFace",
                        "(Ljava/nio/ByteBuffer;Ljava/lang/Object;I)I",
                        false);
            }
            super.visitInsn(opcode);
        }
    }
}
