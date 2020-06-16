package com.wizd.mygradleplugin;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class StringMistClassVisitor extends ClassVisitor implements Opcodes {

    private Random random;
    private String targetClassName;
    private String decMethodClassName;
    private String decMethodName;
    private String nativeInterfaceClassName;
    private int generateMethodAcc;
    private boolean isClInitExists;
    private boolean needGenDecMethod;
    private boolean isTargetClassInterface;
    private boolean isNativeInterfaceClass;

    private List<ClassStringField> mStaticFinalFields = new ArrayList<>();
    private List<ClassStringField> mStaticFields = new ArrayList<>();
    private List<ClassStringField> mFinalFields = new ArrayList<>();
    private List<ClassStringField> mFields = new ArrayList<>();

    public class StrEnc{
        public String encrypted;
        public String blowfishKey;
        public byte xorVal;
    }

    public StringMistClassVisitor(String nativeInterfaceClassName, ClassVisitor cv) {
        super(Opcodes.ASM5, cv);
        random = new Random();
        random.setSeed(System.currentTimeMillis());

        this.nativeInterfaceClassName = nativeInterfaceClassName;

        isClInitExists = false;
        needGenDecMethod = false;
        isTargetClassInterface = false;
        isNativeInterfaceClass = false;
        generateMethodAcc = ACC_STATIC;

        decMethodName = "strDec123" + random.nextInt(100);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
//        System.out.println(String.format("StringMistClassVisitor access: %d, name: %s, signature: %s",
//                access,
//                name,
//                signature));

        this.targetClassName = name;

        if((access & ACC_INTERFACE) != 0){  // interface, can not generate method, call NativeInterface.strDec instead
            this.isTargetClassInterface = true;
            this.decMethodClassName = nativeInterfaceClassName;
            this.decMethodName = "strDec";
        }
        else{
            this.decMethodClassName = this.targetClassName;
        }

        if(name.equals(this.nativeInterfaceClassName)){
            this.isNativeInterfaceClass = true;
            this.decMethodName = "strDec";
        }

        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        //System.out.println("StringMistClassVisitor : visitMethod : " + name);
        MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);

        if ("<clinit>".equals(name)) {
            isClInitExists = true;
            // 处理静态成员变量
            // If clinit exists meaning the static fields (not final) would have be inited here.
            mv = new MethodVisitor(Opcodes.ASM5, mv) {

                private String lastStashCst;

                @Override
                public void visitCode() {
                    super.visitCode();
                    // Here init static final fields.
                    for (ClassStringField field : mStaticFinalFields) {
//                        System.out.println("visitMethodInsn0");
                        if (!canEncrypted(field.value)) {
                            if(field.value != null) {
                                mv.visitLdcInsn(field.value);
                                mv.visitFieldInsn(Opcodes.PUTSTATIC, targetClassName, field.name, ClassStringField.STRING_DESC);
                            }
                            continue;
                        }
                        String originValue = field.value;

                        needGenDecMethod = !isTargetClassInterface;

                        StrEnc strEnc = generateKeyAndEncryptString(originValue);
                        super.visitLdcInsn(strEnc.encrypted);
                        super.visitLdcInsn(strEnc.blowfishKey);
                        super.visitLdcInsn(strEnc.xorVal);
                        super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                decMethodClassName,
                                decMethodName,
                                "(Ljava/lang/String;Ljava/lang/String;B)Ljava/lang/String;", false);
                        super.visitFieldInsn(Opcodes.PUTSTATIC, targetClassName, field.name, ClassStringField.STRING_DESC);
//                        generateInvokeStrDec(this, field);

                    }
                }

                @Override
                public void visitLdcInsn(Object cst) {
                    // Here init static or static final fields, but we must check field name int 'visitFieldInsn'
//                    System.out.println("visitMethodInsn1");
                    if (cst instanceof String && canEncrypted((String) cst)) {
                        lastStashCst = (String) cst;
                        String originValue = lastStashCst;

                        needGenDecMethod = !isTargetClassInterface;

                        StrEnc strEnc = generateKeyAndEncryptString(originValue);
                        super.visitLdcInsn(strEnc.encrypted);
                        super.visitLdcInsn(strEnc.blowfishKey);
                        super.visitLdcInsn(strEnc.xorVal);
                        super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                decMethodClassName,
                                decMethodName,
                                "(Ljava/lang/String;Ljava/lang/String;B)Ljava/lang/String;", false);

//                        generateInvokeStrDec(this, originValue);
                    } else {
                        lastStashCst = null;
                        super.visitLdcInsn(cst);
                    }
                }

                @Override
                public void visitFieldInsn(int opcode, String owner, String name, String desc) {
                    if (targetClassName.equals(owner) && lastStashCst != null) {
                        boolean isContain = false;
                        for (ClassStringField field : mStaticFields) {
                            if (field.name.equals(name)) {
                                isContain = true;
                                break;
                            }
                        }
                        if (!isContain) {
                            for (ClassStringField field : mStaticFinalFields) {
                                if (field.name.equals(name) && field.value == null) {
                                    field.value = lastStashCst;
                                    break;
                                }
                            }
                        }
                    }
                    lastStashCst = null;
                    super.visitFieldInsn(opcode, owner, name, desc);
                }
            };

        }
        else if ("<init>".equals(name)) {
            // 处理成员变量
            // Here init final(not static) and normal fields
            mv = new MethodVisitor(Opcodes.ASM5, mv) {
                @Override
                public void visitLdcInsn(Object cst) {
                    // We don't care about whether the field is final or normal
//                    System.out.println("visitMethodInsn2");
                    if (cst instanceof String && canEncrypted((String) cst)) {
                        String originValue = (String) cst;

                        needGenDecMethod = !isTargetClassInterface;

                        StrEnc strEnc = generateKeyAndEncryptString(originValue);
                        super.visitLdcInsn(strEnc.encrypted);
                        super.visitLdcInsn(strEnc.blowfishKey);
                        super.visitLdcInsn(strEnc.xorVal);
                        super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                decMethodClassName,
                                decMethodName,
                                "(Ljava/lang/String;Ljava/lang/String;B)Ljava/lang/String;", false);

//                        generateInvokeStrDec(this, originValue);
                    } else {
                        super.visitLdcInsn(cst);
                    }
                }
            };
        }
        else {
            // 处理局部变量
            mv = new MethodVisitor(Opcodes.ASM5, mv) {

                @Override
                public void visitLdcInsn(Object cst) {
//                    System.out.println("visitMethodInsn3");
                    if (cst instanceof String && canEncrypted((String) cst)) {
                        // If the value is a static final field
                        for (ClassStringField field : mStaticFinalFields) {
                            if (cst.equals(field.value)) {
                                super.visitFieldInsn(Opcodes.GETSTATIC, targetClassName, field.name, ClassStringField.STRING_DESC);
                                return;
                            }
                        }
                        // If the value is a final field (not static)
                        for (ClassStringField field : mFinalFields) {
                            // if the value of a final field is null, we ignore it
                            if (cst.equals(field.value)) {
                                super.visitVarInsn(Opcodes.ALOAD, 0);
                                super.visitFieldInsn(Opcodes.GETFIELD, targetClassName, field.name, "Ljava/lang/String;");
                                return;
                            }
                        }
                        // local variables
                        String originValue = (String) cst;

                        needGenDecMethod = !isTargetClassInterface;

                        StrEnc strEnc = generateKeyAndEncryptString(originValue);
                        super.visitLdcInsn(strEnc.encrypted);
                        super.visitLdcInsn(strEnc.blowfishKey);
                        super.visitLdcInsn(strEnc.xorVal);
                        super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                decMethodClassName,
                                decMethodName,
                                "(Ljava/lang/String;Ljava/lang/String;B)Ljava/lang/String;", false);

//                        generateInvokeStrDec(this, originValue);
                        return;
                    }
                    super.visitLdcInsn(cst);
                }

            };
        }
//        }
        return mv;
    }

    @Override
    public FieldVisitor visitField(int access, String name, String desc, String signature, Object value) {
        if (ClassStringField.STRING_DESC.equals(desc) && name != null) {
            // static final, in this condition, the value is null or not null.
            if ((access & Opcodes.ACC_STATIC) != 0 && (access & Opcodes.ACC_FINAL) != 0) {
                mStaticFinalFields.add(new ClassStringField(name, (String) value));
                value = null;
            }
            // static, in this condition, the value is null.
            if ((access & Opcodes.ACC_STATIC) != 0 && (access & Opcodes.ACC_FINAL) == 0) {
                mStaticFields.add(new ClassStringField(name, (String) value));
                value = null;
            }

            // final, in this condition, the value is null or not null.
            if ((access & Opcodes.ACC_STATIC) == 0 && (access & Opcodes.ACC_FINAL) != 0) {
                mFinalFields.add(new ClassStringField(name, (String) value));
                value = null;
            }

            // normal, in this condition, the value is null.
            if ((access & Opcodes.ACC_STATIC) != 0 && (access & Opcodes.ACC_FINAL) != 0) {
                mFields.add(new ClassStringField(name, (String) value));
                value = null;
            }
        }
        return super.visitField(access, name, desc, signature, value);
    }

    @Override
    public void visitEnd() {
        if (!isClInitExists && !mStaticFinalFields.isEmpty()) {
            MethodVisitor mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            mv.visitCode();
            // Here init static final fields.
            for (ClassStringField field : mStaticFinalFields) {
//                System.out.println("visitMethodInsn4");
                if (!canEncrypted(field.value)) {
                    if(field.value != null) {
                        mv.visitLdcInsn(field.value);
                        mv.visitFieldInsn(Opcodes.PUTSTATIC, targetClassName, field.name, ClassStringField.STRING_DESC);
                    }
                    continue;
                }
//                mv.visitLdcInsn("key");
//                mv.visitMethodInsn(Opcodes.INVOKESTATIC, mStringFogImpl.class.getName().replace('.', '/'), "decrypt", "(Ljava/lang/String;)Ljava/lang/String;", false);
//                mv.visitFieldInsn(Opcodes.PUTSTATIC, targetClassName, field.name, ClassStringField.STRING_DESC);

                needGenDecMethod = !isTargetClassInterface;

                String originValue = field.value;
                StrEnc strEnc = generateKeyAndEncryptString(originValue);
                mv.visitLdcInsn(strEnc.encrypted);
                mv.visitLdcInsn(strEnc.blowfishKey);
                mv.visitLdcInsn(strEnc.xorVal);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                        decMethodClassName,
                        decMethodName,
                        "(Ljava/lang/String;Ljava/lang/String;B)Ljava/lang/String;", false);
                mv.visitFieldInsn(Opcodes.PUTSTATIC, targetClassName, field.name, ClassStringField.STRING_DESC);
            }
            mv.visitInsn(Opcodes.RETURN);
            mv.visitMaxs(1, 0);
            mv.visitEnd();
        }

        if(isNativeInterfaceClass){  // if it's nativeInterface, also generate strDec for interface class's invoke
            needGenDecMethod = true;
            generateMethodAcc |= ACC_PUBLIC;
        }
        else{
            generateMethodAcc |= ACC_PRIVATE;
        }

        if(needGenDecMethod) {
            generateNewMethod();
        }

        super.visitEnd();
    }

    // R8 Shrinker will replace this method with "throw null", use proguard instead
    private void generateNewMethod(){
        MethodVisitor mv = super.visitMethod(generateMethodAcc, decMethodName, "(Ljava/lang/String;Ljava/lang/String;B)Ljava/lang/String;", null, null);
        mv.visitCode();
        Label l0 = new Label();
        mv.visitLabel(l0);
        mv.visitLineNumber(43, l0);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETSTATIC, "java/nio/charset/StandardCharsets", "ISO_8859_1", "Ljava/nio/charset/Charset;");
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "(Ljava/nio/charset/Charset;)[B", false);
        mv.visitVarInsn(ALOAD, 1);
        mv.visitFieldInsn(GETSTATIC, "java/nio/charset/StandardCharsets", "ISO_8859_1", "Ljava/nio/charset/Charset;");
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "(Ljava/nio/charset/Charset;)[B", false);
        mv.visitMethodInsn(INVOKESTATIC, nativeInterfaceClassName, "a", "([B[B)[B", false);
        mv.visitVarInsn(ASTORE, 3);
        Label l1 = new Label();
        mv.visitLabel(l1);
        mv.visitLineNumber(44, l1);
        mv.visitInsn(ICONST_0);
        mv.visitVarInsn(ISTORE, 4);
        Label l2 = new Label();
        mv.visitLabel(l2);
        mv.visitFrame(Opcodes.F_APPEND, 2, new Object[]{"[B", Opcodes.INTEGER}, 0, null);
        mv.visitVarInsn(ILOAD, 4);
        mv.visitVarInsn(ALOAD, 3);
        mv.visitInsn(ARRAYLENGTH);
        Label l3 = new Label();
        mv.visitJumpInsn(IF_ICMPGE, l3);
        Label l4 = new Label();
        mv.visitLabel(l4);
        mv.visitLineNumber(45, l4);
        mv.visitVarInsn(ALOAD, 3);
        mv.visitVarInsn(ILOAD, 4);
        mv.visitInsn(DUP2);
        mv.visitInsn(BALOAD);
        mv.visitVarInsn(ILOAD, 2);
        mv.visitInsn(IXOR);
        mv.visitInsn(I2B);
        mv.visitInsn(BASTORE);
        Label l5 = new Label();
        mv.visitLabel(l5);
        mv.visitLineNumber(44, l5);
        mv.visitIincInsn(4, 1);
        mv.visitJumpInsn(GOTO, l2);
        mv.visitLabel(l3);
        mv.visitLineNumber(48, l3);
        mv.visitFrame(Opcodes.F_CHOP, 1, null, 0, null);
        mv.visitTypeInsn(NEW, "java/lang/String");
        mv.visitInsn(DUP);
        mv.visitVarInsn(ALOAD, 3);
        mv.visitFieldInsn(GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;");
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([BLjava/nio/charset/Charset;)V", false);
        mv.visitInsn(ARETURN);
        Label l6 = new Label();
        mv.visitLabel(l6);
        mv.visitLocalVariable("i", "I", null, l2, l3, 4);
        mv.visitLocalVariable("ori", "Ljava/lang/String;", null, l0, l6, 0);
        mv.visitLocalVariable("key", "Ljava/lang/String;", null, l0, l6, 1);
        mv.visitLocalVariable("val", "B", null, l0, l6, 2);
        mv.visitLocalVariable("ori0", "[B", null, l1, l6, 3);
        mv.visitMaxs(4, 5);
        mv.visitEnd();
    }

    private StrEnc generateKeyAndEncryptString(String in){
        StrEnc strEnc = new StrEnc();

        strEnc.xorVal = (byte)(random.nextInt(0x7C) + 1);

        byte[] ori0 = in.getBytes(StandardCharsets.UTF_8);
        for(int i = 0; i < ori0.length; i++){
            ori0[i] ^= strEnc.xorVal;
        }


//        int blowfishKeyLen = 10 + random.nextInt(10);
        int blowfishKeyLen = 32;
        byte[] blowfishKey = new byte[blowfishKeyLen];
        for (int i = 0; i < blowfishKeyLen; i++){
            blowfishKey[i] = (byte)(random.nextInt(0x7C) + 1);
        }
        strEnc.blowfishKey = new String(blowfishKey, StandardCharsets.ISO_8859_1);

        Blowfish blowfish = new Blowfish(blowfishKey);
        byte[] encrypted = blowfish.encryptBytes(ori0);
        strEnc.encrypted = new String(encrypted, StandardCharsets.ISO_8859_1);

//        System.out.println("ori0: " + Base64.getEncoder().encodeToString(ori0));
//        System.out.println("encrypted: " + Base64.getEncoder().encodeToString(encrypted));
//        System.out.println("encrypted: " + Base64.getEncoder().encodeToString(strEnc.encrypted.getBytes(StandardCharsets.ISO_8859_1)));
//        System.out.println("blowfishKey: " + Base64.getEncoder().encodeToString(blowfishKey));
//        System.out.println("blowfishKey: " + Base64.getEncoder().encodeToString(strEnc.blowfishKey.getBytes(StandardCharsets.ISO_8859_1)));
//        System.out.println("xorVal: " + strEnc.xorVal);

        return strEnc;
    }

    private boolean canEncrypted(String value) {
        // Max string length is 65535, should check the encrypted length.
        return !isNativeInterfaceClass && !TextUtils.isEmptyAfterTrim(value) && value.length() < 65535;
    }
}
