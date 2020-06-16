package com.wizd.mygradleplugin;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class StringMistClassInjector {
    private String nativeInterfaceClass;
    private String[] excludeClasses;
    private String[] includeJars;

    public StringMistClassInjector(String nativeInterfaceClass, String[] excludeClasses, String[] includeJars){
        this.nativeInterfaceClass = nativeInterfaceClass;

        this.excludeClasses = excludeClasses;
        for(int i = 0; i < this.excludeClasses.length; i++){
            this.excludeClasses[i] = this.excludeClasses[i] + ".class";
        }

        this.includeJars = includeJars;
    }

    public void doFog2Class(File fileIn, File fileOut) throws IOException {
        InputStream is = null;
        OutputStream os = null;
        try {
            is = new BufferedInputStream(new FileInputStream(fileIn));
            os = new BufferedOutputStream(new FileOutputStream(fileOut));

            if(isExcludeClass(fileIn)){
                byte[] buffer = new byte[1024];
                int read;
                while ((read = is.read(buffer)) >= 0) {
                    os.write(buffer, 0, read);
                }
            }
            else {
                System.out.println(String.format("----------- deal with %s -----------", fileIn.getAbsolutePath()));

                processClass(is, os);
            }
        }
        finally {
            closeQuietly(os);
            closeQuietly(is);
        }
    }

    private boolean isExcludeClass(File fileIn) {
        String fileName = fileIn.getName();
        if(fileName.startsWith("R$") || fileName.equals("R.class")
                || fileName.equals("BuildConfig.class")){
            return true;
        }

        String fullPathName = fileIn.getAbsolutePath();
        String classNameWithPath = fullPathName.replace(File.separator, ".");
        for(String excludeClassName: excludeClasses){
            if (classNameWithPath.endsWith(excludeClassName)){
                return true;
            }
        }

        return false;
    }

    private boolean isIncludeJars(File fileIn) {
        String jarName = fileIn.getName();
        for(String excludeClassName: includeJars){
            if (jarName.endsWith(excludeClassName)){
                return true;
            }
        }

        return false;
    }

    public void doFog2Jar(File jarIn, File jarOut) throws IOException {
        try {
            processJar(jarIn, jarOut, Charset.forName("UTF-8"), Charset.forName("UTF-8"));
        }
        catch (IllegalArgumentException e) {
            if ("MALFORMED".equals(e.getMessage())) {
                processJar(jarIn, jarOut, Charset.forName("GBK"), Charset.forName("UTF-8"));
            } else {
                throw e;
            }
        }
    }

    @SuppressWarnings("NewApi")
    private void processJar(File jarIn, File jarOut, Charset charsetIn, Charset charsetOut) throws IOException {
//        System.out.println(String.format("jar: %s, isIncludeJars: %b", jarIn.getName(), isIncludeJars(jarIn)));

//        boolean shouldExclude = shouldIncludeJar(jarIn, charsetIn);
        boolean shouldExclude = !isIncludeJars(jarIn);
        if(!shouldExclude){
            System.out.println(String.format("----------- deal with %s -----------", jarIn.getName()));
        }

        ZipInputStream zis = null;
        ZipOutputStream zos = null;
        try {
            zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(jarIn)), charsetIn);
            zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(jarOut)), charsetOut);
            ZipEntry entryIn;
            Map<String, Integer> processedEntryNamesMap = new HashMap<>();
            while ((entryIn = zis.getNextEntry()) != null) {
                final String entryName = entryIn.getName();
                if (!processedEntryNamesMap.containsKey(entryName)) {
                    ZipEntry entryOut = new ZipEntry(entryIn);
                    // Set compress method to default, fixed #12
                    if (entryOut.getMethod() != ZipEntry.DEFLATED) {
                        entryOut.setMethod(ZipEntry.DEFLATED);
                    }
                    entryOut.setCompressedSize(-1);
                    zos.putNextEntry(entryOut);
                    if (!entryIn.isDirectory()) {
                        if (entryName.endsWith(".class") && !shouldExclude) {
                            System.out.println("Jar class: " + entryName);
                            processClass(zis, zos);
                        } else {
                            copy(zis, zos);
                        }
                    }
                    zos.closeEntry();
                    processedEntryNamesMap.put(entryName, 1);
                }
            }
        } finally {
            closeQuietly(zos);
            closeQuietly(zis);
        }
    }

//    private boolean shouldExcludeJar(File jarIn, Charset charsetIn) throws IOException {
//        ZipInputStream zis = null;
//        try {
//            zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(jarIn)), charsetIn);
//            ZipEntry entryIn;
//            while ((entryIn = zis.getNextEntry()) != null) {
//                final String entryName = entryIn.getName();
//                if (entryName != null && entryName.contains("StringFog")) {
//                    return true;
//                }
//            }
//        } finally {
//            closeQuietly(zis);
//        }
//        return false;
//    }

    private void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[8192];
        int c;
        while ((c = in.read(buffer)) != -1) {
            out.write(buffer, 0, c);
        }
    }

    private void processClass(InputStream classIn, OutputStream classOut) throws IOException {
        ClassReader cr = new ClassReader(classIn);
        // skip module-info class, fixed #38
        if ("module-info".equals(cr.getClassName())) {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = classIn.read(buffer)) >= 0) {
                classOut.write(buffer, 0, read);
            }
        } else {
            ClassWriter classWriter = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            ClassVisitor cv = new StringMistClassVisitor(nativeInterfaceClass, classWriter);
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            byte[] code = classWriter.toByteArray();
            classOut.write(code);
            classOut.flush();
        }
    }

    private void closeQuietly(Closeable target) {
        if (target != null) {
            try {
                target.close();
            } catch (Exception e) {
                // Ignored.
            }
        }
    }
}
