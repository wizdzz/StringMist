package com.wizd.plugin


import com.android.annotations.NonNull
import com.wizd.mygradleplugin.StringMistClassInjector
import org.gradle.api.*

import com.android.build.gradle.internal.pipeline.TransformManager
import com.android.build.api.transform.*
import com.android.utils.FileUtils
import com.google.common.io.Files
import groovy.io.FileType
import com.wizd.mygradleplugin.MD5

class StringMistPlugin extends Transform implements Plugin<Project> {

    protected StringMistClassInjector mInjector
    protected String nativeInterfaceClass

    StringMistPlugin(Project project){
        project.afterEvaluate {
            nativeInterfaceClass = project.stringmist.nativeInterfaceClass.replace(".", "/")
            String[] excludeClasses = project.stringmist.excludeClasses
            String[] includeJars = project.stringmist.includeJars
            this.mInjector = new StringMistClassInjector(nativeInterfaceClass, excludeClasses, includeJars)
        }
    }

    @Override
    void apply(Project project) {
        //registerTransform
        def android = project.extensions.getByType(AppExtension)
        android.registerTransform(this)
    }

    @Override
    String getName() {
        return "StringMistPlugin"
    }

    @Override
    Set<QualifiedContent.ContentType> getInputTypes() {
        return TransformManager.CONTENT_CLASS
    }

    @Override
    Set<? super QualifiedContent.Scope> getScopes() {
        return TransformManager.SCOPE_FULL_PROJECT
    }

    @Override
    boolean isIncremental() {
        return false
    }

    @Override
    void transform(@NonNull TransformInvocation transformInvocation) throws TransformException, InterruptedException, IOException {
        def dirInputs = new HashSet<>()
        def jarInputs = new HashSet<>()

        if (!transformInvocation.isIncremental()) {
            transformInvocation.getOutputProvider().deleteAll()
        }

        // Collecting inputs.
        transformInvocation.inputs.each { input ->
            input.directoryInputs.each { dirInput ->
                dirInputs.add(dirInput)
            }
            input.jarInputs.each { jarInput ->
                jarInputs.add(jarInput)
            }
        }

//        if (mMappingPrinter != null) {
//            mMappingPrinter.startMappingOutput()
//            mMappingPrinter.ouputInfo(mKey, mImplementation)
//        }

        if (!dirInputs.isEmpty() || !jarInputs.isEmpty()) {
            File dirOutput = transformInvocation.outputProvider.getContentLocation(
                    "classes", getOutputTypes(), getScopes(), Format.DIRECTORY)
            FileUtils.mkdirs(dirOutput)
            if (!dirInputs.isEmpty()) {
                dirInputs.each { dirInput ->
                    if (transformInvocation.incremental) {
                        dirInput.changedFiles.each { entry ->
                            File fileInput = entry.getKey()
                            File fileOutput = new File(fileInput.getAbsolutePath().replace(
                                    dirInput.file.getAbsolutePath(), dirOutput.getAbsolutePath()))
                            FileUtils.mkdirs(fileOutput.parentFile)
                            Status fileStatus = entry.getValue()
                            switch(fileStatus) {
                                case Status.ADDED:
                                case Status.CHANGED:
                                    if (fileInput.isDirectory()) {
                                        return // continue.
                                    }
                                    if (mInjector != null && fileInput.getName().endsWith('.class')) {
                                        mInjector.doFog2Class(fileInput, fileOutput)
                                    } else {
                                        Files.copy(fileInput, fileOutput)
                                    }
                                    break
                                case Status.REMOVED:
                                    if (fileOutput.exists()) {
                                        if (fileOutput.isDirectory()) {
                                            fileOutput.deleteDir()
                                        } else {
                                            fileOutput.delete()
                                        }
                                    }
                                    break
                            }
                        }
                    } else {
                        dirInput.file.traverse(type: FileType.FILES) { fileInput ->
                            File fileOutput = new File(fileInput.getAbsolutePath().replace(dirInput.file.getAbsolutePath(), dirOutput.getAbsolutePath()))
                            FileUtils.mkdirs(fileOutput.parentFile)
                            if (mInjector != null && fileInput.getName().endsWith('.class')) {
                                mInjector.doFog2Class(fileInput, fileOutput)
                            } else {
                                Files.copy(fileInput, fileOutput)
                            }
                        }
                    }
                }
            }

            if (!jarInputs.isEmpty()) {
                jarInputs.each { jarInput ->
                    File jarInputFile = jarInput.file
                    File jarOutputFile = transformInvocation.outputProvider.getContentLocation(
                            getUniqueHashName(jarInputFile), getOutputTypes(), getScopes(), Format.JAR
                    )

                    FileUtils.mkdirs(jarOutputFile.parentFile)

                    switch (jarInput.status) {
                        case Status.NOTCHANGED:
                            if (transformInvocation.incremental) {
                                break
                            }
                        case Status.ADDED:
                        case Status.CHANGED:
                            if (mInjector != null) {
                                mInjector.doFog2Jar(jarInputFile, jarOutputFile)
                            } else {
                                Files.copy(jarInputFile, jarOutputFile)
                            }
                            break
                        case Status.REMOVED:
                            if (jarOutputFile.exists()) {
                                jarOutputFile.delete()
                            }
                            break
                    }
                }
            }
        }
    }

    String getUniqueHashName(File fileInput) {
        final String fileInputName = fileInput.getName()
        if (fileInput.isDirectory()) {
            return fileInputName
        }
        final String parentDirPath = fileInput.getParentFile().getAbsolutePath()
        final String pathMD5 = MD5.getMessageDigest(parentDirPath.getBytes())
        final int extSepPos = fileInputName.lastIndexOf('.')
        final String fileInputNamePrefix =
                (extSepPos >= 0 ? fileInputName.substring(0, extSepPos) : fileInputName)
        return fileInputNamePrefix + '_' + pathMD5
    }
}
