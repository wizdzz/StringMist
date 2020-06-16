package com.wizd.plugin

import com.android.build.gradle.AppExtension
import com.android.build.gradle.LibraryExtension

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.GradleException
import org.gradle.api.UnknownTaskException

class PluginImpl implements Plugin<Project>{

    @Override
    void apply(Project project){
        System.out.println("========================")
        System.out.println("StringMist plugin!")
        System.out.println("========================")

//        def android = project.extensions.findByType(AppExtension)
//        android.registerTransform(new InsertTransform())

//        project.gradle.addListener(new TaskListener())

        project.extensions.create('stringmist', StringMistExtension)

        def android = project.extensions.android
        if (android instanceof AppExtension) {
            applyApplication(project, android)
        }
        if (android instanceof LibraryExtension) {
            applyLibrary(project, android)
        }

//        project.afterEvaluate {
//            Log.setDebug(project.stringfog.debug)
//        }
    }

    void applyApplication(Project project, def android) {
        android.registerTransform(new StringMistPlugin(project))
        // throw an exception in instant run mode
        android.applicationVariants.all { variant ->
            def variantName = variant.name.capitalize()
            try {
                def instantRunTask = project.tasks.getByName("transformClassesWithInstantRunFor${variantName}")
                if (instantRunTask) {
                    throw new GradleException(
                            "StringMist does not support instant run mode, please trigger build"
                                    + " by assemble${variantName} or disable instant run"
                                    + " in 'File->Settings...'."
                    )
                }
            } catch (UnknownTaskException e) {
                // Not in instant run mode, continue.
            }
        }
    }

    void applyLibrary(Project project, def android) {
        android.registerTransform(new StringMistPlugin(project))
    }
}
