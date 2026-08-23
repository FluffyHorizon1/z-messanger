import com.android.build.api.dsl.CommonExtension

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}

// Force every Android module (the app AND every Flutter plugin) to compile
// against at least API 36. This runs in afterEvaluate — AFTER each plugin's
// own build file has executed — so it also fixes plugins like file_picker
// 8.3.7 that hardcode compileSdk 34 inside their own build.gradle and would
// otherwise clobber an override applied earlier (e.g. via plugins.withId).
subprojects {
    afterEvaluate {
        val androidExt = extensions.findByName("android")
        if (androidExt is CommonExtension) {
            if ((androidExt.compileSdk ?: 0) < 36) {
                androidExt.compileSdk = 36
            }
        }
    }
}

subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
