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

// The CMake the Android build runs with, named here rather than left to the
// Android Gradle Plugin's default. Two modules configure a CMake build: the
// app itself — the Flutter tool points it at an EMPTY CMakeLists.txt purely so
// AGP believes it needs the NDK (`forceNdkDownload` in flutter_tools) — and
// `jni`, pulled in by path_provider_android, whose libdartjni.so is real and
// ships in the APK. Neither names a version, so both got AGP's default, 3.22.1,
// which the ubuntu-24.04 runner image has not carried since at least its
// 20260907.300 build (it ships 3.31.5 and 4.1.2). AGP answered that by
// downloading cmake;3.22.1 from Google inside every Android build for a
// month, silently, until one download came back as something that was not a
// zip and the 3.9.4 reproducible slot (c) failed four minutes into Gradle.
//
// A toolchain fetched during the build is a toolchain the recipe does not
// name, and one a verifier following REPRODUCIBLE_BUILDS.md would not know to
// install. So: the version the runner image already carries, applied to every
// module that has not chosen its own, checked to be present by a named CI
// step before Gradle starts, and listed in the toolchain table. 4.1.2 is also
// on the image but CMake 4 drops compatibility with the 3.10 minimum that
// jni's CMakeLists.txt declares, so it is not a drop-in. Change this and the
// step in .github/workflows/build.yml together; that step reads the value
// from this line.
val pinnedCmakeVersion = "3.31.5"

subprojects {
    afterEvaluate {
        val androidExt = extensions.findByName("android")
        if (androidExt is CommonExtension &&
            androidExt.externalNativeBuild.cmake.version == null
        ) {
            androidExt.externalNativeBuild.cmake.version = pinnedCmakeVersion
        }
    }
}

subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
