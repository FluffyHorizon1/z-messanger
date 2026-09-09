import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    // Firebase / FCM (reads google-services.json from this module).
    id("com.google.gms.google-services")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Release signing is read from android/key.properties when it exists. CI writes
// that file plus the keystore from GitHub secrets before a release build; a
// developer can also drop one in locally. When it's absent — PR builds, forks
// without secrets, `flutter run --release` — the build falls back to the debug
// key so it still completes (just not with the upload key).
val keystoreProperties = Properties()
val keystorePropertiesFile = rootProject.file("key.properties")
val hasReleaseSigning = keystorePropertiesFile.exists()
if (hasReleaseSigning) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

android {
    namespace = "com.zmessenger.www"
    // Pinned to 36: newer plugins (file_picker → flutter_plugin_android_lifecycle)
    // require consumers to compile against Android API 36+. This only sets which
    // APIs can be compiled against — targetSdk/minSdk are unchanged below.
    compileSdk = 36
    ndkVersion = flutter.ndkVersion

    compileOptions {
        // Required by flutter_local_notifications (uses java.time on older APIs).
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "com.zmessenger.www"
        // 24+: hardware-backed keystore + EncryptedSharedPreferences, and the
        // floor of androidx.biometric (app lock, 7.8).
        minSdk = maxOf(24, flutter.minSdkVersion)
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    // 14.1: the Android Gradle Plugin otherwise injects a "dependency metadata"
    // blob into the APK signing block — an encrypted description of the app's
    // dependency tree, readable by Google, with fresh randomness on every
    // build.
    //
    // It is the ONLY thing that stops this build being bit-for-bit
    // reproducible: measured, two independent builds differ in exactly 8 603
    // bytes and every one of them is inside that blob, while the v2 signature
    // and all 80 442 248 bytes of app content are identical. It also has no
    // business in a messenger that tells people the operator learns nothing —
    // shipping an encrypted phone-home blob to a third party is the opposite
    // of the claim, whatever it happens to contain.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildTypes {
        release {
            // Upload key when key.properties is present; debug key otherwise so
            // unsigned builds (PRs, forks, `flutter run --release`) still work.
            signingConfig = if (hasReleaseSigning)
                signingConfigs.getByName("release")
            else
                signingConfigs.getByName("debug")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

dependencies {
    // Backports java.time etc. so flutter_local_notifications works on old APIs.
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
    // Theme.AppCompat.* parents in res/values/styles.xml (needed by the
    // biometric prompt on Android 8.1 and below).
    implementation("androidx.appcompat:appcompat:1.7.0")
    // BioKey.kt (7.8b): BiometricPrompt with a CryptoObject for the
    // hardware-bound pass key. Same version local_auth_android ships.
    implementation("androidx.biometric:biometric:1.1.0")
}
