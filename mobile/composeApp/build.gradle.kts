import gobley.gradle.GobleyHost
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.kotlin.atomicfu)
    alias(libs.plugins.gobley.cargo)
    alias(libs.plugins.gobley.uniffi)
}

cargo {
    // The audited FFI crate lives in the Cargo workspace, not inside this Gradle
    // module. Gobley runs `cargo locate-project` here to find the manifest and
    // cross-builds the cdylib for the Android ABIs (and the iOS staticlib on a Mac).
    packageDirectory = layout.projectDirectory.dir("../../crates/pass-mgr-ffi")
}

uniffi {
    // pass-mgr-ffi uses UniFFI proc-macros (no .udl), so generate the Kotlin
    // bindings by introspecting the built library.
    generateFromLibrary()
}

kotlin {
    androidTarget {
        compilerOptions { jvmTarget = JvmTarget.JVM_17 }
    }
    jvmToolchain(17)

    // iOS targets build ONLY on macOS (this Linux box cannot build/sign iOS).
    // Guarded so they don't break the Android build here; see mobile/README.md
    // for the Mac steps. Gobley links the Rust staticlib via Kotlin/Native cinterop.
    if (GobleyHost.Platform.MacOS.isCurrent) {
        listOf(iosArm64(), iosSimulatorArm64(), iosX64()).forEach { target ->
            target.binaries.framework {
                baseName = "ComposeApp"
                isStatic = true
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.material3)
            implementation(compose.ui)
            implementation(libs.kotlinx.coroutines.core)
        }
        androidMain.dependencies {
            implementation(libs.androidx.activity.compose)
        }
    }
}

android {
    namespace = "com.passmgr"
    compileSdk = libs.versions.android.compileSdk.get().toInt()
    // Matches the NDK installed by mobile/scripts/install-android-toolchain.sh.
    ndkVersion = "30.0.14904198"

    defaultConfig {
        applicationId = "com.passmgr"
        minSdk = libs.versions.android.minSdk.get().toInt()
        targetSdk = libs.versions.android.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.1"
        // Build a device ABI (arm64) + an emulator ABI (x86_64).
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    packaging {
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
        // Keep the per-ABI native libs uncompressed/extracted for JNA to dlopen.
        jniLibs { useLegacyPackaging = false }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        getByName("release") {
            // Sign with a REAL release keystore supplied out-of-repo via Gradle properties or
            // env (PM_KEYSTORE / PM_KEYSTORE_PASSWORD / PM_KEY_ALIAS / PM_KEY_PASSWORD); never
            // commit a keystore. The Android debug key is universal and publicly known, so a
            // debug-signed "release" gives NO authenticity — anyone could ship a trojaned
            // same-signature update of this vault app. We fall back to the debug key only when
            // no keystore is configured, with a loud warning, so local `assembleRelease` smoke
            // builds still work but a distributable build requires a real key.
            val storePath = (project.findProperty("PM_KEYSTORE") as String?) ?: System.getenv("PM_KEYSTORE")
            signingConfig = if (!storePath.isNullOrBlank()) {
                signingConfigs.create("release") {
                    storeFile = file(storePath)
                    storePassword = (project.findProperty("PM_KEYSTORE_PASSWORD") as String?) ?: System.getenv("PM_KEYSTORE_PASSWORD")
                    keyAlias = (project.findProperty("PM_KEY_ALIAS") as String?) ?: System.getenv("PM_KEY_ALIAS")
                    keyPassword = (project.findProperty("PM_KEY_PASSWORD") as String?) ?: System.getenv("PM_KEY_PASSWORD")
                }
            } else {
                project.logger.warn(
                    "pass-mgr: no PM_KEYSTORE configured — signing the RELEASE build with the " +
                        "PUBLIC Android debug key. This APK is for local testing ONLY and must NOT be distributed."
                )
                signingConfigs.getByName("debug")
            }
        }
    }
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(17) }
}
