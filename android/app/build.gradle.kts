// SPDX-FileCopyrightText: 2026 FastKiwi (Sarmad)
// SPDX-License-Identifier: Apache-2.0
import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// Release signing material lives in the git-ignored android/keystore/ folder
// (keystore.properties: storeFile, storePassword, keyAlias, keyPassword).
// Without it the release build is signed with the debug key, so a local or
// CI build always works; only a build made with the real keystore is a release.
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore/keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "app.fastkiwi.transfer"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    // Pinned exactly (F-Droid recipe, reproducible builds): docs-build/REPRODUCIBLE.md.
    ndkVersion = "27.3.13750724"

    defaultConfig {
        applicationId = "app.fastkiwi.transfer"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.0-dev"
        // Arabic is the default (values/), English in values-en/.
        androidResources { localeFilters += listOf("ar", "en") }
        // The Rust core .so files go to src/main/jniLibs/<abi>/ (core build script, later).
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }

    signingConfigs {
        create("release") {
            if (keystoreProps.isNotEmpty()) {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = if (keystoreProps.isNotEmpty()) {
                signingConfigs.getByName("release")
            } else {
                // No keystore: debug-signed, NOT distributable (the release workflow refuses it).
                signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures { compose = true }

    packaging {
        jniLibs { useLegacyPackaging = false }
        resources {
            excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/*.version", "DebugProbesKt.bin", "kotlin-tooling-metadata.json")
        }
    }

    // No dependency-metadata blob in the APK (privacy, size, reproducibility).
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = false
    }
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
}
