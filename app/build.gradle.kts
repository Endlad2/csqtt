// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.csqtt.client"
    compileSdk = 37

    defaultConfig {
        applicationId = "csqtt.quic.amurcanov"
        minSdk = 26
        targetSdk = 37
        versionCode = 200
        versionName = "2.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        ndk {
            abiFilters.addAll(listOf("arm64-v8a", "armeabi-v7a"))
        }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a")
            isUniversalApk = true
        }
    }

    val localProperties = Properties()
    val localPropertiesFile = rootProject.file("local.properties")
    if (localPropertiesFile.exists()) {
        localProperties.load(localPropertiesFile.inputStream())
    }

    signingConfigs {
        create("release") {
            val keyFile = localProperties.getProperty("KEYSTORE_FILE")
            if (keyFile != null) {
                // Резолвим путь: если начинается с "..", берём от корня проекта
                val resolvedFile = if (keyFile.startsWith("..")) {
                    // ../release.keystore -> корень проекта / release.keystore
                    file(rootDir.resolve(keyFile.substring(3)))
                } else {
                    file(keyFile)
                }
                if (resolvedFile.exists()) {
                    storeFile = resolvedFile
                    storePassword = localProperties.getProperty("KEYSTORE_PASSWORD")
                    keyAlias = localProperties.getProperty("KEY_ALIAS")
                    keyPassword = localProperties.getProperty("KEY_PASSWORD")
                } else {
                    println("WARNING: Keystore file not found: $keyFile (resolved: ${resolvedFile.absolutePath})")
                }
            }
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            val keyFile = localProperties.getProperty("KEYSTORE_FILE")
            val resolvedFile = if (keyFile != null && keyFile.startsWith("..")) {
                file(rootDir.resolve(keyFile.substring(3)))
            } else if (keyFile != null) {
                file(keyFile)
            } else null
            
            if (resolvedFile != null && resolvedFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
                println("✅ Signing config applied: ${resolvedFile.absolutePath}")
            } else {
                println("⚠️ WARNING: Keystore not found, using debug signing")
                println("   Looked for: ${resolvedFile?.absolutePath ?: keyFile}")
            }
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += "**/libclient.so"
            keepDebugSymbols += "**/libandroidx.graphics.path.so"
            keepDebugSymbols += "**/libdatastore_shared_counter.so"
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/INDEX.LIST"
            excludes += "/META-INF/DEPENDENCIES"
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    lint {
        checkReleaseBuilds = true
        abortOnError = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.19.0")
    implementation(platform("androidx.compose:compose-bom:2026.06.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.datastore:datastore-preferences:1.2.1")
    implementation("com.hierynomus:sshj:0.38.0") {
        exclude(group = "org.bouncycastle", module = "bcprov-jdk18on")
        exclude(group = "org.bouncycastle", module = "bcpkix-jdk18on")
        exclude(group = "org.bouncycastle", module = "bcutil-jdk18on")
    }
    implementation("org.bouncycastle:bcprov-jdk15to18:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk15to18:1.78.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("org.mockito:mockito-core:5.23.0")
    testImplementation("org.json:json:20260719")

    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation(platform("androidx.compose:compose-bom:2026.06.01"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
