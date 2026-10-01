// Module build file of the made-up "orders" app. Read as text by app-manifest-check; never run.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.orders"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.orders"
        minSdk = 24
        targetSdk = 33
        versionCode = 12
        versionName = "1.4.0"
    }

    signingConfigs {
        create("release") {
            // The signing values come from the build machine, never from this file.
            storeFile = file(System.getenv("ORDERS_KEYSTORE") ?: "release.keystore")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
        debug {
            isDebuggable = true
        }
    }
}
