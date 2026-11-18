import com.android.build.gradle.tasks.PackageAndroidArtifact
import java.nio.charset.StandardCharsets
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
}

fun gitOutput(vararg args: String): String? = runCatching {
    val process = ProcessBuilder(listOf("git") + args)
        .directory(rootProject.projectDir)
        .redirectErrorStream(true)
        .start()
    val output = process.inputStream.bufferedReader(StandardCharsets.UTF_8).use { it.readText().trim() }
    if (process.waitFor() == 0) output.takeIf { it.isNotBlank() } else null
}.getOrNull()

val gitCommitCount = gitOutput("rev-list", "HEAD", "--count")
    ?.toIntOrNull()
    ?.coerceAtLeast(1)
    ?: 1
val gitCommitHash = gitOutput("rev-parse", "--verify", "--short=12", "HEAD") ?: "dev"

val keystorePropertiesFile: File = rootProject.file("keystore.properties")
val keystoreProperties = if (keystorePropertiesFile.exists() && keystorePropertiesFile.isFile) {
    Properties().apply {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
} else null

android {
    namespace = "io.github.a13e300.fusefixer"
    compileSdk {
        version = release(36)
    }

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        applicationId = "io.github.a13e300.fusefixer"
        minSdk = 30
        targetSdk = 36
        versionCode = gitCommitCount
        versionName = gitCommitHash

        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=c++_static"
                arguments += "-DCMAKE_CXX_STANDARD=20"
                cppFlags(
                    "-fno-rtti", "-fno-exceptions",
                    "-ffunction-sections", "-fdata-sections",
                    "-fasynchronous-unwind-tables", "-fno-unwind-tables",
                    "-fvisibility=hidden", "-fvisibility-inlines-hidden",
                )
                abiFilters("arm64-v8a", "armeabi-v7a")
            }
        }
        base.archivesName = "FuseFixer-${gitCommitCount}-${gitCommitHash}"
    }

    signingConfigs {
        if (keystoreProperties != null) {
            create("release") {
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            externalNativeBuild {
                cmake {
                    cppFlags += arrayOf("-flto", "-O3")
                    arguments(
                        "-DCMAKE_CXX_FLAGS_RELEASE=",
                        "-DCMAKE_C_FLAGS_RELEASE=",
                    )
                }
            }
            val releaseSig = signingConfigs.findByName("release")
            signingConfig = if (releaseSig != null) releaseSig else {
                println("use debug signing config")
                signingConfigs["debug"]
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    packaging {
        resources.excludes += "**"
    }

    // https://stackoverflow.com/a/77745844
    tasks.withType<PackageAndroidArtifact> {
        doFirst { appMetadata.asFile.orNull?.writeText("") }
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
}

dependencies {
    compileOnly(libs.xposed.api)
    implementation(libs.androidx.core)
}