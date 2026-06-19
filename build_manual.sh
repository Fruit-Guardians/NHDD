#!/bin/bash
set -e

# ============================================================
# NHDD Minimal APK Build Script
# Only dependency: com.topjohnwu.libsu:core:5.2.2
# No appcompat, no material, no recyclerview
# UI built programmatically, Theme: DeviceDefault.NoActionBar
# ============================================================

# --- Configuration ---
PROJECT_DIR="/lina_android/NHDD"
APP_DIR="${PROJECT_DIR}/app"
SRC_DIR="${APP_DIR}/src/main"
RES_DIR="${SRC_DIR}/res"
MANIFEST="${SRC_DIR}/AndroidManifest.xml"
JAVA_SRC="${SRC_DIR}/java/com/nhdd/app/MainActivity.java"

ANDROID_SDK="/home/mansu/Android/Sdk"
BUILD_TOOLS="${ANDROID_SDK}/build-tools/34.0.0"
PLATFORM="${ANDROID_SDK}/platforms/android-34/android.jar"
JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"

AAPT2="${BUILD_TOOLS}/aapt2"
JAVAC="${JAVA_HOME}/bin/javac"
D8="${BUILD_TOOLS}/d8"
ZIPALIGN="${BUILD_TOOLS}/zipalign"
APKSIGNER="${BUILD_TOOLS}/apksigner"

OUTPUT_DIR="${APP_DIR}/build/outputs/apk/debug"
APK_NAME="app-debug.apk"
FINAL_APK="${OUTPUT_DIR}/${APK_NAME}"

# Build intermediates
BUILD_DIR="${APP_DIR}/build/manual"
COMPILED_RES_DIR="${BUILD_DIR}/compiled_res"
GENERATED_DIR="${BUILD_DIR}/generated"
CLASSES_DIR="${BUILD_DIR}/classes"
DEX_DIR="${BUILD_DIR}/dex"
LINKED_RES="${BUILD_DIR}/linked-res.apk"

# --- Only dependency: libsu core ---
LIBSU_JAR="/home/mansu/.gradle/caches/transforms-3/89245cac832c6e14c18b451985b4d112/transformed/core-5.2.2-runtime.jar"

echo "========================================="
echo " NHDD Minimal APK Build"
echo " Dependency: libsu:core:5.2.2 only"
echo "========================================="

# --- Step 0: Verify dependency ---
echo "[0] Verifying dependencies..."
if [ ! -f "${LIBSU_JAR}" ]; then
    echo "ERROR: libsu core JAR not found at ${LIBSU_JAR}"
    echo "Searching alternatives..."
    ALT=$(find /home/mansu/.gradle/caches -name "core-5.2.2-runtime.jar" 2>/dev/null | head -1)
    if [ -n "${ALT}" ]; then
        echo "Found alternative: ${ALT}"
        LIBSU_JAR="${ALT}"
    else
        echo "Also searching for classes.jar in transforms..."
        ALT2=$(find /home/mansu/.gradle/caches/transforms-3 -path "*/core-5.2.2/jars/classes.jar" 2>/dev/null | head -1)
        if [ -n "${ALT2}" ]; then
            echo "Found alternative: ${ALT2}"
            LIBSU_JAR="${ALT2}"
        else
            echo "FATAL: Cannot find libsu core JAR anywhere!"
            exit 1
        fi
    fi
fi
echo "  libsu core: ${LIBSU_JAR}"

# --- Step 1: Clean and create directories ---
echo "[1] Preparing build directories..."
rm -rf "${BUILD_DIR}" "${OUTPUT_DIR}"
mkdir -p "${COMPILED_RES_DIR}" "${GENERATED_DIR}" "${CLASSES_DIR}" "${DEX_DIR}" "${OUTPUT_DIR}"

# --- Step 2: Compile app resources with aapt2 ---
echo "[2] Compiling app resources with aapt2..."
APP_RES_ZIP="${COMPILED_RES_DIR}/app_res.zip"
"${AAPT2}" compile --dir "${RES_DIR}" -o "${APP_RES_ZIP}"
echo "  App resources compiled."

# --- Step 3: Link resources with aapt2 (no dependency resources) ---
echo "[3] Linking resources with aapt2..."
"${AAPT2}" link \
    -o "${LINKED_RES}" \
    -I "${PLATFORM}" \
    --manifest "${MANIFEST}" \
    --java "${GENERATED_DIR}" \
    --auto-add-overlay \
    --min-sdk-version 28 \
    --target-sdk-version 34 \
    --version-code 4 \
    --version-name "4.0" \
    -R "${APP_RES_ZIP}"

echo "  Resource linking done."

# --- Step 4: Compile Java source with javac ---
echo "[4] Compiling Java source with javac..."

R_JAVA=$(find "${GENERATED_DIR}" -name "R.java" 2>/dev/null | head -1)
if [ -z "$R_JAVA" ]; then
    echo "ERROR: R.java not generated!"
    exit 1
fi
echo "  R.java at: ${R_JAVA}"

CLASSPATH="${PLATFORM}:${LIBSU_JAR}"

"${JAVAC}" \
    -source 11 \
    -target 11 \
    -d "${CLASSES_DIR}" \
    -classpath "${CLASSPATH}" \
    -sourcepath "${SRC_DIR}/java:${GENERATED_DIR}" \
    "${JAVA_SRC}" \
    "${R_JAVA}"

echo "  Java compilation done."

# --- Step 5: Convert to DEX with d8 ---
echo "[5] Converting to DEX with d8..."

# Collect compiled class files
CLASS_FILES=$(find "${CLASSES_DIR}" -name "*.class")

# d8: Convert app classes + libsu JAR to DEX
"${D8}" \
    --min-api 28 \
    --output "${DEX_DIR}" \
    --lib "${PLATFORM}" \
    ${CLASS_FILES} \
    "${LIBSU_JAR}"

DEX_COUNT=$(ls "${DEX_DIR}"/*.dex 2>/dev/null | wc -l)
echo "  DEX conversion done. DEX files: ${DEX_COUNT}"

if [ "$DEX_COUNT" -eq 0 ]; then
    echo "ERROR: No DEX files generated!"
    exit 1
fi

# --- Step 6: Package APK ---
echo "[6] Packaging APK..."

PACKAGED_APK="${BUILD_DIR}/app-unsigned.apk"
cp "${LINKED_RES}" "${PACKAGED_APK}"

cd "${DEX_DIR}"
for dex in *.dex; do
    echo "  Adding ${dex} to APK..."
    zip -j "${PACKAGED_APK}" "${dex}"
done
cd -

echo "  APK packaging done."

# --- Step 7: Align APK ---
echo "[7] Aligning APK..."
ALIGNED_APK="${BUILD_DIR}/app-aligned.apk"
"${ZIPALIGN}" -f 4 "${PACKAGED_APK}" "${ALIGNED_APK}"
echo "  APK alignment done."

# --- Step 8: Sign APK ---
echo "[8] Signing APK..."

DEBUG_KEYSTORE="${HOME}/.android/debug.keystore"
if [ ! -f "${DEBUG_KEYSTORE}" ]; then
    echo "  Generating debug keystore..."
    keytool -genkeypair \
        -keystore "${DEBUG_KEYSTORE}" \
        -storepass android \
        -alias androiddebugkey \
        -keypass android \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US"
fi

"${APKSIGNER}" sign \
    --ks "${DEBUG_KEYSTORE}" \
    --ks-pass pass:android \
    --ks-key-alias androiddebugkey \
    --key-pass pass:android \
    --out "${FINAL_APK}" \
    "${ALIGNED_APK}"

echo "  APK signing done."

# --- Step 9: Verify ---
echo "[9] Verifying APK..."
"${APKSIGNER}" verify --verbose "${FINAL_APK}" 2>&1 || true

APK_SIZE=$(du -h "${FINAL_APK}" | cut -f1)
echo ""
echo "========================================="
echo " BUILD SUCCESSFUL!"
echo " APK: ${FINAL_APK}"
echo " Size: ${APK_SIZE}"
echo " Dependencies: libsu:core:5.2.2 only"
echo "========================================="
echo ""
echo "Install with: adb install -r ${FINAL_APK}"
