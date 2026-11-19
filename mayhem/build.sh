#!/usr/bin/env bash
#
# mayhem/build.sh — build TigerVNC's common/ libraries with ASan+UBSan, the
# libFuzzer harnesses in mayhem/harnesses/ (+ a -standalone reproducer each),
# and, separately with the project's normal flags, its GTest unit tests.
#
# Outputs (all under gitignored mayhem/ directories, see mayhem/.gitignore):
#   mayhem/build-fuzz/   sanitized CMake build of common/{core,rdr,network,rfb}
#   mayhem/build-test/   normal-flags CMake build of tests/unit (run by test.sh)
#   mayhem/out/          fuzz_<name> and fuzz_<name>-standalone
#
# Re-runnable and offline: every dependency is an apt -dev package installed
# by mayhem/Dockerfile; CMake/ninja rebuild incrementally.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# A no-sanitizer build (SANITIZER_FLAGS empty) has no runtime that provides
# the SanCov hooks, so its -standalone reproducers link mayhem/sancov_stub.c.
NO_SANITIZERS=0
[ -n "$SANITIZER_FLAGS" ] || NO_SANITIZERS=1

# UBSan relaxation (ASan and every other UBSan check stay on and halting):
# nonnull-attribute fires on every connection, because the empty initial
# cursor is built as Cursor(0, 0, {}, nullptr) and Cursor's constructor does
# memcpy(data, nullptr, 0) (common/rfb/Cursor.cxx). A zero-length copy from
# NULL is harmless, and left on it would stop all three RFB targets on their
# first input.
SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=nonnull-attribute"

# SanCov for the project and harness objects: $LIB_FUZZING_ENGINE only
# instruments the translation unit it is linked into. Always on, also when
# SANITIZER_FLAGS is empty.
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"

# Only the libraries are needed; switch off the optional parts that pull in
# GUI/session dependencies. Nettle stays ON: DH, MSLogonII and RA2* need it.
COMMON_OPTS=(
  -G Ninja
  -DBUILD_VIEWER=OFF -DENABLE_NLS=OFF -DENABLE_H264=OFF -DENABLE_GNUTLS=OFF
  -DENABLE_NETTLE=ON -DENABLE_PAM=OFF -DENABLE_WAYLAND=OFF -DENABLE_SYSTEMD=OFF
  -DENABLE_SELINUX=OFF -DENABLE_PWQUALITY=OFF -DENABLE_AUDIO=OFF
)
LIBS=(core rdr network rfb rfbclient rfbserver)

# 1) The project, sanitized. Build type "Fuzz" is not one CMake knows, so it
#    adds no flags of its own: -O1, asserts kept, DWARF 3 from $DEBUG_FLAGS.
FZ="$SRC/mayhem/build-fuzz"
cmake -S . -B "$FZ" "${COMMON_OPTS[@]}" -DCMAKE_BUILD_TYPE=Fuzz \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_CFLAGS"
cmake --build "$FZ" -j"$MAYHEM_JOBS" --target "${LIBS[@]}"

# 2) The harnesses, each linked twice: libFuzzer and the standalone driver.
OUT="$SRC/mayhem/out"
OBJ="$FZ/harness-obj"
mkdir -p "$OUT" "$OBJ"
CXXFLAGS_H=($FUZZ_CFLAGS -std=gnu++17 -DHAVE_CONFIG_H
            -I"$FZ" -I"$SRC/common" -I"$SRC/vncviewer" -I"$SRC/mayhem/harnesses")
LINK_LIBS=("$FZ/common/rfb/librfbclient.a" "$FZ/common/rfb/librfbserver.a"
           "$FZ/common/rfb/librfb.a" "$FZ/common/network/libnetwork.a"
           "$FZ/common/rdr/librdr.a" "$FZ/common/core/libcore.a"
           -ljpeg -lz -lpixman-1 -lhogweed -lnettle -lgmp -lpthread)

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OBJ/lsan_off.o"
STANDALONE_EXTRA=()
if [ "$NO_SANITIZERS" = 1 ]; then
  $CC $DEBUG_FLAGS -c "$SRC/mayhem/sancov_stub.c" -o "$OBJ/sancov_stub.o"
  STANDALONE_EXTRA=("$OBJ/sancov_stub.o")
fi

# The viewer's config-file reader lives in vncviewer/, which is not built as
# a library; compile the two files it needs with the same flags.
$CXX "${CXXFLAGS_H[@]}" -c "$SRC/vncviewer/parameters.cxx" -o "$OBJ/viewer_parameters.o"
$CXX "${CXXFLAGS_H[@]}" -c "$SRC/vncviewer/MonitorIndicesParameter.cxx" -o "$OBJ/viewer_monitorindices.o"

harness() {  # harness <name> [extra objects...]
  local name="$1"; shift
  $CXX "${CXXFLAGS_H[@]}" -c "$SRC/mayhem/harnesses/$name.cxx" -o "$OBJ/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$OBJ/$name.o" "$@" "$OBJ/lsan_off.o" "${LINK_LIBS[@]}" -o "$OUT/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$OBJ/standalone_main.o" "$OBJ/$name.o" "$@" "$OBJ/lsan_off.o" "${STANDALONE_EXTRA[@]}" \
    "${LINK_LIBS[@]}" -o "$OUT/$name-standalone"
}
harness fuzz_client_msg
harness fuzz_client_handshake
harness fuzz_server_msg
harness fuzz_server_auth
harness fuzz_hostport
harness fuzz_viewer_config "$OBJ/viewer_parameters.o" "$OBJ/viewer_monitorindices.o"

# 3) The unit tests (GTest), with the project's normal Release flags.
TB="$SRC/mayhem/build-test"
cmake -S . -B "$TB" "${COMMON_OPTS[@]}" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build "$TB" -j"$MAYHEM_JOBS" --target \
  configargs conv convertlf gesturehandler hostport parameters pixelformat \
  shortcuthandler unicode emulatemb
