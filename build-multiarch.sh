#!/bin/bash
# Build dist/hp_uploadprogress_guard-<X.Y>-<arch>.so for every requested PHP minor and every
# architecture, using the official php:<X.Y>-cli Docker images (NTS). <arch> is the `uname -m`
# name of the target (x86_64, aarch64), which is also what Ansible reports as ansible_architecture.
# The ABI of a PHP extension is fixed by the Zend module API number of the minor version plus the
# NTS/ZTS flavour, so one build per minor and arch loads on any NTS build of that minor: Sury,
# Remi, cPanel EA4, DirectAdmin CustomBuild, ...
#
#   ./build.sh 8.5 8.4 8.3 8.2 8.1 8.0 7.4 7.3 7.2 7.1 7.0 5.6
#   ARCHS="arm64" ./build.sh 8.4      # only one architecture (Docker platform names: amd64 arm64)
#
# Building the non-native arch needs QEMU binfmt emulation (bundled with Docker Desktop; on Linux:
# docker run --privileged --rm tonistiigi/binfmt --install all).
#
set -u
S="$(cd "$(dirname "$0")" && pwd)"
A="$S/src/rfc1867"
ARCHS="${ARCHS:-amd64 arm64}"
mkdir -p "$S/dist"
for v in "$@"; do
  for platform in $ARCHS; do  
    case "$platform" in
      amd64) arch=x86_64 ;;
      arm64) arch=aarch64 ;;
      *) echo "unknown arch: $platform (use amd64 or arm64)"; exit 1 ;;
    esac
    b="PHP-$v"; d="$S/src-$v"; mkdir -p "$d"; cp "$S/src/config.m4" "$S/src/hp_uploadprogress_guard.c" "$d/"
    cp "$A/rfc1867_copy-$v.c" "$d/rfc1867_copy.c"   # the per-branch parser copy is the source of truth (patched after the fix)
    img="php:${v}-cli"
    echo "=== $img ($arch)"
    docker run --rm --platform "linux/$platform" -e img="$img" -e arch="$arch" \
      -v "$d:/src:ro" -v "$S/dist-multiarch:/out" "$img" bash -c '    
      set -e
      [ "$(uname -m)" = "$arch" ] || { echo "refusing: $img is $(uname -m), wanted $arch"; exit 1; }
      cp -r /src /build && cd /build && phpize >/dev/null && ./configure --quiet >/dev/null && make -s 2>&1 | grep -E " error|error:" | head -5
      v=$(php -r "echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;")
      cp modules/hp_uploadprogress_guard.so /out/hp_uploadprogress_guard-${v}-${arch}.so
      php -n -d extension=/out/hp_uploadprogress_guard-$v-${arch}.so --ri hp_uploadprogress_guard | tail -1' 2>&1 | grep -vE "shtool|^$" | tail -5
  done
done
(cd "$S/dist" && sha256sum hp_uploadprogress_guard-*.so > SHA256SUMS)