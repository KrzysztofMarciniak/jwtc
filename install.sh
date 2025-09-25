#!/bin/sh
set -xe

echo "Building jwtc (shared)..."
ninja

echo "Installing to /usr/local..."

install -Dm644 libjwtc.so /usr/local/lib/libjwtc.so

install -Dm644 jwtc.h /usr/local/include/jwtc.h

command -v ldconfig >/dev/null && ldconfig || true

echo "Installation complete!"
echo "To use: Link with -ljwtc -ljson-c -lcrypto"
echo "Headers in /usr/local/include, lib in /usr/local/lib"

