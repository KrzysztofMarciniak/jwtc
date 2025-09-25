#!/bin/sh
set -e   

echo "Building jwtc (shared)..."
ninja

echo "Installing to /usr/local..."
sudo cp libjwtc.so /usr/local/lib/
sudo cp jwtc.h /usr/local/include/
sudo ldconfig

echo "Installation complete!"
echo "To use: Link with -ljwtc -ljson-c -lcrypto"
echo "Headers in /usr/local/include, lib in /usr/local/lib"

