#!/bin/sh

# Simple install script for jwtc
# Builds the library and installs to /usr/local (requires sudo)

set -e  # Exit on error

echo "Building jwtc..."
ninja

echo "Installing to /usr/local..."
sudo cp libjwtc.a /usr/local/lib/
sudo cp jwtc.h /usr/local/include/
sudo ranlib /usr/local/lib/libjwtc.a  # Ensure symbol table

echo "Installation complete!"
echo "To use: Link with -ljwtc -ljson-c -lcrypto"
echo "Headers in /usr/local/include, lib in /usr/local/lib"
