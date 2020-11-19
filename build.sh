#!/bin/sh

mkdir -p dist

x86_64-w64-mingw32-gcc -c src/getversion.c -o dist/getversion.x64.o
i686-w64-mingw32-gcc -c src/getversion.c -o dist/getversion.x86.o

x86_64-w64-mingw32-gcc -c src/inject_urbanbishop.c -o dist/inject_urbanbishop.x64.o
i686-w64-mingw32-gcc -c src/inject_urbanbishop.c -o dist/inject_urbanbishop.x86.o

cp src/bof.cna dist/bof.cna
