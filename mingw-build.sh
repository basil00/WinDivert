#!/bin/bash
#
# mingw-build.sh
# (C) 2015, all rights reserved,
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Script for MinGW/Linux cross compilation.
# NOTE: run wddk-build.bat before this script.

set -e

ENVS="i686-w64-mingw32 x86_64-w64-mingw32"

for ENV in $ENVS
do
    if [ $ENV = "i686-w64-mingw32" ]
    then
        CPU=i386
        BITS=32
        MANGLE=_
    else
        CPU=amd64
        BITS=64
        MANGLE=
    fi
    if [ ! -d install/WDDK/$CPU ]
    then
        echo "WARNING: missing WDDK build; run wddk-build.bat first"
        echo "SKIP WDDK-$CPU"
        continue
    fi
    echo "BUILD WDDK-$CPU"
    CC="$ENV-gcc"
    COPTS="-shared -Wall -Wno-pointer-to-int-cast -O2 -Iinclude/ 
        -Wl,--enable-stdcall-fixup -Wl,--entry=${MANGLE}WinDivertDllEntry"
    CLIBS="-lgcc -lmsvcrt -lkernel32 -ladvapi32"
    STRIP="$ENV-strip"
    if [ -x "`which $CC`" ]
    then
        echo "\tmake install/MINGW/$CPU..."
        mkdir -p "install/MINGW/$CPU"
        echo "\tbuild install/MINGW/$CPU/WinDivert.dll..."
        $CC $COPTS -c dll/windivert.c -o dll/windivert.o
        $CC $COPTS -o "install/MINGW/$CPU/WinDivert.dll" \
            dll/windivert.o dll/windivert.def -nostdlib $CLIBS
        $STRIP "install/MINGW/$CPU/WinDivert.dll"
        echo "\tbuild install/MINGW/$CPU/netdump.exe..."
        $CC -s -O2 -Iinclude/ examples/netdump/netdump.c \
            -o "install/MINGW/$CPU/netdump.exe" -lWinDivert -lws2_32 \
            -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/netfilter.exe..."
        $CC -s -O2 -Iinclude/ examples/netfilter/netfilter.c \
            -o "install/MINGW/$CPU/netfilter.exe" -lWinDivert -lws2_32 \
            -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/passthru.exe..."
        $CC -s -O2 -Iinclude/ examples/passthru/passthru.c \
            -o "install/MINGW/$CPU/passthru.exe" -lWinDivert -lws2_32 \
            -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/webfilter.exe..."
        $CC -s -O2 -Iinclude/ examples/webfilter/webfilter.c \
            -o "install/MINGW/$CPU/webfilter.exe" -lWinDivert -lws2_32 \
            -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/streamdump.exe..."
        $CC -s -O2 -Iinclude/ examples/streamdump/streamdump.c \
            -o "install/MINGW/$CPU/streamdump.exe" -lWinDivert -lws2_32 \
            -L"install/MINGW/$CPU/"
        echo "\tcopy install/MINGW/$CPU/WinDivert$BITS.sys..."
        cp install/WDDK/$CPU/WinDivert$BITS.sys install/MINGW/$CPU
    else
        echo "WARNING: $CC not found"
    fi
done

