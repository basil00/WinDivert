#!/bin/bash
#
# mingw-build.sh
# (C) 2019, all rights reserved,
#
# This file is part of WinDivert.
#
# WinDivert is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# WinDivert is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

# Script for MinGW/Linux cross compilation.
# NOTE: run msvc-build.bat before this script.

set -e

ENVS="i686-w64-mingw32 x86_64-w64-mingw32"

if [ "$1" = "debug" ]
then
    EXTRA_OPTS="-lmsvcrt -include stdio.h"
fi 

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
    HAVE_SYS=yes
    if [ ! -d install/MSVC/$CPU ]
    then
        echo "WARNING: missing MSVC build; run msvc-build.bat first"
        HAVE_SYS=no
    fi
    echo "BUILD MINGW-$CPU"
    CC="$ENV-gcc"
    COPTS="-fno-ident -shared -Wall -Wno-pointer-to-int-cast -Os -Iinclude/ 
        -Wl,--enable-stdcall-fixup -Wl,--entry=${MANGLE}WinDivertDllEntry"
    CLIBS="-lkernel32 -ladvapi32 $EXTRA_OPTS"
    STRIP="$ENV-strip"
    DLLTOOL="$ENV-dlltool"
    if [ -x "`which $CC`" ]
    then
        echo "\tmake install/MINGW/$CPU..."
        mkdir -p "install/MINGW/$CPU"
        echo "\tbuild install/MINGW/$CPU/WinDivert.dll..."
        $CC $COPTS -c dll/windivert.c -o dll/windivert.o
        $CC $COPTS -o "install/MINGW/$CPU/WinDivert.dll" \
            dll/windivert.o dll/windivert.def -nostdlib $CLIBS
        $STRIP "install/MINGW/$CPU/WinDivert.dll"
        echo "\tbuild install/MINGW/$CPU/WinDivert.lib..."
        $DLLTOOL --dllname install/MINGW/$CPU/WinDivert.dll \
            --def dll/windivert.def \
            --output-lib install/MINGW/$CPU/WinDivert.lib 2>/dev/null
        echo "\tbuild install/MINGW/$CPU/netdump.exe..."
        $CC -s -O2 -Iinclude/ examples/netdump/netdump.c \
            -o "install/MINGW/$CPU/netdump.exe" -lWinDivert \
            -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/netfilter.exe..."
        $CC -s -O2 -Iinclude/ examples/netfilter/netfilter.c \
            -o "install/MINGW/$CPU/netfilter.exe" -lWinDivert \
            -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/passthru.exe..."
        $CC -s -O2 -Iinclude/ examples/passthru/passthru.c \
            -o "install/MINGW/$CPU/passthru.exe" -lWinDivert \
            -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/webfilter.exe..."
        $CC -s -O2 -Iinclude/ examples/webfilter/webfilter.c \
            -o "install/MINGW/$CPU/webfilter.exe" -lWinDivert \
            -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/streamdump.exe..."
        $CC -s -O2 -Iinclude/ examples/streamdump/streamdump.c \
            -o "install/MINGW/$CPU/streamdump.exe" -lWinDivert -lws2_32 \
            -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/flowtrack.exe..."
        $CC -s -O2 -Iinclude/ examples/flowtrack/flowtrack.c \
            -o "install/MINGW/$CPU/flowtrack.exe" -lWinDivert -lpsapi \
            -lshlwapi -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/windivertctl.exe..."
        $CC -s -O2 -Iinclude/ examples/windivertctl/windivertctl.c \
            -o "install/MINGW/$CPU/windivertctl.exe" -lWinDivert \
            -lpsapi -lshlwapi -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/socketdump.exe..."
        $CC -s -O2 -Iinclude/ examples/socketdump/socketdump.c \
            -o "install/MINGW/$CPU/socketdump.exe" -lWinDivert \
            -lpsapi -lshlwapi -L"install/MINGW/$CPU/"
        echo "\tbuild install/MINGW/$CPU/test.exe..."
        $CC -s -O2 -Iinclude/ test/test.c \
            -o "install/MINGW/$CPU/test.exe" -lWinDivert \
            -L"install/MINGW/$CPU/"
        if [ $HAVE_SYS = yes ]
        then
            echo "\tcopy install/MINGW/$CPU/WinDivert$BITS.sys..."
            cp install/MSVC/$CPU/WinDivert$BITS.sys install/MINGW/$CPU
        fi
    else
        echo "WARNING: $CC not found"
    fi
done

