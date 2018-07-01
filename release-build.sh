#!/bin/bash
#
# release-build.sh
# (C) 2018, all rights reserved,
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
#
# Script for building WinDivert binary packages.  This script assumes the
# binaries are already built and are in the install/ subdirectory.

set -e

VERSION=`cat ./VERSION`
NAME=WinDivert-$VERSION

for TARGET in WDDK MSVC MINGW
do
    if [ ! -d "install/$TARGET" ]
    then
        echo "SKIP $NAME-$TARGET"
        continue
    fi
    echo "BUILD $NAME-$TARGET"
    INSTALL=install/$NAME-$TARGET
    echo "\tmake $INSTALL..."
    mkdir -p $INSTALL
    echo "\tcopy $INSTALL/README..."
    cp README $INSTALL
    echo "\tcopy $INSTALL/CHANGELOG..."
    cp CHANGELOG $INSTALL
    echo "\tcopy $INSTALL/LICENSE..."
    cp LICENSE $INSTALL
    echo "\tcopy $INSTALL/VERSION..."
    cp VERSION $INSTALL
    echo "\tmake $INSTALL/include..."
    mkdir -p $INSTALL/include
    echo "\tcopy $INSTALL/include/windivert.h..."
    cp include/windivert.h $INSTALL/include
    echo "\tmake $INSTALL/doc..."
    mkdir -p $INSTALL/doc
    echo "\tcopy $INSTALL/doc/WinDivert.html..."
    cp doc/windivert.html $INSTALL/doc/WinDivert.html
    echo "\tmake $INSTALL/x86..."
    mkdir -p $INSTALL/x86
    echo "\tcopy $INSTALL/x86/WinDivert32.sys..."
    cp install/$TARGET/i386/WinDivert32.sys $INSTALL/x86
    if ! grep "DigiCert High Assurance EV Root" $INSTALL/x86/WinDivert32.sys \
        2>&1 >/dev/null
    then
        echo "\t\033[33mWARNING\033[0m: unsigned WinDivert32.sys..."
    fi
    echo "\tcopy $INSTALL/x86/WinDivert.lib..."
    cp install/$TARGET/i386/WinDivert.lib $INSTALL/x86
    echo "\tcopy $INSTALL/x86/WinDivert.dll..."
    cp install/$TARGET/i386/WinDivert.dll $INSTALL/x86
    echo "\tcopy $INSTALL/x86/netdump.exe..."
    cp install/$TARGET/i386/netdump.exe $INSTALL/x86
    echo "\tcopy $INSTALL/x86/netfilter.exe..."
    cp install/$TARGET/i386/netfilter.exe $INSTALL/x86
    echo "\tcopy $INSTALL/x86/passtru.exe..."
    cp install/$TARGET/i386/passthru.exe $INSTALL/x86
    echo "\tcopy $INSTALL/x86/webfilter.exe..."
    cp install/$TARGET/i386/webfilter.exe $INSTALL/x86
    echo "\tcopy $INSTALL/x86/streamdump.exe..."
    cp install/$TARGET/i386/streamdump.exe $INSTALL/x86
    if [ -d "install/$TARGET/amd64" ]
    then
        echo "\tmake $INSTALL/amd64..."
        mkdir -p $INSTALL/amd64
        echo "\tcopy $INSTALL/amd64/WinDivert64.sys..."
        cp install/$TARGET/amd64/WinDivert64.sys $INSTALL/amd64
        if ! grep "DigiCert High Assurance EV Root" \
            $INSTALL/amd64/WinDivert64.sys 2>&1 >/dev/null
        then
            echo -e "\t\033[33mWARNING\033[0m: unsigned WinDivert64.sys..."
        fi
        echo "\tcopy $INSTALL/amd64/WinDivert.lib..."
        cp install/$TARGET/amd64/WinDivert.lib $INSTALL/amd64
        echo "\tcopy $INSTALL/amd64/WinDivert.dll..."
        cp install/$TARGET/amd64/WinDivert.dll $INSTALL/amd64
        echo "\tcopy $INSTALL/amd64/netdump.exe..."
        cp install/$TARGET/amd64/netdump.exe $INSTALL/amd64
        echo "\tcopy $INSTALL/amd64/netfilter.exe..."
        cp install/$TARGET/amd64/netfilter.exe $INSTALL/amd64
        echo "\tcopy $INSTALL/amd64/passtru.exe..."
        cp install/$TARGET/amd64/passthru.exe $INSTALL/amd64
        echo "\tcopy $INSTALL/amd64/webfilter.exe..."
        cp install/$TARGET/amd64/webfilter.exe $INSTALL/amd64
        echo "\tcopy $INSTALL/amd64/streamdump.exe..."
        cp install/$TARGET/amd64/streamdump.exe $INSTALL/amd64
    else
        echo "\tWARNING: skipping missing AMD64 build..."
    fi
    PACKAGE=$NAME-$TARGET.tar.gz
    echo "\tbuilding $PACKAGE..."
    (
        cd install;
        tar cvz --owner root --group root -f $PACKAGE $NAME-$TARGET > /dev/null
    )
    PACKAGE=$NAME-$TARGET.zip
    echo "\tbuilding $PACKAGE..."
    (
        cd install;
        zip -r $PACKAGE $NAME-$TARGET > /dev/null
    )
    echo -n "\tclean $INSTALL..."
    rm -rf $INSTALL
    echo "DONE"
done

