#!/bin/bash
#
# (C) 2012, all rights reserved,
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

# Script for building WinDivert binary packages.  This script assumes the
# binaries are already built and are in the install/ subdirectory.

set -e

VERSION=1.0
NAME=WinDivert-$VERSION

echo -n "COPYING FILES..."
INSTALL=install/$NAME
mkdir -p $INSTALL
cp README $INSTALL
cp LICENSE $INSTALL
cp sys/divert.inf $INSTALL/WinDivert.inf
cp include/divert.h $INSTALL
mkdir -p $INSTALL/x86
cp install/i386/WinDivert.sys $INSTALL/x86
cp install/i386/WdfCoInstaller01009.dll $INSTALL/x86
mkdir -p $INSTALL/amd64
cp install/amd64/WinDivert.sys $INSTALL/amd64
cp install/amd64/WdfCoInstaller01009.dll $INSTALL/amd64
echo "DONE"

PACKAGE=$NAME-MSVC.tar.gz
echo -n "BUILDING $PACKAGE..."
cp install/i386/WinDivert.dll $INSTALL/x86
cp install/amd64/WinDivert.dll $INSTALL/amd64
(cd install; tar cvz --owner root --group root -f $PACKAGE $NAME > /dev/null)
echo "DONE"

PACKAGE=$NAME-MSVC.zip
echo -n "BUILDING $PACKAGE..."
(cd install; zip -r $PACKAGE $NAME > /dev/null)
echo "DONE"

PACKAGE=$NAME-MinGW.tar.gz
echo -n "BUILDING $PACKAGE..."
cp install/i586-mingw32msvc/WinDivert.dll $INSTALL/x86
cp install/amd64-mingw32msvc/WinDivert.dll $INSTALL/amd64
(cd install; tar cvz --owner root --group root -f $PACKAGE $NAME > /dev/null)
echo "DONE"

PACKAGE=$NAME-MinGW.zip
echo -n "BUILDING $PACKAGE..."
(cd install; zip -r $PACKAGE $NAME > /dev/null)
echo "DONE"

echo -n "CLEANING UP..."
rm -rf $INSTALL
echo "DONE"

