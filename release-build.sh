#!/bin/bash
#
# release-build.sh
# (C) 2011, all rights reserved,
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Script for building WinDivert binary packages.  This script assumes the
# binaries are already built and are in the install/ subdirectory.

set -e

echo -n "COPYING FILES..."
INSTALL=install/divert
mkdir -p $INSTALL
cp LICENSE $INSTALL
cp sys/divert.inf $INSTALL
cp include/divert.h $INSTALL
mkdir -p $INSTALL/x86
cp install/i386/divert.sys $INSTALL/x86
cp install/i386/WdfCoInstaller01009.dll $INSTALL/x86
mkdir -p $INSTALL/amd64
cp install/amd64/divert.sys $INSTALL/amd64
cp install/amd64/WdfCoInstaller01009.dll $INSTALL/amd64
echo "DONE"

PACKAGE=divert-msvc.tar.gz
echo -n "BUILDING $PACKAGE..."
cp install/i386/divert.lib $INSTALL/x86
cp install/i386/divert.dll $INSTALL/x86
cp install/amd64/divert.lib $INSTALL/amd64
cp install/amd64/divert.dll $INSTALL/amd64
(cd install; tar cvz --owner root --group root -f $PACKAGE divert > /dev/null)
echo "DONE"

PACKAGE=divert-msvc.zip
echo -n "BUILDING $PACKAGE..."
(cd install; zip -r $PACKAGE divert > /dev/null)
echo "DONE"

rm $INSTALL/x86/divert.lib $INSTALL/amd64/divert.lib

PACKAGE=divert-mingw.tar.gz
echo -n "BUILDING $PACKAGE..."
cp install/i586-mingw32msvc/divert.dll $INSTALL/x86
cp install/amd64-mingw32msvc/divert.dll $INSTALL/amd64
(cd install; tar cvz --owner root --group root -f $PACKAGE divert > /dev/null)
echo "DONE"

PACKAGE=divert-mingw.zip
echo -n "BUILDING $PACKAGE..."
(cd install; zip -r $PACKAGE divert > /dev/null)
echo "DONE"

echo -n "CLEANING UP..."
rm -rf $INSTALL
echo "DONE"

