#!/bin/bash
#
# build.sh
# (C) 2016, all rights reserved,
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

CC=x86_64-w64-mingw32-gcc

$CC -s -O2 -I../include/ test.c -o test.exe -lWinDivert \
    -L"../install/MINGW/amd64/"

