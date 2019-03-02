#!/bin/bash
#
# build.sh
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
#
# Script for MinGW/Linux cross compilation.
# NOTE: run wddk-build.bat before this script.

CC=i686-w64-mingw32-gcc
$CC -fno-ident -s -O2 -I../include/ test.c \
    -o ../install/MINGW/i386/test.exe -lWinDivert -L"../install/MINGW/i386/" 

CC=x86_64-w64-mingw32-gcc
$CC -fno-ident -s -O2 -I../include/ test.c -o ../install/MINGW/amd64/test.exe \
    -lWinDivert -L"../install/MINGW/amd64/"

