#!/bin/bash
#
# build.sh
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

# Script for MinGW/Linux cross compilation.
# NOTE: This script only builds divert.dll, not the driver divert.sys

ENVS="i586-mingw32msvc amd64-mingw32msvc"

for ENV in $ENVS
do
    CC="$ENV-gcc"
    if [ -x "`which $CC`" ]
    then
        mkdir -p "install/$ENV"
        echo "$CC -O2 -Iinclude/ -c divert.o dll/divert.c"
        $CC -O2 -Iinclude/ -c divert.o dll/divert.c
        echo "$CC -shared -o install/$ENV/divert.dll divert.o"
        $CC -shared -o "install/$ENV/divert.dll" divert.o 
    else
        echo "$CC: not found"
    fi
done

