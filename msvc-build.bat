:: msvc-build.bat
:: (C) 2019, all rights reserved,
::
:: This file is part of WinDivert.
::
:: WinDivert is free software: you can redistribute it and/or modify it under
:: the terms of the GNU Lesser General Public License as published by the
:: Free Software Foundation, either version 3 of the License, or (at your
:: option) any later version.
::
:: This program is distributed in the hope that it will be useful, but
:: WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
:: or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
:: License for more details.
::
:: You should have received a copy of the GNU Lesser General Public License
:: along with this program.  If not, see <http://www.gnu.org/licenses/>.
::
:: WinDivert is free software; you can redistribute it and/or modify it under
:: the terms of the GNU General Public License as published by the Free
:: Software Foundation; either version 2 of the License, or (at your option)
:: any later version.
:: 
:: This program is distributed in the hope that it will be useful, but
:: WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
:: or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
:: for more details.
:: 
:: You should have received a copy of the GNU General Public License along
:: with this program; if not, write to the Free Software Foundation, Inc., 51
:: Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

@echo off

msbuild sys\windivert.vcxproj ^
    /p:Configuration=Release ^
    /p:platform=Win32 ^
    /p:SignMode=Off ^
    /p:OutDir=..\install\MSVC\i386\ ^
    /p:AssemblyName=WinDivert32

msbuild sys\windivert.vcxproj ^
    /p:Configuration=Release ^
    /p:platform=x64 ^
    /p:SignMode=Off ^
    /p:OutDir=..\install\MSVC\amd64\ ^
    /p:AssemblyName=WinDivert64

msbuild dll\windivert.vcxproj ^
    /p:Configuration=Release ^
    /p:platform=Win32 ^
    /p:OutDir=..\install\MSVC\i386\
move dll\WinDivert.lib install\MSVC\i386\.

msbuild dll\windivert.vcxproj ^
    /p:Configuration=Release ^
    /p:platform=x64 ^
    /p:OutDir=..\install\MSVC\amd64\
move dll\WinDivert.lib install\MSVC\amd64\.

msbuild examples\flowtrack\flowtrack.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=Win32 ^
    /p:OutDir=..\..\install\MSVC\i386\

msbuild examples\flowtrack\flowtrack.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\install\MSVC\amd64\

msbuild examples\netdump\netdump.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=Win32 ^
    /p:OutDir=..\..\install\MSVC\i386\

msbuild examples\netdump\netdump.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\install\MSVC\amd64\

msbuild examples\netfilter\netfilter.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=Win32 ^
    /p:OutDir=..\..\install\MSVC\i386\

msbuild examples\netfilter\netfilter.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\install\MSVC\amd64\

msbuild examples\passthru\passthru.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=Win32 ^
    /p:OutDir=..\..\install\MSVC\i386\

msbuild examples\passthru\passthru.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\install\MSVC\amd64\

msbuild examples\socketdump\socketdump.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=Win32 ^
    /p:OutDir=..\..\install\MSVC\i386\

msbuild examples\socketdump\socketdump.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\install\MSVC\amd64\

msbuild examples\streamdump\streamdump.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=Win32 ^
    /p:OutDir=..\..\install\MSVC\i386\

msbuild examples\streamdump\streamdump.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\install\MSVC\amd64\

msbuild examples\webfilter\webfilter.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=Win32 ^
    /p:OutDir=..\..\install\MSVC\i386\

msbuild examples\webfilter\webfilter.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\install\MSVC\amd64\

msbuild examples\windivertctl\windivertctl.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=Win32 ^
    /p:OutDir=..\..\install\MSVC\i386\

msbuild examples\windivertctl\windivertctl.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\install\MSVC\amd64\

msbuild test\test.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=Win32 ^
    /p:OutDir=..\install\MSVC\i386\

msbuild test\test.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\install\MSVC\amd64\

