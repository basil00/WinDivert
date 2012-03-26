:: msvc-build.bat
:: (C) 2012, all rights reserved,
::
:: This program is free software: you can redistribute it and/or modify
:: it under the terms of the GNU Lesser General Public License as published by
:: the Free Software Foundation, either version 3 of the License, or
:: (at your option) any later version.
::
:: This program is distributed in the hope that it will be useful,
:: but WITHOUT ANY WARRANTY; without even the implied warranty of
:: MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
:: GNU Lesser General Public License for more details.
::
:: You should have received a copy of the GNU Lesser General Public License
:: along with this program.  If not, see <http://www.gnu.org/licenses/>.
::
:: Script for MSVC (Microsoft Visual Studio 2010) compilation.
:: NOTE: run wddk-build.bat before this script.

@echo off

set WDDK_INSTALL=install\WDDK\i386\
set MSVC_INSTALL=install\MSVC\i386\

if not exist %WDDK_INSTALL% (
    echo ERROR: Missing WDDK build; run wddk-build.bat first
    exit /B
)
mkdir %MSVC_INSTALL%

:: Build WinDivert.dll
cd dll
msbuild
copy /Y Release\WinDivert.dll ..\%MSVC_INSTALL%
copy /Y Release\WinDivert.lib ..\%MSVC_INSTALL%
cd ..

:: Build netdump
cd examples\netdump
msbuild
copy /Y Release\netdump.exe ..\..\%MSVC_INSTALL%
cd ..\..

:: Build netfilter
cd examples\netfilter
msbuild
copy /Y Release\netfilter.exe ..\..\%MSVC_INSTALL%
cd ..\..

:: Build passthru
cd examples\passthru
msbuild
copy /Y Release\passthru.exe ..\..\%MSVC_INSTALL%
cd ..\..

:: Build webfilter
cd examples\webfilter
msbuild
copy /Y Release\webfilter.exe ..\..\%MSVC_INSTALL%
cd ..\..

:: Copy files
copy /Y %WDDK_INSTALL%\WinDivert.sys %MSVC_INSTALL%
copy /Y %WDDK_INSTALL%\WinDivert.inf %MSVC_INSTALL%
copy /Y %WDDK_INSTALL%\WdfCoInstaller*.dll %MSVC_INSTALL%

