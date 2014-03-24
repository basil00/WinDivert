:: msvc-build.bat
:: (C) 2014, all rights reserved,
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
:: Script for MSVC (Microsoft Visual Studio 2012) compilation.
:: NOTE: run wddk-build.bat before this script.

@echo off

:: Determine target CPU.

cl 2>&1 | findstr "x86" > NUL

if %ERRORLEVEL% == 0 (
    set TARGET=i386
    set PLATFORM=Win32
    set BITS=32
) ELSE (
    set TARGET=amd64
    set PLATFORM=x64
    set BITS=64
)

set WDDK_INSTALL=install\WDDK\%TARGET%\
set MSVC_INSTALL=install\MSVC\%TARGET%\

if not exist %WDDK_INSTALL% (
    echo ERROR: Missing WDDK build; run wddk-build.bat first
    exit /B
)
mkdir %MSVC_INSTALL%

:: Build WinDivert.dll
cd dll
msbuild /p:Platform=%PLATFORM% /p:OutDir=build\
copy /Y build\WinDivert.dll ..\%MSVC_INSTALL%
copy /Y build\WinDivert.lib ..\%MSVC_INSTALL%
copy /Y build\WinDivert.lib ..\%MSVC_INSTALL%..
rd /s /q build\
cd ..

:: Build netdump
cd examples\netdump
msbuild /p:Platform=%PLATFORM% /p:OutDir=build\
copy /Y build\netdump.exe ..\..\%MSVC_INSTALL%
rd /s /q build\
cd ..\..

:: Build netfilter
cd examples\netfilter
msbuild /p:Platform=%PLATFORM% /p:OutDir=build\
copy /Y build\netfilter.exe ..\..\%MSVC_INSTALL%
rd /s /q build\
cd ..\..

:: Build passthru
cd examples\passthru
msbuild /p:Platform=%PLATFORM% /p:OutDir=build\
copy /Y build\passthru.exe ..\..\%MSVC_INSTALL%
rd /s /q build\
cd ..\..

:: Build webfilter
cd examples\webfilter
msbuild /p:Platform=%PLATFORM% /p:OutDir=build\
copy /Y build\webfilter.exe ..\..\%MSVC_INSTALL%
rd /s /q build\
cd ..\..

:: Copy files
copy /Y %WDDK_INSTALL%\WinDivert%BITS%.sys %MSVC_INSTALL%

:: Clean-up
del %MSVC_INSTALL%..\WinDivert.lib

