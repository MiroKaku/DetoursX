@echo off
pushd "%~dp0"

if exist build rd /s /q build

"%PROGRAMFILES(x86)%\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\msbuild.exe" /p:Configuration=Release /p:Platform=x64 ..\..\msvc\DetoursX.sln -t:DetoursX
"%PROGRAMFILES(x86)%\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\msbuild.exe" /p:Configuration=Release /p:Platform=x86 ..\..\msvc\DetoursX.sln -t:DetoursX

:exit
popd
@echo on
