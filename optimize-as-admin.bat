@echo off
REM tangerine launcher (Windows) -- run the tool with administrator rights.
REM
REM Probing needs no privileges, but writing the hosts file does. This script
REM re-launches itself through a UAC prompt and then runs the tool.
REM
REM Usage:
REM   optimize-as-admin.bat                                   run "optimize"
REM   optimize-as-admin.bat --dry-run                         measure, write nothing
REM   optimize-as-admin.bat --domains github.com --rounds 5   any tangerine flag
REM   optimize-as-admin.bat restore --write                   undo (also needs admin)
REM
REM Accepts a subcommand as the first argument; without one it defaults to
REM "optimize".
REM
REM Keep this file in CRLF. cmd.exe mis-parses LF-only batch files.
setlocal EnableExtensions

REM Capture our own path and the raw argument list up front, before anything
REM can disturb them.
set "SELF=%~f0"
set "TOOL=%~dp0tangerine.py"

if not exist "%TOOL%" (
    echo error: %TOOL% not found.
    echo        keep optimize-as-admin.bat and tangerine.py in the same directory.
    exit /b 1
)

REM --- locate a Python interpreter -------------------------------------------
set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
    echo error: no Python found on PATH.
    echo        install it from https://www.python.org/downloads/
    exit /b 1
)

REM --- work out which subcommand to run --------------------------------------
REM Deliberately no SHIFT here. SHIFT rewrites %0 and %* as well, which once
REM corrupted %~f0 into the first argument and broke the relaunch path.
REM Instead: recognise %~1, then forward the original argument list untouched.
set "SUB="
if /i "%~1"=="resolve"  set "SUB=resolve"
if /i "%~1"=="probe"    set "SUB=probe"
if /i "%~1"=="optimize" set "SUB=optimize"
if /i "%~1"=="restore"  set "SUB=restore"
if /i "%~1"=="show"     set "SUB=show"

REM With a subcommand, forward the arguments verbatim. Without one, prepend
REM the default so the tool gets a subcommand either way.
set "FORWARD=optimize %*"
if defined SUB set "FORWARD=%*"
set "LABEL=%SUB%"
if not defined LABEL set "LABEL=optimize"

REM --- already elevated? just run -------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    echo   command : %FORWARD%
    echo   tool    : %TOOL%
    echo   target  : %SystemRoot%\System32\drivers\etc\hosts
    echo.
    REM %FORWARD% and %SELF% must both be passed on, otherwise the flags are
    REM lost the moment the UAC prompt appears.
    powershell -NoProfile -Command "Start-Process -FilePath '%SELF%' -Verb RunAs -ArgumentList '%FORWARD%'"
    exit /b
)

echo Running tangerine %LABEL% as administrator...
echo.
%PY% "%TOOL%" %FORWARD%
echo.
pause
