::version 1

@echo off
setlocal enableextensions enabledelayedexpansion

set FORCE_SCRIPT_DOWNLOAD=0

if "%1"=="--help" (
    echo This is a script that helps with building c/cpp code.
    echo It will download necessary helper build scripts to help
    echo with finding vcvarsall.bat path.
    echo:
    echo How to use this:
    echo define variables C_FILES, OUTPUT_FILE_NAME, SOURCE_FOLDER, INCLUDE_DIRECTORIES, 
    echo BUILD_CONFIGURATION, OUTPUT_FOLDER, COMPILER_OPTIONS, ^& LINKER_OPTIONS
    echo outside of this script and then call this script.
    echo:
    echo use option "--force-script-download" to force re-download of build scripts
    echo: 
    echo ^(Only C_FILES ^& OUTPUT_FILE_NAME are mandatory^)
    echo Example when calling build_cl.bat from another script^:
    echo:
    echo set C_FILES=test.c 
    echo set OUTPUT_FILE_NAME=test.exe
    echo call build_cl.bat
    exit /b 0
) else if "%1"=="--force-script-download" (
    echo forcing script download...
    set FORCE_SCRIPT_DOWNLOAD=1
)

if "!DEBUG_OUTPUT!"=="" (
    set DEBUG_OUTPUT=0
)

set SCRIPT_DIRECTORY=%~dp0
if "!C_FILES!"=="" (
    echo Variable C_FILES not defined.
    set errorlevel=1
    goto ERROR_FAILURE
)

if "!OUTPUT_FILE_NAME!"=="" (
    echo Variable OUTPUT_FILE_NAME not defined.
    set errorlevel=1
    goto ERROR_FAILURE
)

if "!SOURCE_FOLDER!"=="" (
    set DEFAULT_SOURCE_FOLDER=%dp0%
    set SOURCE_FOLDER=!DEFAULT_SOURCE_FOLDER!

    if !DEBUG_OUTPUT! equ 1 (
        echo Variable SOURCE_FOLDER not defined, using default '!DEFAULT_SOURCE_FOLDER!'
    )
)

if "!BUILD_CONFIGURATION!"=="" (
    set DEFAULT_BUILD_CONFIGURATION=debug
    set BUILD_CONFIGURATION=!DEFAULT_BUILD_CONFIGURATION!

    if !DEBUG_OUTPUT! equ 1 (
        echo Variable BUILD_CONFIGURATION not defined, using default '!DEFAULT_BUILD_CONFIGURATION!'
    )
) else if not "!BUILD_CONFIGURATION!"=="debug" if not "!BUILD_CONFIGURATION!"=="release" (
    echo Wrong build config "!BUILD_CONFIGURATION!", assuming debug build
	set BUILD_CONFIG=debug
)

if "!OUTPUT_FOLDER!"=="" (
    set DEFAULT_OUTPUT_FOLDER=build
    set OUTPUT_FOLDER=!DEFAULT_OUTPUT_FOLDER!

    if !DEBUG_OUTPUT! equ 1 (
        echo Variable OUTPUT_FOLDER not defined, using default '!DEFAULT_OUTPUT_FOLDER!'
    )
)

if "!COMPILER_OPTIONS!"=="" (
    set DEFAULT_COMPILER_OPTIONS=/nologo /FC /TP /W3
    if "!BUILD_CONFIGURATION!"=="debug" (
        set DEFAULT_COMPILER_OPTIONS=!DEFAULT_COMPILER_OPTIONS! /Od /Zi /GS /MTd /std:c++17
    ) else if "!BUILD_CONFIGURATION!"=="release" (
        set DEFAULT_COMPILER_OPTIONS=!DEFAULT_COMPILER_OPTIONS! /O2 /GL /Gw /MT /Zi /DK15_RELEASE_BUILD /std:c++17
    )

    set COMPILER_OPTIONS=!DEFAULT_COMPILER_OPTIONS!

    if !DEBUG_OUTPUT! equ 1 (
        echo Variable COMPILER_OPTIONS not defined, using default '!DEFAULT_COMPILER_OPTIONS!'
    )
)

if "!LINKER_OPTIONS!"=="" (
    set DEFAULT_LINKER_OPTIONS=/SUBSYSTEM:CONSOLE
    set LINKER_OPTIONS=!DEFAULT_LINKER_OPTIONS!

    if !DEBUG_OUTPUT! equ 1 (
        echo Variable LINKER_OPTIONS not defined, using default '!DEFAULT_LINKER_OPTIONS!'
    )
)

set OUTPUT_FOLDER=!SCRIPT_DIRECTORY!!OUTPUT_FOLDER!\!BUILD_CONFIGURATION!

if not exist "!OUTPUT_FOLDER!" (
    echo !OUTPUT_FOLDER! doesn't exist, creating...
    mkdir !OUTPUT_FOLDER!
)

set COMPILER_EXE_PATH_SCRIPT_PATH=!SCRIPT_DIRECTORY!find_cl_exe_path.bat
set VCVARS_PATH_SCRIPT_PATH=!SCRIPT_DIRECTORY!find_vcvars_path.bat
set COMPILER_EXE_REPOSITORY_PATH=https://raw.githubusercontent.com/FelixK15/k15_batch_scripts/main/find_cl_exe_path.bat
set VCVARS_REPOSITORY_PATH=https://raw.githubusercontent.com/FelixK15/k15_batch_scripts/main/find_vcvars_path.bat

set DOWNLOAD_SCRIPT=!FORCE_SCRIPT_DOWNLOAD!
if not exist !COMPILER_EXE_PATH_SCRIPT_PATH! (
    set DOWNLOAD_SCRIPT=1
)

if !DOWNLOAD_SCRIPT! equ 1 (
    ::FK: Download file from github repository
    call bitsadmin.exe /transfer compiler_script_download_job /priority HIGH !COMPILER_EXE_REPOSITORY_PATH! !COMPILER_EXE_PATH_SCRIPT_PATH! !VCVARS_REPOSITORY_PATH! !VCVARS_PATH_SCRIPT_PATH!

    if not ERRORLEVEL 0 (
        echo Error trying to download script from '!COMPILER_EXE_REPOSITORY_PATH!' & '!VCVARS_REPOSITORY_PATH!'. Please check your internet connection.
        set errorlevel=2
        goto ERROR_FAILURE
    )
)

::FK: Populate COMPILER_PATH & ASSEMBLER_PATH env var
call !COMPILER_EXE_PATH_SCRIPT_PATH!

(for %%a in (!C_FILES!) do ( 
   set C_FILES_CONCATENATED="!SCRIPT_DIRECTORY!!SOURCE_FOLDER!%%a" !C_FILES_CONCATENATED!
))

(for %%a in (!INCLUDE_DIRECTORIES!) do ( 
   set INCLUDE_DIRS_CONCATENATED=/I "%%a" !INCLUDE_DIRS_CONCATENATED!
))

echo compiling build configuration !BUILD_CONFIGURATION!...

set COMPILER_OPTIONS=!COMPILER_OPTIONS! !INCLUDE_DIRS_CONCATENATED! /Fe!OUTPUT_FOLDER!\!OUTPUT_FILE_NAME!
set COMPILE_COMMAND="!COMPILER_PATH!" !COMPILER_OPTIONS! !C_FILES_CONCATENATED! /link !LINKER_OPTIONS!
!COMPILE_COMMAND!

if !DEBUG_OUTPUT! equ 1 (
    echo !COMPILE_COMMAND!
)

if not ERRORLEVEL 0 (
    echo build script exited with error !errorlevel!
)

exit /b !errorlevel!

:ERROR_FAILURE
echo build script exited with error !errorlevel!
echo make sure to not call this script directly but rather call it from within another script - "build_cl --help" for more infos