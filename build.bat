@echo off

set C_FILES=wait_on_address_test.cpp
set OUTPUT_FILE_NAME=wait_on_address_test
set BUILD_CONFIGURATION=%1
call build_cl.bat

exit /b 0