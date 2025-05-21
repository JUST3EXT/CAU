@ECHO OFF
set TEST_START_TIME=%TIME%
ECHO.
ECHO ======================================================
ECHO          CAUJUS_dev.bat Unit Test Runner
ECHO ======================================================
ECHO.

:: Test Setup
:: ======================================================
ECHO Setting up test environment...

SET AD_ORIGINAL=%AD%
SET COMPUTERNAME_ORIGINAL=%COMPUTERNAME%
SET RUTA_LOG_ORIGINAL=%ruta_log%

SET AD=TESTUSER
SET COMPUTERNAME=TESTPC
SET "ruta_log_test_base=%~dp0test_logs"
SET "CAUJUS_SCRIPT_PATH=%~dp0CAUJUS_dev.bat"

:: Determine MonthlyFolder (same logic as in CAUJUS_dev.bat)
ECHO Determining MonthlyFolder for test setup...
for /f "tokens=2 delims==" %%a in ('wmic os get LocalDateTime /value') do set test_datetime=%%a
if not defined test_datetime (
    ECHO ERROR: Failed to get LocalDateTime from WMIC for test setup.
    set test_datetime=00000000000000.000000+000
)
set "TEST_YY=%test_datetime:~2,2%"
set "TEST_MesNum=%test_datetime:~4,2%"

if "%TEST_MesNum%"=="01" set "TEST_MesNombre=ene"
if "%TEST_MesNum%"=="02" set "TEST_MesNombre=feb"
if "%TEST_MesNum%"=="03" set "TEST_MesNombre=mar"
if "%TEST_MesNum%"=="04" set "TEST_MesNombre=abr"
if "%TEST_MesNum%"=="05" set "TEST_MesNombre=may"
if "%TEST_MesNum%"=="06" set "TEST_MesNombre=jun"
if "%TEST_MesNum%"=="07" set "TEST_MesNombre=jul"
if "%TEST_MesNum%"=="08" set "TEST_MesNombre=ago"
if "%TEST_MesNum%"=="09" set "TEST_MesNombre=sep"
if "%TEST_MesNum%"=="10" set "TEST_MesNombre=oct"
if "%TEST_MesNum%"=="11" set "TEST_MesNombre=nov"
if "%TEST_MesNum%"=="12" set "TEST_MesNombre=dic"
if not defined TEST_MesNombre (
    ECHO ERROR: TEST_MesNombre could not be determined. Defaulting to 'MES_DESCONOCIDO_TEST'.
    set "TEST_MesNombre=MES_DESCONOCIDO_TEST"
)
set "MonthlyFolder=%TEST_MesNombre%_%TEST_YY%"
ECHO MonthlyFolder determined as: %MonthlyFolder%
ECHO.

SET "TEST_LOG_FILE_DIR=%ruta_log_test_base%\%MonthlyFolder%"
SET "TEST_LOG_FILE=%TEST_LOG_FILE_DIR%\%AD%_%COMPUTERNAME%.log"

:: Override ruta_log for the CAUJUS_dev.bat script to use the base test log directory
SET "ruta_log=%ruta_log_test_base%"

ECHO Test User (AD): %AD%
ECHO Test PC (COMPUTERNAME): %COMPUTERNAME%
ECHO Base Test Log Path (ruta_log_test_base): %ruta_log_test_base%
ECHO Monthly Test Log Directory (TEST_LOG_FILE_DIR): %TEST_LOG_FILE_DIR%
ECHO Script to Test: %CAUJUS_SCRIPT_PATH%
ECHO Expected Log File: %TEST_LOG_FILE%
ECHO CAUJUS_dev.bat will use ruta_log: %ruta_log%
ECHO.

ECHO Creating base test log directory if it doesn't exist...
IF NOT EXIST "%ruta_log_test_base%" (
    MKDIR "%ruta_log_test_base%"
    IF ERRORLEVEL 1 (
        ECHO FAILED to create base test log directory: %ruta_log_test_base%
        GOTO TeardownAndExit
    ) ELSE (
        ECHO Base test log directory created: %ruta_log_test_base%
    )
) ELSE (
    ECHO Base test log directory already exists: %ruta_log_test_base%
)
ECHO.

ECHO Creating monthly test log directory if it doesn't exist: %TEST_LOG_FILE_DIR%
IF NOT EXIST "%TEST_LOG_FILE_DIR%" (
    MKDIR "%TEST_LOG_FILE_DIR%"
    IF ERRORLEVEL 1 (
        ECHO FAILED to create monthly test log directory: %TEST_LOG_FILE_DIR%
        GOTO TeardownAndExit
    ) ELSE (
        ECHO Monthly test log directory created: %TEST_LOG_FILE_DIR%
    )
) ELSE (
    ECHO Monthly test log directory already exists: %TEST_LOG_FILE_DIR%
)
ECHO.

ECHO Cleaning up previous test log file (if any)...
IF EXIST "%TEST_LOG_FILE%" (
    DEL /Q "%TEST_LOG_FILE%"
    ECHO Previous test log file deleted: %TEST_LOG_FILE%
) ELSE (
    ECHO No previous test log file to delete.
)
ECHO.
ECHO Setup complete.
ECHO ======================================================
ECHO.

:: Test Cases
:: ======================================================

:: Test Case 1: Initial Log Entry via --test-logging
ECHO Running Test Case 1: Basic Log Functionality Test
ECHO   Purpose: Verify that CAUJUS_dev.bat creates a log entry when called with --test-logging.
ECHO   Action: Calling CAUJUS_dev.bat --test-logging
ECHO ------------------------------------------------------
CALL "%CAUJUS_SCRIPT_PATH%" --test-logging
IF ERRORLEVEL 1 (
    ECHO Test Case 1 FAILED: CAUJUS_dev.bat --test-logging returned an error.
    GOTO TeardownAndExit
)

ECHO Verifying log content for Test Case 1...
IF NOT EXIST "%TEST_LOG_FILE%" (
    ECHO Test Case 1 FAILED: Log file not found at %TEST_LOG_FILE%
    GOTO TeardownAndExit
)

FINDSTR /C:"Test log entry from --test-logging mode" "%TEST_LOG_FILE%" >NUL
IF ERRORLEVEL 0 (
    ECHO Test Case 1 PASSED: Found expected log entry "Test log entry from --test-logging mode".
) ELSE (
    ECHO Test Case 1 FAILED: Did not find "Test log entry from --test-logging mode" in %TEST_LOG_FILE%
    ECHO Log content:
    TYPE "%TEST_LOG_FILE%"
)
ECHO ------------------------------------------------------
ECHO.

:: Add more test cases here if needed

:: Teardown and Exit
:: ======================================================
:TeardownAndExit
ECHO.
ECHO Restoring original environment variables...
SET AD=%AD_ORIGINAL%
SET COMPUTERNAME=%COMPUTERNAME_ORIGINAL%
SET ruta_log=%RUTA_LOG_ORIGINAL%

IF DEFINED AD_ORIGINAL (SET AD_ORIGINAL=)
IF DEFINED COMPUTERNAME_ORIGINAL (SET COMPUTERNAME_ORIGINAL=)
IF DEFINED RUTA_LOG_ORIGINAL (SET RUTA_LOG_ORIGINAL=)
IF DEFINED TEST_YY (SET TEST_YY=)
IF DEFINED TEST_MesNum (SET TEST_MesNum=)
IF DEFINED TEST_MesNombre (SET TEST_MesNombre=)
IF DEFINED MonthlyFolder (SET MonthlyFolder=)
IF DEFINED test_datetime (SET test_datetime=)


ECHO.
ECHO ======================================================
ECHO                    Testing Finished
ECHO ======================================================
ECHO.

set TEST_END_TIME=%TIME%
set /A T_START_H=1%TEST_START_TIME:~0,2% - 100
set /A T_START_M=1%TEST_START_TIME:~3,2% - 100
set /A T_START_S=1%TEST_START_TIME:~6,2% - 100
set /A T_START_CS=1%TEST_START_TIME:~9,2% - 100
set /A T_START_TOTAL_CS=(%T_START_H%*360000) + (%T_START_M%*6000) + (%T_START_S%*100) + %T_START_CS%

set /A T_END_H=1%TEST_END_TIME:~0,2% - 100
set /A T_END_M=1%TEST_END_TIME:~3,2% - 100
set /A T_END_S=1%TEST_END_TIME:~6,2% - 100
set /A T_END_CS=1%TEST_END_TIME:~9,2% - 100
set /A T_END_TOTAL_CS=(%T_END_H%*360000) + (%T_END_M%*6000) + (%T_END_S%*100) + %T_END_CS%

IF %T_END_TOTAL_CS% LSS %T_START_TOTAL_CS% (
    set /A T_END_TOTAL_CS = %T_END_TOTAL_CS% + (24 * 360000)
)
set /A T_DURATION_CS=%T_END_TOTAL_CS% - %T_START_TOTAL_CS%

set /A T_DURATION_S = %T_DURATION_CS% / 100
set /A T_DURATION_DEC = %T_DURATION_CS% %% 100
IF %T_DURATION_DEC% LSS 10 set T_DURATION_DEC=0%T_DURATION_DEC%

set /A T_DURATION_M = %T_DURATION_S% / 60
set /A T_DURATION_S_REM = %T_DURATION_S% %% 60
IF %T_DURATION_S_REM% LSS 10 set T_DURATION_S_REM=0%T_DURATION_S_REM%

set /A T_DURATION_H = %T_DURATION_M% / 60
set /A T_DURATION_M_REM = %T_DURATION_M% %% 60
IF %T_DURATION_M_REM% LSS 10 set T_DURATION_M_REM=0%T_DURATION_M_REM%

ECHO Total test script execution time: %T_DURATION_H%:%T_DURATION_M_REM%:%T_DURATION_S_REM%.%T_DURATION_DEC%
ECHO.

EXIT /B %ERRORLEVEL%
