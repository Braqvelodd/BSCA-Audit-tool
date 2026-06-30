@echo off
setlocal enabledelayedexpansion

:: Find JRE 8 java.exe dynamically
set "JAVA8_EXE="
for /d %%d in ("C:\Program Files (x86)\Java\jre1.8.*" "C:\Program Files\Java\jre1.8.*" "C:\Program Files (x86)\Java\jdk1.8.*" "C:\Program Files\Java\jdk1.8.*") do (
    if exist "%%d\bin\java.exe" (
        set "JAVA8_EXE=%%d\bin\java.exe"
        goto :found_java
    )
    if exist "%%d\jre\bin\java.exe" (
        set "JAVA8_EXE=%%d\jre\bin\java.exe"
        goto :found_java
    )
)

:found_java
if not defined JAVA8_EXE (
    echo ERROR: Oracle JRE 8 java.exe was not found on your system.
    echo Please make sure Oracle JRE 8 (1.8) is installed.
    pause
    exit /b 1
)

if not exist dist\ispw-jira-audit-automator.jar (
    echo ERROR: Application jar not found. Please run compileandbuild.bat first.
    pause
    exit /b 1
)

echo Starting ISPW-Jira Audit Automator using: "%JAVA8_EXE%"
"%JAVA8_EXE%" -jar dist\ispw-jira-audit-automator.jar
if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: Application exited with error code: %ERRORLEVEL%
    pause
)
