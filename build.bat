@echo off
echo ==============================================
echo ISPW-Jira Audit Automator Build System
echo ==============================================

:: Create directories
if not exist lib mkdir lib
if not exist bin mkdir bin
if not exist dist mkdir dist

:: Download dependencies if missing
echo Checking dependencies in lib...

if not exist lib\gson-2.10.1.jar (
    echo Downloading Gson...
    powershell -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar' -OutFile 'lib\gson-2.10.1.jar'"
)
if not exist lib\httpclient-4.5.14.jar (
    echo Downloading HttpClient...
    powershell -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/org/apache/httpcomponents/httpclient/4.5.14/httpclient-4.5.14.jar' -OutFile 'lib\httpclient-4.5.14.jar'"
)
if not exist lib\httpcore-4.4.16.jar (
    echo Downloading HttpCore...
    powershell -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/org/apache/httpcomponents/httpcore/4.4.16/httpcore-4.4.16.jar' -OutFile 'lib\httpcore-4.4.16.jar'"
)
if not exist lib\commons-logging-1.2.jar (
    echo Downloading Commons Logging...
    powershell -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar' -OutFile 'lib\commons-logging-1.2.jar'"
)
if not exist lib\commons-codec-1.15.jar (
    echo Downloading Commons Codec...
    powershell -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/commons-codec/commons-codec/1.15/commons-codec-1.15.jar' -OutFile 'lib\commons-codec-1.15.jar'"
)

:: Clean bin and dist
echo Cleaning build directories...
if exist bin rmdir /S /Q bin
if exist dist rmdir /S /Q dist
mkdir bin
mkdir dist

:: Unpack external JAR libraries into bin directory
echo Unpacking libraries to build a self-contained fat JAR...
cd bin
jar xf ..\lib\gson-2.10.1.jar
if errorlevel 1 (
    echo ERROR: Failed to unpack gson-2.10.1.jar
    cd ..
    goto :error_exit
)
jar xf ..\lib\httpclient-4.5.14.jar
if errorlevel 1 (
    echo ERROR: Failed to unpack httpclient-4.5.14.jar
    cd ..
    goto :error_exit
)
jar xf ..\lib\httpcore-4.4.16.jar
if errorlevel 1 (
    echo ERROR: Failed to unpack httpcore-4.4.16.jar
    cd ..
    goto :error_exit
)
jar xf ..\lib\commons-logging-1.2.jar
if errorlevel 1 (
    echo ERROR: Failed to unpack commons-logging-1.2.jar
    cd ..
    goto :error_exit
)
jar xf ..\lib\commons-codec-1.15.jar
if errorlevel 1 (
    echo ERROR: Failed to unpack commons-codec-1.15.jar
    cd ..
    goto :error_exit
)
cd ..

:: Clean signature files from META-INF to avoid security errors in fat JAR
del /Q /S bin\META-INF\*.SF bin\META-INF\*.DSA bin\META-INF\*.RSA >nul 2>&1

:: Check for javac and jar tools
where javac >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: The Java compiler 'javac' was not found on your system PATH.
    echo Please make sure a JDK is installed and added to your system PATH.
    goto :error_exit
)

where jar >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: The Java packager 'jar' was not found on your system PATH.
    echo Please make sure the JDK binary directory is added to your system PATH.
    goto :error_exit
)

:: Compile sources targeting Java 8
echo Compiling source files...
javac --release 8 -cp "lib\*" -d bin src\com\company\ispwjira\*.java >nul 2>&1
if errorlevel 1 (
    javac -source 1.8 -target 1.8 -cp "lib\*" -d bin src\com\company\ispwjira\*.java
    if errorlevel 1 (
        echo ERROR: Compilation failed!
        goto :error_exit
    )
)

:: Create MANIFEST.MF
echo Creating Manifest...
(
echo Manifest-Version: 1.0
echo Main-Class: com.company.ispwjira.MainApp
) > dist\MANIFEST.MF

:: Package executable JAR
echo Packaging Fat JAR...
jar cfm dist\ispw-jira-audit-automator.jar dist\MANIFEST.MF -C bin .
if errorlevel 1 (
    echo ERROR: Packaging failed!
    goto :error_exit
)

del dist\MANIFEST.MF
echo ==============================================
echo Build Completed Successfully: dist\ispw-jira-audit-automator.jar
echo ==============================================
pause
exit /b 0

:error_exit
echo ==============================================
echo BUILD FAILED!
echo ==============================================
pause
exit /b 1
