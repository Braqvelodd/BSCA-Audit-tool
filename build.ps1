# build.ps1 - Compile and package ISPW-Jira Audit Automator

$ErrorActionPreference = "Stop"

Write-Host "=============================================="
Write-Host "ISPW-Jira Audit Automator Build System (PowerShell)"
Write-Host "=============================================="

# Determine JDK Bin path
$JdkBin = "C:\Program Files\Java\jdk-25\bin"
if (Test-Path "C:\Program Files\Java\jdk21\TSO\bin") {
    $JdkBin = "C:\Program Files\Java\jdk21\TSO\bin"
}

# Verify JDK path
$Javac = Join-Path $JdkBin "javac.exe"
$Jar = Join-Path $JdkBin "jar.exe"

if (!(Test-Path $Javac)) {
    # Check if javac is in the system PATH as a fallback
    $JavacPath = Get-Command javac -ErrorAction SilentlyContinue
    if ($JavacPath) {
        $Javac = $JavacPath.Source
        $Jar = (Get-Command jar -ErrorAction SilentlyContinue).Source
    } else {
        Write-Error "ERROR: Java compiler not found at: '$Javac'. Please ensure JDK is installed."
    }
}

Write-Host "Using JDK Bin: $(Split-Path $Javac)"

# Create directories
if (!(Test-Path "lib")) { New-Item -ItemType Directory -Path "lib" | Out-Null }
if (!(Test-Path "bin")) { New-Item -ItemType Directory -Path "bin" | Out-Null }
if (!(Test-Path "dist")) { New-Item -ItemType Directory -Path "dist" | Out-Null }

# Check/download dependencies
$deps = @{
    "gson-2.10.1.jar" = "https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar"
    "httpclient-4.5.14.jar" = "https://repo1.maven.org/maven2/org/apache/httpcomponents/httpclient/4.5.14/httpclient-4.5.14.jar"
    "httpcore-4.4.16.jar" = "https://repo1.maven.org/maven2/org/apache/httpcomponents/httpcore/4.4.16/httpcore-4.4.16.jar"
    "commons-logging-1.2.jar" = "https://repo1.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar"
    "commons-codec-1.15.jar" = "https://repo1.maven.org/maven2/commons-codec/commons-codec/1.15/commons-codec-1.15.jar"
}

foreach ($dep in $deps.GetEnumerator()) {
    $depPath = Join-Path "lib" $dep.Key
    if (!(Test-Path $depPath)) {
        Write-Host "Downloading $($dep.Key)..."
        Invoke-WebRequest -Uri $dep.Value -OutFile $depPath
    }
}

# Clean bin and dist
Write-Host "Cleaning build directories..."
if (Test-Path "bin") { Remove-Item -Recurse -Force "bin" }
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
New-Item -ItemType Directory -Path "bin" | Out-Null
New-Item -ItemType Directory -Path "dist" | Out-Null

# Unpack external JAR libraries to bin
Write-Host "Unpacking libraries to build a self-contained fat JAR..."
Push-Location "bin"
try {
    & $Jar xf ..\lib\gson-2.10.1.jar
    & $Jar xf ..\lib\httpclient-4.5.14.jar
    & $Jar xf ..\lib\httpcore-4.4.16.jar
    & $Jar xf ..\lib\commons-logging-1.2.jar
    & $Jar xf ..\lib\commons-codec-1.15.jar
} finally {
    Pop-Location
}

# Clean signature files from META-INF
if (Test-Path "bin\META-INF") {
    Remove-Item -Path "bin\META-INF\*.SF", "bin\META-INF\*.DSA", "bin\META-INF\*.RSA" -ErrorAction SilentlyContinue
}

# Compile Java files
Write-Host "Compiling Java files..."
$javaFiles = Get-ChildItem -Path "src" -Filter "*.java" -Recurse | ForEach-Object { $_.FullName }
& $Javac --release 8 -cp "lib/*" -d bin $javaFiles

# Create the JAR file
Write-Host "Creating Fat JAR file..."
& $Jar cvfe dist/ispw-jira-audit-automator.jar com.company.ispwjira.MainApp -C bin . | Out-Null

Write-Host "=============================================="
Write-Host "Build Completed Successfully: dist\ispw-jira-audit-automator.jar"
Write-Host "=============================================="
