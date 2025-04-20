@echo off
setlocal EnableDelayedExpansion
mode con cols=80 lines=25

::============================================================================
::
::   IDM Activation Script (Enhanced Version)
::
::   By MasterHunter
::   https://masterhunterr.github.io/ck/
::
::   ⭐ ALL free for you ⭐
::
::============================================================================

:: Set Path variable
set "PATH=%SystemRoot%\System32;%SystemRoot%\System32\wbem;%SystemRoot%\System32\WindowsPowerShell\v1.0\"
if exist "%SystemRoot%\Sysnative\reg.exe" (
set "PATH=%SystemRoot%\Sysnative;%SystemRoot%\Sysnative\wbem;%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\;%PATH%"
)

:: Re-launch with admin privileges if needed
fltmc >nul 2>&1 || (
powershell -command "Start-Process -Verb RunAs -FilePath '%~f0'" >nul 2>&1
echo This script requires admin privileges.
echo Please run it as administrator.
pause
exit /b
)

:: Set variables
set "nul=>nul 2>&1"
set psc=powershell.exe

:: Get user account SID
set _sid=
for /f "delims=" %%a in ('%psc% "([System.Security.Principal.NTAccount](Get-WmiObject -Class Win32_ComputerSystem).UserName).Translate([System.Security.Principal.SecurityIdentifier]).Value" 2^>nul') do (set _sid=%%a)

:: Set architecture specific variables
for /f "skip=2 tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PROCESSOR_ARCHITECTURE') do set arch=%%b
if /i not "%arch%"=="x86" set arch=x64

if "%arch%"=="x86" (
    set "CLSID=HKCU\Software\Classes\CLSID"
    set "CLSID2=HKU\%_sid%\Software\Classes\CLSID"
    set "HKLM=HKLM\Software\Internet Download Manager"
) else (
    set "CLSID=HKCU\Software\Classes\Wow6432Node\CLSID"
    set "CLSID2=HKU\%_sid%\Software\Classes\Wow6432Node\CLSID"
    set "HKLM=HKLM\SOFTWARE\Wow6432Node\Internet Download Manager"
)

:: Find IDM path
for /f "tokens=2*" %%a in ('reg query "HKU\%_sid%\Software\DownloadManager" /v ExePath 2^>nul') do call set "IDMan=%%b"

if not exist "%IDMan%" (
    if %arch%==x64 set "IDMan=%ProgramFiles(x86)%\Internet Download Manager\IDMan.exe"
    if %arch%==x86 set "IDMan=%ProgramFiles%\Internet Download Manager\IDMan.exe"
)

if not exist %SystemRoot%\Temp md %SystemRoot%\Temp
set "idmcheck=tasklist /fi "imagename eq idman.exe" | findstr /i "idman.exe" >nul"

:: Check HKCU sync with HKU
set HKCUsync=$null
reg add HKCU\IDM_TEST %nul%
reg query HKU\%_sid%\IDM_TEST %nul% && (
    set HKCUsync=1
)
reg delete HKCU\IDM_TEST /f %nul%
reg delete HKU\%_sid%\IDM_TEST /f %nul%

:MainMenu
cls
title IDM Activation Script by MasterHunter

echo.
echo +-------------------------------------+
echo ^|       ALL free for you            ^|
echo ^|                                   ^|
echo ^|      IDM ACTIVATION OPTIONS       ^|
echo ^|                                   ^|
echo ^|         By MasterHunter           ^|
echo +-------------------------------------+
echo.
echo  1. Activate IDM
echo  2. Freeze Trial
echo  3. Reset Activation/Trial
echo  4. Activate and Freeze (Recommended)
echo  5. Visit MasterHunter Website

echo  0. Exit
echo.
echo  Note: Option 5 is recommended for maximum protection
echo        against fake registration screens.
echo.

choice /C:123450 /N /M "Enter your choice (1, 2, 3, 4, 5 or 0): "
set _erl=%errorlevel%

if %_erl%==6 exit /b
if %_erl%==4 (set frz=1&set combo=1&goto :_activate)
if %_erl%==5 start https://masterhunterr.github.io/ck/ & goto :MainMenu
if %_erl%==3 goto _reset
if %_erl%==2 (set frz=1&set combo=0&goto :_activate)
if %_erl%==1 (set frz=0&set combo=0&goto :_activate)
goto :MainMenu

::========================================================================================================================================

:_reset
cls
echo.
echo +----------------------------------+
echo ^|   RESETTING IDM ACTIVATION/TRIAL  ^|
echo +----------------------------------+
echo.

%idmcheck% && taskkill /f /im idman.exe

set _time=
for /f %%a in ('%psc% "(Get-Date).ToString(\'yyyyMMdd-HHmmssfff\')"') do set _time=%%a

call :delete_queue
%psc% "$sid = '%_sid%'; $HKCUsync = %HKCUsync%; $lockKey = $null; $deleteKey = 1; $f=[io.file]::ReadAllText('%~f0') -split ':regscan\:.*';iex ($f[1])" %nul%

call :add_key

echo.
echo The IDM reset process has been completed successfully.
echo.
pause
goto MainMenu

:delete_queue
echo Deleting IDM registry keys...

for %%# in (
""HKCU\Software\DownloadManager" "/v" "FName""
""HKCU\Software\DownloadManager" "/v" "LName""
""HKCU\Software\DownloadManager" "/v" "Email""
""HKCU\Software\DownloadManager" "/v" "Serial""
""HKCU\Software\DownloadManager" "/v" "scansk""
""HKCU\Software\DownloadManager" "/v" "tvfrdt""
""HKCU\Software\DownloadManager" "/v" "radxcnt""
""HKCU\Software\DownloadManager" "/v" "LstCheck""
""HKCU\Software\DownloadManager" "/v" "ptrk_scdt""
""HKCU\Software\DownloadManager" "/v" "LastCheckQU""
"%HKLM%"
) do for /f "tokens=* delims=" %%A in ("%%~#") do (
set "reg="%%~A"" &reg query !reg! %nul% && call :del
)

if not %HKCUsync%==1 for %%# in (
""HKU\%_sid%\Software\DownloadManager" "/v" "FName""
""HKU\%_sid%\Software\DownloadManager" "/v" "LName""
""HKU\%_sid%\Software\DownloadManager" "/v" "Email""
""HKU\%_sid%\Software\DownloadManager" "/v" "Serial""
""HKU\%_sid%\Software\DownloadManager" "/v" "scansk""
""HKU\%_sid%\Software\DownloadManager" "/v" "tvfrdt""
""HKU\%_sid%\Software\DownloadManager" "/v" "radxcnt""
""HKU\%_sid%\Software\DownloadManager" "/v" "LstCheck""
""HKU\%_sid%\Software\DownloadManager" "/v" "ptrk_scdt""
""HKU\%_sid%\Software\DownloadManager" "/v" "LastCheckQU""
) do for /f "tokens=* delims=" %%A in ("%%~#") do (
set "reg="%%~A"" &reg query !reg! %nul% && call :del
)

exit /b

:del
reg delete %reg% /f %nul%
exit /b

::========================================================================================================================================

:_activate
cls
echo.
if %combo%==1 (
    echo +----------------------------------+
    echo ^|    ACTIVATING AND FREEZING IDM    ^|
    echo +----------------------------------+
) else (
    if %frz%==1 (
        echo +----------------------------------+
        echo ^|        FREEZING IDM TRIAL        ^|
        echo +----------------------------------+
    ) else (
        echo +----------------------------------+
        echo ^|         ACTIVATING IDM           ^|
        echo +----------------------------------+
    )
)
echo.

if not exist "%IDMan%" (
    echo IDM [Internet Download Manager] is not installed.
    echo You can download it from https://www.internetdownloadmanager.com/download.html
    pause
    goto MainMenu
)

%idmcheck% && taskkill /f /im idman.exe

set _time=
for /f %%a in ('%psc% "(Get-Date).ToString(\'yyyyMMdd-HHmmssfff\')"') do set _time=%%a

call :delete_queue
call :add_key

%psc% "$sid = '%_sid%'; $HKCUsync = %HKCUsync%; $lockKey = 1; $deleteKey = $null; $toggle = 1; $f=[io.file]::ReadAllText('%~f0') -split ':regscan\:.*';iex ($f[1])" %nul%

if %frz%==0 (
    call :register_IDM
) else if %combo%==1 (
    call :register_IDM
)

call :download_files

%psc% "$sid = '%_sid%'; $HKCUsync = %HKCUsync%; $lockKey = 1; $deleteKey = $null; $f=[io.file]::ReadAllText('%~f0') -split ':regscan\:.*';iex ($f[1])" %nul%

echo.
if %combo%==1 (
    echo The IDM has been activated and trial has been frozen successfully.
    echo This provides maximum protection against registration popups.
) else (
    if %frz%==0 (
        echo The IDM Activation process has been completed successfully.
        echo If the fake serial screen appears, use the 'Activate and Freeze' option instead.
    ) else (
        echo The IDM 30 days trial period is successfully frozen for lifetime.
        echo If IDM is showing a popup to register, try the 'Activate and Freeze' option.
    )
)
echo.
pause
goto MainMenu

::========================================================================================================================================

:_rcont
reg add %reg% %nul%
call :add
exit /b

:register_IDM
echo Applying registration details...
set fname=Master
set lname=Hunter
set email=%fname%.%lname%@tonec.com

for /f "delims=" %%a in ('%psc% "$key = -join ((Get-Random -Count 20 -InputObject ([char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'))));$key = ($key.Substring(0, 5) + '-' + $key.Substring(5, 5) + '-' + $key.Substring(10, 5) + '-' + $key.Substring(15, 5) + $key.Substring(20));Write-Output $key" 2^>nul') do (set key=%%a)

set "reg=HKCU\SOFTWARE\DownloadManager /v FName /t REG_SZ /d "%fname%"" & call :_rcont
set "reg=HKCU\SOFTWARE\DownloadManager /v LName /t REG_SZ /d "%lname%"" & call :_rcont
set "reg=HKCU\SOFTWARE\DownloadManager /v Email /t REG_SZ /d "%email%"" & call :_rcont
set "reg=HKCU\SOFTWARE\DownloadManager /v Serial /t REG_SZ /d "%key%"" & call :_rcont

if not %HKCUsync%==1 (
    set "reg=HKU\%_sid%\SOFTWARE\DownloadManager /v FName /t REG_SZ /d "%fname%"" & call :_rcont
    set "reg=HKU\%_sid%\SOFTWARE\DownloadManager /v LName /t REG_SZ /d "%lname%"" & call :_rcont
    set "reg=HKU\%_sid%\SOFTWARE\DownloadManager /v Email /t REG_SZ /d "%email%"" & call :_rcont
    set "reg=HKU\%_sid%\SOFTWARE\DownloadManager /v Serial /t REG_SZ /d "%key%"" & call :_rcont
)
exit /b

:download_files
echo Triggering downloads to create registry keys, please wait...

set "file=%SystemRoot%\Temp\temp.png"

set link=https://www.internetdownloadmanager.com/images/idm_box_min.png
call :download
set link=https://www.internetdownloadmanager.com/register/IDMlib/images/idman_logos.png
call :download
set link=https://www.internetdownloadmanager.com/pictures/idm_about.png
call :download

timeout /t 3 %nul%
%idmcheck% && taskkill /f /im idman.exe
if exist "%file%" del /f /q "%file%"
exit /b

:download
set /a attempt=0
if exist "%file%" del /f /q "%file%"
start "" /B "%IDMan%" /n /d "%link%" /p "%SystemRoot%\Temp" /f temp.png

:check_file
timeout /t 1 %nul%
set /a attempt+=1
if exist "%file%" exit /b
if %attempt% GEQ 20 exit /b
goto :Check_file

::========================================================================================================================================

:add_key
echo Adding registry key...

set "reg="%HKLM%" /v "AdvIntDriverEnabled2""

reg add %reg% /t REG_DWORD /d "1" /f %nul%

:add
exit /b

::========================================================================================================================================

:regscan:
$finalValues = @()

$arch = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE
if ($arch -eq "x86") {
  $regPaths = @("HKCU:\Software\Classes\CLSID", "Registry::HKEY_USERS\$sid\Software\Classes\CLSID")
} else {
  $regPaths = @("HKCU:\Software\Classes\WOW6432Node\CLSID", "Registry::HKEY_USERS\$sid\Software\Classes\Wow6432Node\CLSID")
}

foreach ($regPath in $regPaths) {
    if (($regPath -match "HKEY_USERS") -and ($HKCUsync -ne $null)) {
        continue
    }
	
	Write-Host
	Write-Host "Searching IDM CLSID Registry Keys in $regPath"
	Write-Host
	
    $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue -ErrorVariable lockedKeys | Where-Object { $_.PSChildName -match '^\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}$' }

    foreach ($lockedKey in $lockedKeys) {
        $leafValue = Split-Path -Path $lockedKey.TargetObject -Leaf
        $finalValues += $leafValue
        Write-Output "$leafValue - Found Locked Key"
    }

    if ($subKeys -eq $null) {
	continue
	}
	
	$subKeysToExclude = "LocalServer32", "InProcServer32", "InProcHandler32"

    $filteredKeys = $subKeys | Where-Object { !($_.GetSubKeyNames() | Where-Object { $subKeysToExclude -contains $_ }) }

    foreach ($key in $filteredKeys) {
        $fullPath = $key.PSPath
        $keyName = $key.PSChildName
        
        if ($deleteKey -ne $null) {
            Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Output "$keyName - Deleted"
        }
        
        if ($lockKey -ne $null) {
            $acl = Get-Acl -Path $fullPath
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule("Everyone", "FullControl", "Deny")
            $acl.AddAccessRule($rule)
            Set-Acl -Path $fullPath -AclObject $acl -ErrorAction SilentlyContinue
            Write-Output "$keyName - Locked"
        }
        
        if ($toggle -ne $null) {
            $idmKey = "HKCU:\Software\DownloadManager"
            $idmKeyHKU = "Registry::HKEY_USERS\$sid\Software\DownloadManager"
            
            $paths = @($idmKey)
            if ($HKCUsync -eq $null) {
                $paths += $idmKeyHKU
            }
            
            foreach ($path in $paths) {
                if (!(Test-Path -Path $path)) {
                    New-Item -Path $path -Force | Out-Null
                }
                
                $now = Get-Date
                $future = $now.AddDays(30).ToString("MM/dd/yyyy")
                
                New-ItemProperty -Path $path -Name "tvfrdt" -Value $future -PropertyType String -Force | Out-Null
                Write-Output "Set trial expiry date to $future"
            }
        }
    }
}
