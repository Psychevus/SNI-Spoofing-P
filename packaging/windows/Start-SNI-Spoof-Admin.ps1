$releaseRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$escapedRoot = $releaseRoot -replace "'", "''"
$command = "Set-Location -LiteralPath '$escapedRoot'; .\sni-spoof.exe run --log-level INFO"
Start-Process powershell.exe -Verb RunAs -WorkingDirectory $releaseRoot -ArgumentList @(
    "-NoExit",
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    $command
)
