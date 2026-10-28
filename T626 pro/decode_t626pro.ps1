<#
.SYNOPSIS
    True Router T626 Pro romfile.cfg Decoder (PowerShell)
    Extracts superadmin and admin web credentials from encrypted romfile.cfg backups.

.DESCRIPTION
    Supports Drag & Drop, interactive prompt, and command-line arguments.
    Works natively on Windows PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path,

    [Parameter()]
    [string]$OutputXml
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $Path) {
    if (Test-Path "romfile.cfg") {
        $Path = "romfile.cfg"
    }
    else {
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "   True T626 Pro Superadmin Password Extractor" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        $inputPath = Read-Host "Drag & drop your romfile.cfg here and press Enter"
        $Path = $inputPath.Trim('"').Trim("'")
    }
}
else {
    $Path = $Path.Trim('"').Trim("'")
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Host "`n[-] Error: File not found: $Path" -ForegroundColor Red
    Read-Host "`nPress Enter to exit..."
    return
}

$resolvedPath = (Resolve-Path -LiteralPath $Path).Path
Write-Host "`n[*] Reading and decoding: $resolvedPath ..." -ForegroundColor Cyan

try {
    # 1. Read binary content
    [byte[]]$buf = [System.IO.File]::ReadAllBytes($resolvedPath)
    $len = $buf.Length

    # 2. De-obfuscation loop (reverse modulo 9 and 12 bitwise XOR)
    $r1 = 0
    $r8 = 3

    while ($r1 -lt $len) {
        if ($r1 % 9 -eq 0) {
            $buf[$r1] = [byte]((-bnot ($buf[$r1] -bxor 0x75)) -band 0xFF)
            if ($r8 -lt $len) {
                $buf[$r1 + 1] = [byte]((-bnot ($buf[$r1 + 1] -bxor 0x7B)) -band 0xFF)
                $buf[$r1 + 3] = [byte]((-bnot ($buf[$r1 + 3] -bxor 0x77)) -band 0xFF)
            }
        }
        elseif ($r1 % 12 -eq 0) {
            $buf[$r1] = [byte]((-bnot ($buf[$r1] -bxor 0x53)) -band 0xFF)
            if ($r8 -lt $len) {
                $buf[$r1 + 1] = [byte]((-bnot ($buf[$r1 + 1] -bxor 0x77)) -band 0xFF)
                $buf[$r1 + 3] = [byte]((-bnot ($buf[$r1 + 3] -bxor 0x5B)) -band 0xFF)
            }
        }
        $r1 += 6
        $r8 += 6
    }

    # 3. Custom Base64 alphabet translation
    $customAlpha = "edcbaZYXWVUTSRQPONMLKJIHGFEDCBA+9876543210zyxwvutsrqponmlkjihgf/"
    $stdAlpha    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    [byte[]]$map = New-Object 'byte[]' 256
    for ($i = 0; $i -lt 256; $i++) { $map[$i] = [byte]$i }
    for ($i = 0; $i -lt $customAlpha.Length; $i++) {
        $c = [byte][char]$customAlpha[$i]
        $s = [byte][char]$stdAlpha[$i]
        $map[$c] = $s
    }

    for ($i = 0; $i -lt $len; $i++) {
        $buf[$i] = $map[$buf[$i]]
    }

    # 4. Base64 Decode to XML
    $b64 = [System.Text.Encoding]::ASCII.GetString($buf)
    $pad = (4 - ($b64.Length % 4)) % 4
    if ($pad -gt 0) {
        $b64 += "=" * $pad
    }

    $xmlBytes = [System.Convert]::FromBase64String($b64)
    $xml = [System.Text.Encoding]::GetEncoding("ISO-8859-1").GetString($xmlBytes)

    if ($OutputXml) {
        [System.IO.File]::WriteAllText($OutputXml, $xml, [System.Text.Encoding]::UTF8)
        Write-Host "[+] Decoded XML saved to: $OutputXml" -ForegroundColor Green
    }

    # 5. Extract web login credentials
    Write-Host "`n==================================================" -ForegroundColor Yellow
    Write-Host "             WEB LOGIN CREDENTIALS" -ForegroundColor Yellow
    Write-Host "==================================================" -ForegroundColor Yellow

    $pattern = '<Entry[01]\s+[^>]*username="([^"]+)"[^>]*web_passwd="([^"]+)"'
    $matches = [regex]::Matches($xml, $pattern)

    if ($matches.Count -gt 0) {
        foreach ($m in $matches) {
            $user = $m.Groups[1].Value
            $pass = $m.Groups[2].Value
            $role = if ($user -eq "superadmin") { "SUPERADMIN" } else { "USER" }
            $color = if ($user -eq "superadmin") { "Green" } else { "Cyan" }

            Write-Host ("  [{0,-10}] User: {1,-12} Pass: {2}" -f $role, $user, $pass) -ForegroundColor $color
        }
    }
    else {
        Write-Host "  No web login entries found in file." -ForegroundColor Red
    }

    # WAN PPPoE
    if ($xml -match '<(?:PVC\d+|Entry\d+)[^>]*USERNAME="([^"]+@fiberhome)"[^>]*PASSWORD="([^"]+)"') {
        $wanU = $matches[1]
        $wanP = $matches[2]
        Write-Host "`n  [WAN PPPoE Credentials]" -ForegroundColor Magenta
        Write-Host "    Username: $wanU" -ForegroundColor White
        Write-Host "    Password: $wanP" -ForegroundColor White
    } elseif ($xml -match '<(?:PVC\d+|Entry\d+)[^>]*PASSWORD="([^"]+)"[^>]*USERNAME="([^"]+@fiberhome)"') {
        $wanU = $matches[2]
        $wanP = $matches[1]
        Write-Host "`n  [WAN PPPoE Credentials]" -ForegroundColor Magenta
        Write-Host "    Username: $wanU" -ForegroundColor White
        Write-Host "    Password: $wanP" -ForegroundColor White
    }

    # Device Info
    if ($xml -match 'SerialNumber="([^"]+)"') {
        Write-Host "`n  [Device Info]" -ForegroundColor Gray
        Write-Host "    SerialNumber    : $($matches[1])" -ForegroundColor Gray
    }

    Write-Host "==================================================`n" -ForegroundColor Yellow
}
catch {
    Write-Host "`n[-] Error during decoding: $_" -ForegroundColor Red
}

if (-not $Path -and ($Host.Name -match "Console" -or -not $env:PSExecutionPolicyPreference) -and -not [Console]::IsInputRedirected) {
    Read-Host "Press Enter to exit..."
}
