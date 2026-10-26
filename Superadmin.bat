@echo off
title True Router T626 Pro Superadmin Password Extractor
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$script = ((Get-Content -LiteralPath '%~f0' | Select-Object -Skip 6) -join [Environment]::NewLine); & ([ScriptBlock]::Create($script))" %*
pause
exit /b

$Path = if ($args.Count -gt 0) { $args[0] } else { $null }

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

    Write-Host "==================================================`n" -ForegroundColor Yellow
}
catch {
    Write-Host "`n[-] Error during decoding: $_" -ForegroundColor Red
}
