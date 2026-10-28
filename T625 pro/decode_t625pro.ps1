<#
.SYNOPSIS
    True Router T625 Pro bfwcfg.dt Decoder & Superadmin Enabler (PowerShell)
    Extracts superadmin and admin credentials from encrypted bfwcfg.dt router backups
    and generates an unlocked bfwcfg.dt ready for router restore.

.DESCRIPTION
    Reverse-engineered from T3 Technology T625 Pro firmware (/ptrom/bin/cfgutil).
    Supports Drag & Drop, interactive prompt, and command-line arguments.
    Works natively on Windows PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$CustomPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $Path) {
    if (Test-Path "bfwcfg.dt") {
        $Path = "bfwcfg.dt"
    }
    else {
        Write-Host "=======================================================" -ForegroundColor Cyan
        Write-Host "     True T625 Pro bfwcfg.dt Superadmin Decoder" -ForegroundColor Cyan
        Write-Host "=======================================================" -ForegroundColor Cyan
        $inputPath = Read-Host "Drag & drop your bfwcfg.dt here and press Enter"
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
    [byte[]]$raw = [System.IO.File]::ReadAllBytes($resolvedPath)
    if ($raw.Length -lt 40) {
        throw "File is too short to be a valid bfwcfg.dt (minimum 40 bytes required)"
    }

    # 2. De-XOR 40-byte header with 0x68
    [byte[]]$hdrDec = New-Object byte[] 40
    for ($i = 0; $i -lt 40; $i++) {
        $hdrDec[$i] = [byte]($raw[$i] -bxor 0x68)
    }

    $hdrStr = [System.Text.Encoding]::ASCII.GetString($hdrDec)
    $prefix = $hdrStr.Substring(0, 8)
    $expectedMd5 = $hdrStr.Substring(8, 32)

    if ($prefix -ne "37249126") {
        throw "Invalid magic prefix '$prefix' (expected '37249126'). Is this a valid T625 bfwcfg.dt?"
    }

    # 3. De-XOR payload with 0x68 (recovers tar.gz)
    $payloadLen = $raw.Length - 40
    [byte[]]$targz = New-Object byte[] $payloadLen
    for ($i = 0; $i -lt $payloadLen; $i++) {
        $targz[$i] = [byte]($raw[40 + $i] -bxor 0x68)
    }

    # 4. Verify MD5
    $md5Calc = [System.Security.Cryptography.MD5]::Create()
    $hashBytes = $md5Calc.ComputeHash($targz)
    $calcMd5 = -join ($hashBytes | ForEach-Object { "{0:x2}" -f $_ })

    if ($calcMd5.ToLower() -ne $expectedMd5.ToLower()) {
        throw "MD5 checksum mismatch! Expected: $expectedMd5, Calculated: $calcMd5"
    }

    # 5. Decompress GZIP payload
    $msIn = New-Object System.IO.MemoryStream(,$targz)
    $gz = New-Object System.IO.Compression.GZipStream($msIn, [System.IO.Compression.CompressionMode]::Decompress)
    $msOut = New-Object System.IO.MemoryStream
    $gz.CopyTo($msOut)
    $tarBytes = $msOut.ToArray()
    $gz.Close()
    $msIn.Close()
    $msOut.Close()

    # 6. Extract files from TAR archive
    $files = @{}
    $pos = 0
    while ($pos + 512 -le $tarBytes.Length) {
        $nameBytes = $tarBytes[$pos..($pos + 99)]
        $nullIdx = [Array]::IndexOf($nameBytes, [byte]0)
        if ($nullIdx -le 0) {
            $pos += 512
            continue
        }
        $name = [System.Text.Encoding]::ASCII.GetString($nameBytes, 0, $nullIdx).Trim()
        if (-not $name) {
            $pos += 512
            continue
        }

        # Size in octal at offset 124 (12 bytes)
        $sizeStr = [System.Text.Encoding]::ASCII.GetString($tarBytes, $pos + 124, 11).Trim()
        $size = [Convert]::ToInt32($sizeStr, 8)

        $dataStart = $pos + 512
        if ($dataStart + $size -le $tarBytes.Length) {
            [byte[]]$content = New-Object byte[] $size
            [Array]::Copy($tarBytes, $dataStart, $content, 0, $size)
            $files[$name] = $content
        }

        # Tar blocks are aligned to 512 bytes
        $blocks = [Math]::Ceiling($size / 512.0)
        $pos = $dataStart + ($blocks * 512)
    }

    # 7. Parse usrconfig_conf
    $superadminPass = ""
    $adminPass = ""
    $wanUser = ""
    $wanPass = ""

    if ($files.ContainsKey("usrconfig_conf")) {
        $usrText = [System.Text.Encoding]::UTF8.GetString($files["usrconfig_conf"])

        # Superadmin (UserList 1)
        if ($usrText -match "config interface 'InternetGatewayDevice__X_TRUE_UserInfo__UserList__1__'(?:\s+option Password '([^']+)')?") {
            $b64 = $matches[1]
            if ($b64) {
                try {
                    $pad = (4 - ($b64.Length % 4)) % 4
                    if ($pad -gt 0) { $b64 += "=" * $pad }
                    $superadminPass = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
                } catch { $superadminPass = $b64 }
            }
        }

        # Admin (UserList 2)
        if ($usrText -match "config interface 'InternetGatewayDevice__X_TRUE_UserInfo__UserList__2__'(?:\s+option Password '([^']+)')?") {
            $b64 = $matches[1]
            if ($b64) {
                try {
                    $pad = (4 - ($b64.Length % 4)) % 4
                    if ($pad -gt 0) { $b64 += "=" * $pad }
                    $adminPass = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
                } catch { $adminPass = $b64 }
            }
        }

        # WAN PPPoE credentials
        if ($usrText -match "option Username '([^']+@fiberhome)'") {
            try {
                $b64 = $matches[1]
                $pad = (4 - ($b64.Length % 4)) % 4
                if ($pad -gt 0) { $b64 += "=" * $pad }
                $wanUser = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
            } catch { $wanUser = $matches[1] }
        }
        if ($usrText -match "Username '[^']+'\s+option Password '([^']+)'") {
            try {
                $b64 = $matches[1]
                $pad = (4 - ($b64.Length % 4)) % 4
                if ($pad -gt 0) { $b64 += "=" * $pad }
                $wanPass = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
            } catch { $wanPass = $matches[1] }
        }
    }

    # 8. Display Results
    Write-Host "`n=======================================================" -ForegroundColor Yellow
    Write-Host "        TRUE ROUTER T625 PRO WEB CREDENTIALS" -ForegroundColor Yellow
    Write-Host "=======================================================" -ForegroundColor Yellow

    if ($superadminPass) {
        Write-Host ("  [{0,-24}] User: {1,-12} Pass: {2}" -f "SUPERADMIN (UserList 1)", "superadmin", $superadminPass) -ForegroundColor Green
    } else {
        Write-Host ("  [{0,-24}] User: {1,-12} Pass: {2} (Default)" -f "SUPERADMIN (Default)", "superadmin", "t4246#5753S@dM1n") -ForegroundColor Green
    }

    if ($adminPass) {
        Write-Host ("  [{0,-24}] User: {1,-12} Pass: {2}" -f "USER (UserList 2)", "admin", $adminPass) -ForegroundColor Cyan
    } else {
        Write-Host ("  [{0,-24}] User: {1,-12} Pass: {2}" -f "USER (UserList 2)", "admin", "(Printed on router bottom sticker - Factory Default)") -ForegroundColor Cyan
    }

    if ($wanUser) {
        Write-Host "`n  [WAN PPPoE Credentials]" -ForegroundColor Magenta
        Write-Host "    Username: $wanUser" -ForegroundColor White
        if ($wanPass) { Write-Host "    Password: $wanPass" -ForegroundColor White }
    }

    if ($files.ContainsKey("sysinfo_conf")) {
        $sysText = [System.Text.Encoding]::UTF8.GetString($files["sysinfo_conf"])
        Write-Host "`n  [Device Info]" -ForegroundColor Gray
        foreach ($line in ($sysText -split "`r?`n")) {
            if ($line -match "config key '([^']+)'") { $k = $matches[1] }
            if ($line -match "option value '([^']+)'") {
                $v = $matches[1]
                if ($k -in @("SoftwareVersion", "HardwareVersion", "UnifiedSoftwareVersion")) {
                    Write-Host ("    {0,-24}: {1}" -f $k, $v) -ForegroundColor Gray
                }
            }
        }
    }

    Write-Host "=======================================================" -ForegroundColor Yellow

    # 9. Generate Unlocked bfwcfg.dt for router restore
    $file = [System.IO.Path]::GetFileName($resolvedPath)
    $shouldUnlock = $true
    if (-not $OutputPath) {
        if ($file.StartsWith("unlocked_")) {
            $shouldUnlock = $false
        } else {
            $dir = [System.IO.Path]::GetDirectoryName($resolvedPath)
            $OutputPath = [System.IO.Path]::Combine($dir, "unlocked_$file")
        }
    }

    if ($shouldUnlock -and $OutputPath) {
        Write-Host "`n[*] Generating unlocked router restore file: $OutputPath ..." -ForegroundColor Cyan

    $activePass = if ($CustomPassword) { $CustomPassword } elseif ($superadminPass) { $superadminPass } else { "t4246#5753S@dM1n" }
    $superB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($activePass))

    $newUsrText = [System.Text.Encoding]::UTF8.GetString($files["usrconfig_conf"])

    # Ensure UserList 1 has username superadmin and password
    $userlistBlock = "`nconfig interface 'InternetGatewayDevice__X_TRUE_UserInfo__UserList__1__'`n`toption Username 'c3VwZXJhZG1pbg=='`n`toption Password '$superB64'`n"
    if ($newUsrText -match "config interface 'InternetGatewayDevice__X_TRUE_UserInfo__UserList__1__'") {
        $newUsrText = [regex]::Replace($newUsrText, "config interface 'InternetGatewayDevice__X_TRUE_UserInfo__UserList__1__'(?:(?!config interface)[\s\S])*", $userlistBlock.Trim() + "`n`n")
    } else {
        $newUsrText += $userlistBlock
    }

    # Ensure TeleComAccount is Enabled (both X_CT111COM and X_CT_COM)
    $telecomBlock = "`nconfig interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_TeleComAccount__'`n`toption Enable '1'`n`toption Name 'superadmin'`n`toption Password '$activePass'`n`toption X_PT_LoginInterval '180'`n`nconfig interface 'InternetGatewayDevice__DeviceInfo__X_CT_COM_TeleComAccount__'`n`toption Enable '1'`n`toption Name 'superadmin'`n`toption Password '$activePass'`n"
    if ($newUsrText -match "config interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_TeleComAccount__'") {
        $newUsrText = [regex]::Replace($newUsrText, "config interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_TeleComAccount__'(?:(?!config interface)[\s\S])*", $telecomBlock.Trim() + "`n`n")
    } else {
        $newUsrText += $telecomBlock
    }

    # Ensure TelnetEnable is '1' and SuperUser Telnet is '1'
    $telnetBlock = "`nconfig interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_ServiceManage__'`n`toption TelnetEnable '1'`n`toption X_PT_SuperUser_TelnetEnable '1'`n`toption FtpEnable '0'`n"
    if ($newUsrText -match "config interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_ServiceManage__'") {
        $newUsrText = [regex]::Replace($newUsrText, "config interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_ServiceManage__'(?:(?!config interface)[\s\S])*", $telnetBlock.Trim() + "`n`n")
    } else {
        $newUsrText += $telnetBlock
    }

    $files["usrconfig_conf"] = [System.Text.Encoding]::UTF8.GetBytes($newUsrText)

    # Re-build TAR in memory
    $tarMs = New-Object System.IO.MemoryStream
    foreach ($entryName in @("usrconfig_conf", "attrconfig_conf", "sysinfo_conf", "tr069_control_conf", "voice_digitmap_conf")) {
        if (-not $files.ContainsKey($entryName)) { continue }
        [byte[]]$cBytes = $files[$entryName]

        # 512-byte header
        [byte[]]$h = New-Object byte[] 512
        [byte[]]$nB = [System.Text.Encoding]::ASCII.GetBytes($entryName)
        [Array]::Copy($nB, 0, $h, 0, $nB.Length)

        # Mode: 0000644 (at offset 100, 8 bytes)
        $mB = [System.Text.Encoding]::ASCII.GetBytes("0000644`0")
        [Array]::Copy($mB, 0, $h, 100, $mB.Length)

        # Uid / Gid (at offset 108 & 116, 8 bytes)
        $uB = [System.Text.Encoding]::ASCII.GetBytes("0000000`0")
        [Array]::Copy($uB, 0, $h, 108, $uB.Length)
        [Array]::Copy($uB, 0, $h, 116, $uB.Length)

        # Size in octal (at offset 124, 12 bytes)
        $octSize = [Convert]::ToString($cBytes.Length, 8).PadLeft(11, '0') + " "
        $sB = [System.Text.Encoding]::ASCII.GetBytes($octSize)
        [Array]::Copy($sB, 0, $h, 124, $sB.Length)

        # Mtime: 00000000000
        $tB = [System.Text.Encoding]::ASCII.GetBytes("00000000000 ")
        [Array]::Copy($tB, 0, $h, 136, $tB.Length)

        # Typeflag '0' (regular file at offset 156)
        $h[156] = [byte]48

        # Checksum space filled with spaces (offset 148, 8 bytes)
        for ($k = 148; $k -lt 156; $k++) { $h[$k] = [byte]32 }

        # Calculate checksum
        $chksum = 0
        for ($k = 0; $k -lt 512; $k++) { $chksum += $h[$k] }
        $chkStr = [Convert]::ToString($chksum, 8).PadLeft(6, '0') + "`0 "
        $cB = [System.Text.Encoding]::ASCII.GetBytes($chkStr)
        [Array]::Copy($cB, 0, $h, 148, $cB.Length)

        # Write header
        $tarMs.Write($h, 0, 512)

        # Write content
        $tarMs.Write($cBytes, 0, $cBytes.Length)

        # Padding to 512
        $padBytes = (512 - ($cBytes.Length % 512)) % 512
        if ($padBytes -gt 0) {
            [byte[]]$zeroPad = New-Object byte[] $padBytes
            $tarMs.Write($zeroPad, 0, $padBytes)
        }
    }

    # 1024 bytes of nulls at tar EOF
    [byte[]]$tarEof = New-Object byte[] 1024
    $tarMs.Write($tarEof, 0, 1024)
    [byte[]]$uncompressedTar = $tarMs.ToArray()
    $tarMs.Close()

    # Compress TAR with GZIP
    $gzMs = New-Object System.IO.MemoryStream
    $gzOut = New-Object System.IO.Compression.GZipStream($gzMs, [System.IO.Compression.CompressionMode]::Compress)
    $gzOut.Write($uncompressedTar, 0, $uncompressedTar.Length)
    $gzOut.Close()
    [byte[]]$newTargz = $gzMs.ToArray()
    $gzMs.Close()

    # Compute MD5
    $newHash = $md5Calc.ComputeHash($newTargz)
    $newMd5 = -join ($newHash | ForEach-Object { "{0:x2}" -f $_ })

    # 40-byte header: "37249126" + newMd5
    $headerPlain = [System.Text.Encoding]::ASCII.GetBytes("37249126" + $newMd5)
    [byte[]]$encHeader = New-Object byte[] 40
    for ($i = 0; $i -lt 40; $i++) {
        $encHeader[$i] = [byte]($headerPlain[$i] -bxor 0x68)
    }

    # Encrypt payload with XOR 0x68
    [byte[]]$encPayload = New-Object byte[] $newTargz.Length
    for ($i = 0; $i -lt $newTargz.Length; $i++) {
        $encPayload[$i] = [byte]($newTargz[$i] -bxor 0x68)
    }

    # Combine and save
    $fsOut = [System.IO.File]::Create($OutputPath)
    $fsOut.Write($encHeader, 0, 40)
    $fsOut.Write($encPayload, 0, $encPayload.Length)
    $fsOut.Close()

    Write-Host "[+] SUCCESS! Unlocked file created: $OutputPath" -ForegroundColor Green
    Write-Host "    - Superadmin Account: superadmin" -ForegroundColor Green
    Write-Host "    - Superadmin Password: $activePass" -ForegroundColor Green
    Write-Host "    - Telnet Service: ENABLED (Port 23)" -ForegroundColor Green
    Write-Host "    - TeleComAccount: ENABLED" -ForegroundColor Green

    Write-Host "`n[+] How to restore on router:" -ForegroundColor Yellow
    Write-Host "    1. Open router Web GUI (http://192.168.1.1)" -ForegroundColor White
    Write-Host "    2. Navigate to Admin -> Backup / Restore" -ForegroundColor White
    Write-Host "    3. Choose File -> Select '$( [System.IO.Path]::GetFileName($OutputPath) )' -> Click Restore" -ForegroundColor White
    Write-Host "    4. Router will reboot with full superadmin privileges active!" -ForegroundColor White
    }
}
catch {
    Write-Host "`n[-] Error: $_" -ForegroundColor Red
}

if (-not $Path -and ($Host.Name -match "Console" -or -not $env:PSExecutionPolicyPreference) -and -not [Console]::IsInputRedirected) {
    Read-Host "`nPress Enter to exit..."
}
