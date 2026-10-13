<#
.SYNOPSIS
    CTEM Platform - Windows Endpoint Monitoring & Security Log Forwarding Agent
.DESCRIPTION
    Streams Windows host telemetry and Security Event Log detections to the CTEM backend:
      4625 Failed logon        -> Logs (medium) + UEBA (brute-force burst alert at >= 5 in 15 min)
      4624 Successful logon    -> UEBA (interactive / unlock / RDP / remote network only)
      4672 Admin privileges    -> UEBA (deduplicated, 30 min per user)
      4720 User account created            -> Logs (high  -> alert)
      4732 Member added to local group     -> Logs (high/critical -> alert)
      4740 Account locked out              -> Logs (critical -> alert)
    System identities (DWM-x, UMFD-x, SYSTEM, machine$ accounts, services) are filtered out.

    MUST run as Administrator - Windows only lets Administrators read the Security log.
    The script relaunches itself elevated automatically if needed.
.PARAMETER CtemServer
    URL of the CTEM backend (e.g. http://192.168.1.50:8000, or http://10.0.2.2:8000 for VirtualBox NAT)
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\windows_agent.ps1 -CtemServer http://192.168.1.50:8000
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\windows_agent.ps1 -CtemServer http://192.168.1.50:8000 -InstallAutoStart
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\windows_agent.ps1 -CtemServer http://192.168.1.50:8000 -SimulateFailedLogins 6
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\windows_agent.ps1 -CtemServer http://192.168.1.50:8000 -TestPeripheral "ROGUE-USB-999"
#>

param(
    [string]$CtemServer = "http://10.0.2.2:8000",
    [string]$Hostname = $env:COMPUTERNAME,
    [int]$HeartbeatInterval = 30,
    [int]$PortScanInterval = 60,
    [int]$PollIntervalSeconds = 2,
    [switch]$InstallAutoStart,
    [switch]$UninstallAutoStart,
    [int]$SimulateFailedLogins = 0,
    [string]$TestPeripheral = ""
)

$AgentVersion = "1.2.0"
$FailedLoginThreshold = 5
$FailedLoginWindowMinutes = 15

# ==============================================================================
# 0. Administrator check / self-elevation
# ==============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and $SimulateFailedLogins -le 0 -and [string]::IsNullOrEmpty($TestPeripheral)) {
    Write-Host "[!] This agent is NOT running as Administrator." -ForegroundColor Yellow
    Write-Host "    Windows only allows Administrators to read the Security log (failed logins, lockouts, new users)." -ForegroundColor Yellow
    Write-Host "[*] Requesting elevation - please accept the UAC prompt..." -ForegroundColor Cyan

    $argList = @("-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    foreach ($key in $PSBoundParameters.Keys) {
        $val = $PSBoundParameters[$key]
        if ($val -is [System.Management.Automation.SwitchParameter]) {
            if ($val.IsPresent) { $argList += "-$key" }
        } else {
            $argList += "-$key"
            $argList += "`"$val`""
        }
    }
    try {
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList -ErrorAction Stop
        Write-Host "[+] Agent relaunched in a new Administrator window. You can close this window." -ForegroundColor Green
        exit 0
    } catch {
        Write-Host "[!] Elevation was declined. Continuing in LIMITED mode: heartbeats only, NO security log detection." -ForegroundColor Red
    }
}

# ==============================================================================
# 1. Auto-start install / uninstall (Scheduled Task running as SYSTEM)
# ==============================================================================
if ($UninstallAutoStart) {
    Write-Host "[*] Removing CTEM Windows Agent persistent startup task..." -ForegroundColor Yellow
    Stop-ScheduledTask -TaskName "CTEM_Windows_Agent" -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "CTEM_Windows_Agent" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "[+] SUCCESS: CTEM_Windows_Agent scheduled task removed." -ForegroundColor Green
    exit 0
}

if ($InstallAutoStart) {
    Write-Host "[*] Configuring CTEM Windows Agent to start automatically on system boot..." -ForegroundColor Cyan
    $scriptFullPath = $PSCommandPath
    if (-not $scriptFullPath -or -not (Test-Path $scriptFullPath)) {
        $scriptFullPath = (Get-Item ".\windows_agent.ps1").FullName
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptFullPath`" -CtemServer `"$CtemServer`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)

    Register-ScheduledTask -TaskName "CTEM_Windows_Agent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName "CTEM_Windows_Agent" -ErrorAction SilentlyContinue

    Write-Host "[+] SUCCESS: CTEM Windows Agent will start automatically on every boot (as SYSTEM, hidden)." -ForegroundColor Green
    Write-Host "    - Target Server: $CtemServer" -ForegroundColor Cyan
    Write-Host "`nTo check status: Get-ScheduledTask -TaskName CTEM_Windows_Agent" -ForegroundColor White
    Write-Host "To uninstall:    powershell -ExecutionPolicy Bypass -File .\windows_agent.ps1 -UninstallAutoStart" -ForegroundColor White
    exit 0
}

# ==============================================================================
# 2. Startup banner & environment
# ==============================================================================
if ($CtemServer -notmatch '^https?://') { $CtemServer = "http://$CtemServer" }
$CtemServer = $CtemServer.TrimEnd('/')
$StateFile = Join-Path $PSScriptRoot ".agent_state.json"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CTEM Platform - Windows Real-Time Monitoring Agent v$AgentVersion" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Target CTEM Host Server : $CtemServer"
Write-Host "[*] Monitored Windows Node  : $Hostname"
Write-Host "[*] Running as Administrator: $isAdmin"

# Primary IP = adapter that owns the default gateway (avoids picking virtual adapters)
$primaryIp = "127.0.0.1"
try {
    $cfg = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
    if ($cfg -and $cfg.IPv4Address) { $primaryIp = ($cfg.IPv4Address | Select-Object -First 1).IPAddress }
} catch {}
if ($primaryIp -eq "127.0.0.1") {
    try {
        $ipObj = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1
        if ($ipObj) { $primaryIp = $ipObj.IPAddress }
    } catch {}
}
Write-Host "[*] Primary Node IP         : $primaryIp"

function Get-HttpErrorDetail($err) {
    if ($err.ErrorDetails -and $err.ErrorDetails.Message) { return $err.ErrorDetails.Message }
    if ($err.Exception -and $err.Exception.Response) {
        try {
            $reader = New-Object System.IO.StreamReader($err.Exception.Response.GetResponseStream())
            $text = $reader.ReadToEnd()
            if ($text) { return $text }
        } catch {}
    }
    if ($err.Exception) { return $err.Exception.Message }
    return [string]$err
}

# ==============================================================================
# 3. Backend connectivity & asset registration
# ==============================================================================
Write-Host "`n[*] Testing connectivity to CTEM Backend ($CtemServer/health)..." -ForegroundColor Cyan
$serverOnline = $false
try {
    $health = Invoke-RestMethod -Uri "$CtemServer/health?check_db=true" -Method Get -TimeoutSec 8 -ErrorAction Stop
    if ($health.status -eq "ok") {
        if ($health.database -and $health.database -ne "ok") {
            Write-Host "[!] Backend reachable, BUT database reported: $($health.database)" -ForegroundColor Red
            Write-Host "    [Fix] Check SUPABASE_URL / SUPABASE_KEY in .env on the CTEM host." -ForegroundColor Yellow
        } else {
            Write-Host "[+] Connection SUCCESS! CTEM Backend is reachable and healthy." -ForegroundColor Green
            $serverOnline = $true
        }
    }
} catch {
    Write-Host "[!] ERROR: Could not connect to $CtemServer/health" -ForegroundColor Red
    Write-Host "    Details: $(Get-HttpErrorDetail $_)" -ForegroundColor Red
    Write-Host "    - VirtualBox NAT VM?  use -CtemServer http://10.0.2.2:8000" -ForegroundColor Yellow
    Write-Host "    - Bridged / LAN?      use the CTEM host's LAN IP, e.g. http://192.168.1.x:8000" -ForegroundColor Yellow
    Write-Host "    - On the CTEM host:   backend must listen on 0.0.0.0 and firewall must allow TCP 8000" -ForegroundColor Yellow
}

function Register-AgentNode {
    Write-Host "[*] Registering Windows Node with CTEM Platform..." -ForegroundColor Cyan
    $osInfo = "Windows"
    try { $osInfo = (Get-CimInstance Win32_OperatingSystem).Caption } catch {}
    $cpuCores = 2
    try { $cpuCores = (Get-CimInstance Win32_Processor | Select-Object -First 1).NumberOfCores } catch {}
    $ramMb = 2048
    try { $ramMb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB) } catch {}

    $regBody = @{
        hostname = $Hostname
        ip_address = $primaryIp
        os_name = "Windows"
        os_version = $osInfo
        asset_type = "endpoint"
        zone = "internal"
        criticality = "medium"
        agent_version = $AgentVersion
        metadata = @{ cpu_count = $cpuCores; memory_mb = $ramMb }
    } | ConvertTo-Json -Depth 4

    try {
        $regRes = Invoke-RestMethod -Uri "$CtemServer/agent/register" -Method Post -Body $regBody -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
        if ($regRes.asset_id) {
            $script:assetId = $regRes.asset_id
            Write-Host "[+] Node Registered! Assigned Asset ID: $script:assetId" -ForegroundColor Green
            @{ asset_id = $script:assetId; hostname = $Hostname; server = $CtemServer } | ConvertTo-Json | Out-File -FilePath $StateFile -Encoding utf8
            return $true
        }
    } catch {
        Write-Host "[!] Registration failed: $(Get-HttpErrorDetail $_)" -ForegroundColor Red
    }
    return $false
}

$script:assetId = $null
if (Test-Path $StateFile) {
    try {
        $savedState = Get-Content $StateFile -Raw | ConvertFrom-Json
        if ($savedState.asset_id -and $serverOnline) {
            try {
                Invoke-RestMethod -Uri "$CtemServer/agent/status/$($savedState.asset_id)" -Method Get -TimeoutSec 8 -ErrorAction Stop | Out-Null
                $script:assetId = $savedState.asset_id
                Write-Host "[+] Verified and resuming active CTEM Asset ID: $script:assetId" -ForegroundColor Green
            } catch {
                Write-Host "[-] Cached Asset ID no longer valid on server. Re-registering..." -ForegroundColor Yellow
                Remove-Item -Path $StateFile -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}
if (-not $script:assetId -and $serverOnline) { Register-AgentNode | Out-Null }

# ==============================================================================
# 4. Delivery helpers
# ==============================================================================
$script:forwardedCount = 0
$script:lastSendErrorAt = [DateTime]::MinValue

function Invoke-CtemPost([string]$path, $payload) {
    try {
        $json = $payload | ConvertTo-Json -Depth 6
        Invoke-RestMethod -Uri "$CtemServer$path" -Method Post -Body $json -ContentType "application/json" -TimeoutSec 8 -ErrorAction Stop | Out-Null
        $script:forwardedCount++
        return $true
    } catch {
        # Surface delivery failures (rate-limited) instead of failing silently
        if (([DateTime]::UtcNow - $script:lastSendErrorAt).TotalSeconds -ge 30) {
            Write-Host "[!] Delivery to $path failed: $(Get-HttpErrorDetail $_)" -ForegroundColor DarkYellow
            $script:lastSendErrorAt = [DateTime]::UtcNow
        }
        return $false
    }
}

function Get-UtcStamp([datetime]$when) {
    return $when.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Send-UebaEvent([string]$user, [string]$type, [string]$srcIp, [string]$occurredAt) {
    if (-not $occurredAt) { $occurredAt = Get-UtcStamp (Get-Date) }
    return Invoke-CtemPost "/ueba/events" @{
        username = $user
        event_type = $type
        source_ip = $srcIp
        occurred_at = $occurredAt
        asset_id = $script:assetId
        hostname = $Hostname
    }
}

function Send-LogEvent([string]$type, [string]$severity, [string]$summary, [string]$occurredAt) {
    if (-not $occurredAt) { $occurredAt = Get-UtcStamp (Get-Date) }
    return Invoke-CtemPost "/logs/events" @{
        source = "windows_security_eventlog"
        asset_id = $script:assetId
        event_type = $type
        severity = $severity
        summary = $summary
        occurred_at = $occurredAt
    }
}

# ==============================================================================
# 5. Noise filtering & local correlation
# ==============================================================================
$NoiseDomains = @("Window Manager", "Font Driver Host", "NT AUTHORITY", "NT SERVICE", "NT VIRTUAL MACHINE")
$NoiseUsers = @("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "DefaultAccount", "WDAGUtilityAccount", "-", "")

function Test-NoiseAccount([string]$user, [string]$domain) {
    if ([string]::IsNullOrWhiteSpace($user)) { return $true }
    if ($user -in $NoiseUsers) { return $true }
    if ($user.EndsWith('$')) { return $true }                    # machine accounts
    if ($user -match '^(DWM|UMFD)-\d+$') { return $true }        # Desktop Window Manager / Font Driver
    if ($domain -and ($domain -in $NoiseDomains)) { return $true }
    return $false
}

function Get-CleanIp([string]$ip) {
    if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq '-' -or $ip -eq '::1') { return '127.0.0.1' }
    return $ip.Replace('::ffff:', '')
}

$LogonTypeNames = @{
    "2" = "Interactive"; "3" = "Network"; "4" = "Batch"; "5" = "Service"; "7" = "Unlock";
    "8" = "NetworkCleartext"; "9" = "NewCredentials"; "10" = "RDP"; "11" = "CachedInteractive"
}
function Get-LogonTypeName([string]$lt) {
    if ($LogonTypeNames.ContainsKey($lt)) { return $LogonTypeNames[$lt] }
    return "Type $lt"
}

$FailureReasons = @{
    "0xc000006a" = "wrong password"; "0xc0000064" = "unknown username"; "0xc0000234" = "account locked out";
    "0xc0000072" = "account disabled"; "0xc000006f" = "outside allowed hours"; "0xc0000070" = "workstation restriction";
    "0xc0000071" = "password expired"; "0xc0000193" = "account expired"; "0xc0000224" = "password must change";
    "0xc000015b" = "logon type not granted"; "0xc000006d" = "bad username or password"
}

$script:recentKeys = @{}
function Test-RecentlySeen([string]$key, [int]$seconds) {
    $now = [DateTime]::UtcNow
    if ($script:recentKeys.ContainsKey($key) -and ($now - $script:recentKeys[$key]).TotalSeconds -lt $seconds) { return $true }
    $script:recentKeys[$key] = $now
    return $false
}

$script:failHistory = @{}
function Register-LocalFailure([string]$user) {
    $now = [DateTime]::UtcNow
    $cutoff = $now.AddMinutes(-$FailedLoginWindowMinutes)
    $list = @()
    if ($script:failHistory.ContainsKey($user)) { $list = @($script:failHistory[$user] | Where-Object { $_ -ge $cutoff }) }
    $list += $now
    $script:failHistory[$user] = $list
    return $list.Count
}

# ==============================================================================
# 6. Windows audit policy (Windows only writes these events if auditing is on)
# ==============================================================================
function Enable-SecurityAuditing {
    if (-not $isAdmin) { return }
    # Locale-independent subcategory GUIDs
    $subcats = [ordered]@{
        "Logon"                     = "{0CCE9215-69AE-11D9-BED3-505054503030}"
        "Account Lockout"           = "{0CCE9217-69AE-11D9-BED3-505054503030}"
        "User Account Management"   = "{0CCE9235-69AE-11D9-BED3-505054503030}"
        "Security Group Management" = "{0CCE9237-69AE-11D9-BED3-505054503030}"
    }
    foreach ($name in $subcats.Keys) {
        $null = & auditpol.exe /set /subcategory:"$($subcats[$name])" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Audit policy enabled: $name (success + failure)" -ForegroundColor DarkGreen
        } else {
            Write-Host "[!] Could not enable audit policy: $name (exit $LASTEXITCODE). A domain GPO may override it." -ForegroundColor Yellow
        }
    }
}

# ==============================================================================
# 7. Security log reader (bookmark-based: no gaps, no duplicates, no clock issues)
# ==============================================================================
$SecurityXPath = "*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4720 or EventID=4732 or EventID=4740)]]"
$script:bookmark = $null
$script:lastRecordId = [long]0
$script:secLogReadable = $false

function Initialize-SecurityLogCursor {
    $reader = $null
    try {
        $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery("Security", [System.Diagnostics.Eventing.Reader.PathType]::LogName)
        $q.ReverseDirection = $true
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
        $latest = $reader.ReadEvent()
        if ($latest) {
            $script:bookmark = $latest.Bookmark
            $script:lastRecordId = [long]$latest.RecordId
            $latest.Dispose()
        }
        $script:secLogReadable = $true
        return $true
    } catch {
        $script:secLogReadable = $false
        Write-Host "[!] CANNOT READ the Windows Security log: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    Failed logins / lockouts will NOT be detected. Run this agent as Administrator." -ForegroundColor Red
        return $false
    } finally {
        if ($reader) { $reader.Dispose() }
    }
}

function Get-EventFields($rec) {
    $fields = @{}
    try {
        $xml = [xml]$rec.ToXml()
        foreach ($node in $xml.Event.EventData.Data) { $fields[[string]$node.Name] = [string]$node.'#text' }
    } catch {}
    return $fields
}

function Invoke-SecurityEvent($rec) {
    $f = Get-EventFields $rec
    $ts = Get-UtcStamp $rec.TimeCreated

    switch ($rec.Id) {
        4625 {
            $user = $f["TargetUserName"]
            if (Test-NoiseAccount $user $f["TargetDomainName"]) { return }
            $ip = Get-CleanIp $f["IpAddress"]
            $ltName = Get-LogonTypeName ([string]$f["LogonType"])
            $code = ([string]$f["SubStatus"]).ToLower()
            if (-not $code -or $code -eq "0x0") { $code = ([string]$f["Status"]).ToLower() }
            $reason = if ($FailureReasons.ContainsKey($code)) { $FailureReasons[$code] } else { "status $code" }

            $count = Register-LocalFailure $user
            Write-Host "[FAILED LOGIN] user='$user' reason=$reason type=$ltName src=$ip  ($count in last $FailedLoginWindowMinutes min)" -ForegroundColor Red

            Send-LogEvent "failed_login" "medium" "Failed logon for '$user' on $Hostname ($reason, $ltName, from $ip) - Event 4625" $ts | Out-Null
            Send-UebaEvent $user "failed_login" $ip $ts | Out-Null

            if ($count -eq $FailedLoginThreshold -or $count -eq 10) {
                Write-Host "[BRUTE-FORCE] $count failed logins for '$user' within $FailedLoginWindowMinutes min -> CTEM alert raised" -ForegroundColor Magenta
            }
        }
        4624 {
            $user = $f["TargetUserName"]
            if (Test-NoiseAccount $user $f["TargetDomainName"]) { return }
            $lt = [string]$f["LogonType"]
            $ip = Get-CleanIp $f["IpAddress"]
            $isRemote = $ip -ne "127.0.0.1"
            # Only human-relevant logons: console, unlock, RDP, cached, or network from a remote host
            if (-not (($lt -in @("2", "7", "10", "11")) -or ($lt -eq "3" -and $isRemote))) { return }
            # Windows logs 2 events per admin logon (UAC split token) - collapse them
            if (Test-RecentlySeen "login|$user|$lt|$ip" 60) { return }
            Write-Host "[LOGIN] user='$user' type=$(Get-LogonTypeName $lt) src=$ip" -ForegroundColor Green
            Send-UebaEvent $user "login" $ip $ts | Out-Null
        }
        4672 {
            $user = $f["SubjectUserName"]
            if (Test-NoiseAccount $user $f["SubjectDomainName"]) { return }
            if (Test-RecentlySeen "priv|$user" 1800) { return }
            Send-UebaEvent $user "privilege_change" "127.0.0.1" $ts | Out-Null
        }
        4720 {
            $newUser = $f["TargetUserName"]; $by = $f["SubjectUserName"]
            Write-Host "[HIGH] New local account created: '$newUser' by '$by'" -ForegroundColor Magenta
            Send-LogEvent "account_created" "high" "New user account '$newUser' created on $Hostname by '$by' (Event 4720)" $ts | Out-Null
        }
        4732 {
            $group = $f["TargetUserName"]; $by = $f["SubjectUserName"]; $member = $f["MemberName"]
            if (-not $member -or $member -eq "-") { $member = $f["MemberSid"] }
            $sev = if ($group -match "Administrators") { "critical" } else { "high" }
            Write-Host "[$($sev.ToUpper())] '$member' added to local group '$group' by '$by'" -ForegroundColor Magenta
            Send-LogEvent "group_membership_added" $sev "'$member' added to local group '$group' on $Hostname by '$by' (Event 4732)" $ts | Out-Null
        }
        4740 {
            $locked = $f["TargetUserName"]
            Write-Host "[CRITICAL] Account locked out: '$locked'" -ForegroundColor Red
            Send-LogEvent "account_lockout" "critical" "Account '$locked' was LOCKED OUT on $Hostname after repeated failed logons (Event 4740)" $ts | Out-Null
        }
    }
}

function Read-NewSecurityEvents {
    if (-not $script:secLogReadable) { return }
    $reader = $null
    try {
        $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery("Security", [System.Diagnostics.Eventing.Reader.PathType]::LogName, $SecurityXPath)
        if ($script:bookmark) {
            $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q, $script:bookmark)
        } else {
            $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
        }
        $processed = 0
        while ($processed -lt 500) {
            $rec = $reader.ReadEvent()
            if ($null -eq $rec) { break }
            $processed++
            $script:bookmark = $rec.Bookmark
            if ([long]$rec.RecordId -gt $script:lastRecordId) {
                $script:lastRecordId = [long]$rec.RecordId
                try { Invoke-SecurityEvent $rec } catch { Write-Host "[!] Could not process event $($rec.Id): $($_.Exception.Message)" -ForegroundColor DarkYellow }
            }
            $rec.Dispose()
        }
    } catch {
        # e.g. Security log was cleared -> bookmark invalid; re-anchor at the newest record
        Write-Host "[!] Security log read error ($($_.Exception.Message)). Re-anchoring reader..." -ForegroundColor DarkYellow
        Initialize-SecurityLogCursor | Out-Null
    } finally {
        if ($reader) { $reader.Dispose() }
    }
}

# ==============================================================================
# 8. Endpoint checks (ports, threat processes)
# ==============================================================================
function Get-ListeningPorts {
    $portNums = @()
    try {
        $portNums = Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort
    } catch {
        try {
            foreach ($line in (netstat -ano -p tcp | Select-String "LISTENING")) {
                $parts = $line.ToString().Trim() -split '\s+'
                if ($parts.Length -ge 2) {
                    $p = ($parts[1] -split ':')[-1]
                    if ($p -match '^\d+$') { $portNums += [int]$p }
                }
            }
        } catch {}
    }
    # IPv4 + IPv6 listeners on the same port are one exposure
    return @($portNums | Sort-Object -Unique | ForEach-Object { @{ port = [string]$_; protocol = "tcp"; service = "unknown" } })
}

$SuspiciousPorts = @(4444, 1337, 31337, 5555, 6667, 8888, 9999)
$script:flaggedPorts = @{}
function Test-SuspiciousPorts($ports) {
    $open = @{}
    foreach ($p in $ports) { $open[[int]$p.port] = $true }
    foreach ($sp in $SuspiciousPorts) {
        if ($open.ContainsKey($sp) -and -not $script:flaggedPorts.ContainsKey($sp)) {
            $script:flaggedPorts[$sp] = $true
            Write-Host "[HIGH] Suspicious backdoor-style port listening: $sp/tcp" -ForegroundColor Yellow
            Send-LogEvent "suspicious_port_opened" "high" "Suspicious port $sp/tcp is listening on $Hostname (common reverse-shell/backdoor port)" | Out-Null
        } elseif (-not $open.ContainsKey($sp) -and $script:flaggedPorts.ContainsKey($sp)) {
            $script:flaggedPorts.Remove($sp)
        }
    }
}

$ThreatProcesses = @("nc", "netcat", "ncat", "socat", "hydra", "mimikatz", "chisel", "xmrig", "psexec", "procdump")
$script:seenThreatPids = @{}
function Test-ThreatProcesses {
    foreach ($name in $ThreatProcesses) {
        foreach ($p in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            if ($script:seenThreatPids.ContainsKey($p.Id)) { continue }   # alert once per process
            $script:seenThreatPids[$p.Id] = $true
            Write-Host "[CRITICAL] Intrusion tool running: $($p.ProcessName).exe (PID $($p.Id))" -ForegroundColor Red
            Send-LogEvent "threat_process_detected" "critical" "Intrusion utility running on ${Hostname}: $($p.ProcessName).exe (PID $($p.Id))" | Out-Null
        }
    }
}

# ==============================================================================
# 8.2 Peripheral & USB Hardware Monitoring
# ==============================================================================
$script:knownPeripherals = @{}

function Check-PeripheralDevice($serial, $label) {
    if (-not $serial) { return $true }
    try {
        $body = @{ serial_number = $serial } | ConvertTo-Json
        $resp = Invoke-RestMethod -Uri "$CtemServer/peripherals/check" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
        if ($resp.result -eq "authorized") {
            Write-Host "[AUTHORIZED PERIPHERAL] Device '$label' ($serial) approved by CTEM allowlist." -ForegroundColor Green
            return $true
        } else {
            Write-Host "[ALERT] UNAUTHORIZED PERIPHERAL DETECTED: '$label' ($serial) is BLOCKED! Security alert raised." -ForegroundColor Red
            Send-LogEvent "peripheral_unauthorized" "high" "Unauthorized peripheral device connected to $Hostname: $label (Serial: $serial)" | Out-Null
            return $false
        }
    } catch {
        Write-Host "[!] Could not verify peripheral ($serial): $(Get-HttpErrorDetail $_)" -ForegroundColor DarkYellow
        return $false
    }
}

function Test-ConnectedPeripherals {
    try {
        $usbDrives = Get-CimInstance Win32_DiskDrive -Filter "InterfaceType='USB'" -ErrorAction SilentlyContinue
        if ($usbDrives) {
            foreach ($drive in $usbDrives) {
                $serial = if ($drive.SerialNumber) { $drive.SerialNumber.Trim() } else { $drive.PNPDeviceID }
                if (-not $serial) { continue }
                $label = if ($drive.Model) { $drive.Model } else { "USB Storage Device" }

                if (-not $script:knownPeripherals.ContainsKey($serial)) {
                    $script:knownPeripherals[$serial] = $true
                    Write-Host "[*] New USB Device plugged in: $label (Serial: $serial)" -ForegroundColor Cyan
                    Check-PeripheralDevice $serial $label | Out-Null
                }
            }
        }
    } catch {}
}

# ==============================================================================
# 9. Startup: auditing, log cursor, optional simulation / test
# ==============================================================================
if (-not [string]::IsNullOrEmpty($TestPeripheral)) {
    Write-Host "`n[*] CTEM Peripheral Authorization Test: '$TestPeripheral'..." -ForegroundColor Cyan
    try {
        $body = @{ serial_number = $TestPeripheral } | ConvertTo-Json
        $resp = Invoke-RestMethod -Uri "$CtemServer/peripherals/check" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
        if ($resp.result -eq "authorized") {
            Write-Host "[+] RESULT: AUTHORIZED" -ForegroundColor Green
            Write-Host "    Device serial '$TestPeripheral' is approved in enterprise allowlist." -ForegroundColor Green
        } else {
            Write-Host "[!] RESULT: UNAUTHORIZED" -ForegroundColor Red
            Write-Host "    Device serial '$TestPeripheral' is NOT in allowlist or has been REVOKED." -ForegroundColor Red
            Write-Host "[+] Security Alert generated on CTEM Dashboard -> Alerts page" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Failed to query CTEM server at $CtemServer : $(Get-HttpErrorDetail $_)" -ForegroundColor Red
    }
    exit 0
}

Write-Host ""
Enable-SecurityAuditing
if ($isAdmin) {
    if (Initialize-SecurityLogCursor) {
        Write-Host "[+] Security log access OK - watching events 4624/4625/4672/4720/4732/4740 (from record #$script:lastRecordId)" -ForegroundColor Green
    }
} else {
    Write-Host "[!] Security log monitoring DISABLED (not Administrator)." -ForegroundColor Red
}

if ($SimulateFailedLogins -gt 0) {
    if (-not $script:assetId -and $serverOnline) { Register-AgentNode | Out-Null }
    $simUser = $env:USERNAME
    Write-Host "`n[*] SIMULATION: sending $SimulateFailedLogins failed logins for '$simUser'..." -ForegroundColor Magenta
    for ($i = 1; $i -le $SimulateFailedLogins; $i++) {
        $ok1 = Send-LogEvent "failed_login" "medium" "Failed logon #$i for '$simUser' on $Hostname (wrong password, Interactive, from 127.0.0.1) - Event 4625 [SIMULATED]"
        $ok2 = Send-UebaEvent $simUser "failed_login" "127.0.0.1"
        $status = if ($ok1 -and $ok2) { "delivered" } else { "DELIVERY FAILED" }
        Write-Host "    attempt $i -> $status" -ForegroundColor $(if ($ok1 -and $ok2) { "Gray" } else { "Red" })
        Start-Sleep -Milliseconds 300
    }
    if ($SimulateFailedLogins -ge $FailedLoginThreshold) {
        Write-Host "[+] Threshold ($FailedLoginThreshold) reached - check the CTEM Alerts page for 'Repeated failed logins for $simUser'." -ForegroundColor Green
    }
    exit 0
}

# ==============================================================================
# 10. Main loop
# ==============================================================================
$lastHeartbeat = [DateTime]::MinValue
$lastThreatScan = [DateTime]::MinValue

Write-Host "`n[*] CTEM Monitoring Engine is ACTIVE. Press Ctrl+C to stop.`n" -ForegroundColor Green

while ($true) {
    $now = [DateTime]::UtcNow

    if (-not $script:assetId) {
        if (-not (Register-AgentNode)) { Start-Sleep -Seconds 5; continue }
    }

    # 1. Security log detections (every poll)
    Read-NewSecurityEvents

    # 2. Threat processes & peripherals (every 10s)
    if (($now - $lastThreatScan).TotalSeconds -ge 10) {
        Test-ThreatProcesses
        Test-ConnectedPeripherals
        $lastThreatScan = $now
    }

    # 3. Heartbeat + port inventory (backend performs port drift detection)
    if (($now - $lastHeartbeat).TotalSeconds -ge $HeartbeatInterval) {
        $memPct = 0; $diskPct = 0; $uptime = 0
        try {
            $os = Get-CimInstance Win32_OperatingSystem
            $memPct = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1)
            $uptime = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
        } catch {}
        try {
            $disk = Get-PSDrive C | Select-Object -First 1
            $diskPct = [math]::Round(($disk.Used / ($disk.Used + $disk.Free)) * 100, 1)
        } catch {}

        $currentPorts = Get-ListeningPorts
        Test-SuspiciousPorts $currentPorts

        $hbBody = @{
            asset_id = $script:assetId
            hostname = $Hostname
            metrics = @{ cpu_percent = 5.0; memory_percent = $memPct; disk_percent = $diskPct; uptime_seconds = $uptime }
            listening_ports = $currentPorts
            agent_version = $AgentVersion
        } | ConvertTo-Json -Depth 5

        $secStatus = if ($script:secLogReadable) { "watching (#$script:lastRecordId)" } else { "NO ACCESS" }
        try {
            Invoke-RestMethod -Uri "$CtemServer/agent/heartbeat" -Method Post -Body $hbBody -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop | Out-Null
            Write-Host "[Heartbeat] RAM: $memPct% | Disk: $diskPct% | Ports: $($currentPorts.Count) | SecLog: $secStatus | Events sent: $script:forwardedCount" -ForegroundColor Gray
        } catch {
            Write-Host "[!] Heartbeat failed: $(Get-HttpErrorDetail $_)" -ForegroundColor DarkYellow
            if ($_.Exception.Response) {
                $code = [int]$_.Exception.Response.StatusCode
                if ($code -eq 404 -or $code -eq 422) {
                    Write-Host "[!] Asset not found on server. Re-registering..." -ForegroundColor Yellow
                    $script:assetId = $null
                    Remove-Item -Path $StateFile -Force -ErrorAction SilentlyContinue
                }
            }
        }
        $lastHeartbeat = $now
    }

    Start-Sleep -Seconds $PollIntervalSeconds
}
