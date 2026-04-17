# ==============================================================================
# Windows Service Auditor
# logic: Registry -> Get-Service -> SC Query
# ==============================================================================

# 1. Get current user + all group SIDs
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userSIDs = $currentUser.Groups | ForEach-Object { $_.Value }
$userSIDs += $currentUser.User.Value

# Well-known SID mapping (SDDL short names)
$sddlMap = @{ 
    "AU"="S-1-5-11"; "BA"="S-1-5-32-544"; "BU"="S-1-5-32-545"; 
    "IU"="S-1-5-4"; "SU"="S-1-5-6"; "SY"="S-1-5-18"; 
    "LS"="S-1-5-19"; "NS"="S-1-5-20"; "WD"="S-1-1-0"; "RD"="S-1-5-32-555" 
}

$serviceNames = @()

# Attempt 1: Registry
try {
    $serviceNames = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction Stop | Select-Object -ExpandProperty PSChildName
    Write-Host "[*] Enumerating via Registry..." -ForegroundColor Gray
} catch {
    # Attempt 2: PowerShell Get-Service
    try {
        Write-Host "[!] Registry blocked. Trying Get-Service..." -ForegroundColor Yellow
        $serviceNames = Get-Service -ErrorAction Stop | Select-Object -ExpandProperty Name
    } catch {
        # Attempt 3: Native sc.exe query
        Write-Host "[!!] Get-Service blocked. Falling back to sc.exe query..." -ForegroundColor Red
        $scQuery = sc.exe query state= all
        $serviceNames = $scQuery | Select-String "SERVICE_NAME: (.*)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
    }
}

# Remove duplicates if any
$serviceNames = $serviceNames | Select-Object -Unique

foreach ($serviceName in $serviceNames) {
    try {
        # 3. Get Service Permissions via SDDL
        $sddl = sc.exe sdshow $serviceName 2>$null
        if (-not $sddl -or $sddl -match "FAILED") { continue }

        $hasStart = $false; $hasStop = $false; $hasConf = $false
        $aces = $sddl -split '\)'
        
        foreach ($ace in $aces) {
            if ($ace -match '\(A;;([^;]+);;;([A-Z0-9\-]+)') {
                $rights = $matches[1]
                $idRaw = $matches[2]
                $sid = if ($idRaw -match '^S-1-') { $idRaw } else { $sddlMap[$idRaw] }
                
                if ($userSIDs -contains $sid) {
                    if ($rights -match 'RP') { $hasStart = $true }
                    if ($rights -match 'WP') { $hasStop  = $true }
                    if ($rights -match 'DC') { $hasConf  = $true }
                }
            }
        }

        # 4. DECISION LOGIC
        if ($hasConf) {
            Write-Host "[+] CONFIGURABLE SERVICE: $serviceName" -ForegroundColor Green
            continue 
        }

        if ($hasStart -or $hasStop) {
            # 5. Get Binary Path (Registry -> sc qc Fallback)
            $binPath = ""
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
            if (Test-Path $regPath) {
                $binPath = (Get-ItemProperty $regPath -Name "ImagePath" -ErrorAction SilentlyContinue).ImagePath
            }
            if (-not $binPath) {
                $qc = sc.exe qc $serviceName 2>$null
                if ($qc -match "BINARY_PATH_NAME\s+:\s+(.*)") { $binPath = $matches[1].Trim() }
            }

            if ($binPath) {
                # Clean path (Remove quotes/args)
                if ($binPath -match '^"([^"]+)"') { $cleanPath = $matches[1] } 
                else { $cleanPath = $binPath.Split(' ')[0] }

                if (-not (Test-Path $cleanPath)) { continue }
                $parentDir = Split-Path $cleanPath

                # Check Binary and Directory ACLs
                $targets = @($cleanPath, $parentDir)
                foreach ($target in $targets) {
                    $acl = Get-Acl $target -ErrorAction SilentlyContinue
                    if (-not $acl) { continue }

                    foreach ($access in $acl.Access) {
                        try {
                            $aceSid = $access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            if ($userSIDs -contains $aceSid) {
                                $perms = $access.FileSystemRights.ToString()
                                if ($perms -match "Write|Modify|FullControl|Delete") {
                                    $type = if ($target -eq $cleanPath) { "BINARY" } else { "DIRECTORY" }
                                    Write-Host "[!] WEAK $type PERMS: $serviceName" -ForegroundColor Cyan
                                    Write-Host "    -> Path: $target"
                                    Write-Host "    -> Your Rights: $perms"
                                    Write-Host "    -> Service Control: Start($hasStart) Stop($hasStop)"
                                }
                            }
                        } catch { continue }
                    }
                }
            }
        }
    } catch { continue }
}
