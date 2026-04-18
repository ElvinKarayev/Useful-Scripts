param(
    [switch]$obj,
    [switch]$help
)
if ($help) {
    Write-Host "Usage: script.ps1 or script.ps1 -obj"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -obj    Output results as objects instead of strings"
    Write-Host "  -help   Show this help message"
    Write-Host "Filter Options:"
    Write-Host "  ServiceName"
    Write-Host "  Rights"
    Write-Host "  Path"
    Write-Host "  Type:(BINARY, DIR, UnquotedPath, ConfigurableService)"
    return
}
# 1. Identity Setup
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userSIDs = $currentUser.Groups.Value + $currentUser.User.Value
$sddlMap = @{ "AU"="S-1-5-11"; "BA"="S-1-5-32-544"; "BU"="S-1-5-32-545"; "IU"="S-1-5-4"; "SU"="S-1-5-6"; "SY"="S-1-5-18"; "LS"="S-1-5-19"; "NS"="S-1-5-20"; "WD"="S-1-1-0"; "RD"="S-1-5-32-555" }

# 2. Rights Definitions
$writeBit    = [System.Security.AccessControl.FileSystemRights]::Write
$modifyBit   = [System.Security.AccessControl.FileSystemRights]::Modify
$fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
$changePerms = [System.Security.AccessControl.FileSystemRights]::ChangePermissions
$takeOwn     = [System.Security.AccessControl.FileSystemRights]::TakeOwnership

function Test-IsExploitable($acc) {
    if ($acc.PropagationFlags -match "InheritOnly") { return $false }
    $rights = $acc.FileSystemRights
    return (($rights -band $writeBit) -eq $writeBit -or ($rights -band $modifyBit) -eq $modifyBit -or ($rights -band $fullControl) -eq $fullControl -or ($rights -band $changePerms) -eq $changePerms -or ($rights -band $takeOwn) -eq $takeOwn)
}

# 3. Enumeration Status
$serviceNames = @()
try {
    $serviceNames = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction Stop | Select-Object -ExpandProperty PSChildName
    Write-Host "[*] Enumerating services via Registry..." -ForegroundColor Gray
} catch {
    try {
        Write-Host "[!] Registry access DENIED. Trying Get-Service..." -ForegroundColor Yellow
        $serviceNames = Get-Service -ErrorAction Stop | Select-Object -ExpandProperty Name
    } catch {
        Write-Host "[!!] Get-Service FAILED. Falling back to 'sc query'..." -ForegroundColor Red
        $scQuery = sc.exe query state= all
        $serviceNames = $scQuery | Select-String "SERVICE_NAME: (.*)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
    }
}
$serviceNames = $serviceNames | Select-Object -Unique

foreach ($serviceName in $serviceNames) {
    try {
        $sddl = sc.exe sdshow $serviceName 2>$null
        $hasStart = $false; $hasStop = $false; $hasConf = $false

        if ($sddl -and $sddl -notmatch "FAILED") {
            $aces = $sddl -split '\)'
            foreach ($ace in $aces) {
                # Extract Rights ($matches[1]) and SID ($matches[2])
                if ($ace -match '\(A;;([^;]+);;;([A-Z0-9\-]+)') {
                    $foundSid = $matches[2]
                    $perms = $matches[1]

                    # Resolve abbreviation to SID string if necessary
                    $resolvedSid = if ($sddlMap.ContainsKey($foundSid)) { $sddlMap[$foundSid] } else { $foundSid }

                    # THE CRITICAL CHECK: Does this ACE apply to YOU?
                    if ($userSIDs -contains $resolvedSid) {
                        # RP = Start | DT or WP = Stop | DC = Config | GA = Generic All
                        if ($perms -match 'RP|GA|GX') { $hasStart = $true }
                        if ($perms -match 'DT|WP|GA|GX') { $hasStop = $true }
                        if ($perms -match 'DC|GA') { $hasConf = $true }
                    }
                }
            }
        }

        # --- HIERARCHY: Config Access First ---
        if ($hasConf) {
            if (-not $obj) {
                Write-Host "[+] CONFIGURABLE SERVICE: ${serviceName}" -ForegroundColor Green
                Write-Host "    -> Control: Start($hasStart) Stop($hasStop)"
            }
            else {
                [PSCustomObject]@{
                    ServiceName = $serviceName
                    Type        = "ConfigurableService"
                    Path        = $null
                    Rights      = "SERVICE_CHANGE_CONFIG"
                    Start       = $hasStart
                    Stop        = $hasStop
                }
            }
            continue
        }

        # 5. Resolve Paths ONLY if we didn't have Config access
        $binPath = ""
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
        if (Test-Path $regPath) { $binPath = (Get-ItemProperty $regPath -Name "ImagePath" -ErrorAction SilentlyContinue).ImagePath }
        if (-not $binPath) { $qc = sc.exe qc $serviceName 2>$null; if ($qc -match "BINARY_PATH_NAME\s+:\s+(.*)") { $binPath = $matches[1].Trim() } }
        if (-not $binPath) { continue }

        if ($binPath -match '^"([^"]+)"') { $cleanPath = $matches[1] } 
        elseif ($binPath -match '^(.+\.(?:exe|dll|bat|cmd|com|sys))') { $cleanPath = $matches[1].Trim() }
        else { $cleanPath = $binPath.Split(' ')[0] }

        # --- MODULE 1: UNQUOTED HIJACK ---
        if ($binPath -notmatch '^"' -and $cleanPath -match ' ') {
	    $pathParts = $cleanPath.Split('\')
	    $pathBuild = ""
	    for ($i = 0; $i -lt ($pathParts.Count - 1); $i++) {
		
		# Build the path
		if ($pathBuild -eq "") { 
		    $pathBuild = $pathParts[$i] 
		} else { 
		    $pathBuild += "\" + $pathParts[$i] 
		}

		$testPath = $pathBuild
		if ($testPath -match '^[a-zA-Z]:$') { $testPath += "\" }

		if (Test-Path $testPath) {
		    $acl = Get-Acl $testPath -ErrorAction SilentlyContinue
            if (-not $acl) { continue }
		    foreach ($acc in $acl.Access) {
		        try {
		            $sid = $acc.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
		            if ($userSIDs -contains $sid -and (Test-IsExploitable $acc)) {
		                if (($i + 1) -lt $pathParts.Count -and $pathParts[$i+1] -match ' ') {
		                    $payload = $pathParts[$i+1].Split(' ')[0] + ".exe"
                            if (-not $obj){
		                        Write-Host "[!] UNQUOTED HIJACK: ${serviceName}" -ForegroundColor Magenta
		                        Write-Host "    -> Folder: ${testPath}" -ForegroundColor Cyan
		                        Write-Host "    -> Your Rights: $($acc.FileSystemRights)" -ForegroundColor Yellow
		                        Write-Host "    -> Control: Start($hasStart) Stop($hasStop)" -ForegroundColor White
                            }
                            else{
                                [PSCustomObject]@{
                                ServiceName = $serviceName
                                Type        = "UnquotedPath"
                                Path        = $testPath
                                Rights      = $acc.FileSystemRights
                                Start       = $hasStart
                                Stop        = $hasStop
                            }
                            }
		                }
		            }
		        } catch { continue }
		    }
		}
	    }
	}
        # --- MODULE 2: DIRECT FILE CHECK ---
        if (Test-Path $cleanPath) {
            $targets = @($cleanPath, (Split-Path $cleanPath))
            foreach ($t in $targets) {
                $acl = Get-Acl $t -ErrorAction SilentlyContinue
                if (-not $acl) { continue }
                foreach ($acc in $acl.Access) {
                    $sid = try { $acc.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
                    if ($userSIDs -contains $sid -and (Test-IsExploitable $acc)) {
                        $type = if ($t -eq $cleanPath) { "BINARY" } else { "DIR" }
                        if (-not $obj){
                            Write-Host "[!] DIRECT WEAKNESS (${type}): ${serviceName}" -ForegroundColor Cyan
                            Write-Host "    -> Path: ${t}" -ForegroundColor Gray
                            Write-Host "    -> Your Rights: $($acc.FileSystemRights)" -ForegroundColor Yellow # RESTORED
                            Write-Host "    -> Control: Start($hasStart) Stop($hasStop)" -ForegroundColor White
                        }
                        else{
                            [PSCustomObject]@{
                                ServiceName = $serviceName
                                Type        = $type
                                Path        = $t
                                Rights      = $acc.FileSystemRights
                                Start       = $hasStart
                                Stop        = $hasStop
                            }
                        }
                    }
                }
            }
        }
    } catch { continue }
}
