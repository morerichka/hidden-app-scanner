<#
  Scan-HiddenApps.ps1 - audit for hidden / masquerading programs (miners, spyware, RATs).
  READ-ONLY: deletes nothing, changes nothing, sends no data anywhere (except SHA256 hashes to VirusTotal if you opt in).
  Output: an HTML report in the reports\ folder.
#>
[CmdletBinding()]
param(
  [int]$SampleSeconds = 8,
  [string]$OutDir = '',
  [switch]$DeepFiles,
  [switch]$NoElevate,
  [switch]$NoOpen,
  [switch]$Pause,
  [switch]$SkipModules,
  [switch]$UseVirusTotal,
  [int]$VtMax = 60
)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutDir) { $OutDir = Join-Path $scriptDir 'reports' }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $NoElevate) {
  Write-Host 'Requesting administrator rights (needed to see all processes and services)...' -ForegroundColor Yellow
  $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Pause -SampleSeconds $SampleSeconds"
  if ($DeepFiles) { $argList += ' -DeepFiles' }
  if ($SkipModules) { $argList += ' -SkipModules' }
  if ($UseVirusTotal) { $argList += " -UseVirusTotal -VtMax $VtMax" }
  try { Start-Process powershell.exe -Verb RunAs -ArgumentList $argList -ErrorAction Stop; exit }
  catch { Write-Host 'UAC declined - continuing without administrator rights, the report will be less complete.' -ForegroundColor Yellow }
}

function Write-Step($t) { Write-Host "[*] $t" -ForegroundColor Cyan }

# ---------------------------------------------------------------- reference data
$winDir = $env:SystemRoot.ToLower()
$sys32 = "$winDir\system32"
$SysProc = @{
  'svchost.exe'       = @{ Dirs = @($sys32); Parent = 'services.exe' }
  'lsass.exe'         = @{ Dirs = @($sys32); Parent = 'wininit.exe' }
  'csrss.exe'         = @{ Dirs = @($sys32); Parent = '' }
  'services.exe'      = @{ Dirs = @($sys32); Parent = 'wininit.exe' }
  'wininit.exe'       = @{ Dirs = @($sys32); Parent = '' }
  'winlogon.exe'      = @{ Dirs = @($sys32); Parent = '' }
  'smss.exe'          = @{ Dirs = @($sys32); Parent = '' }
  'explorer.exe'      = @{ Dirs = @($winDir); Parent = '' }
  'taskhostw.exe'     = @{ Dirs = @($sys32); Parent = 'svchost.exe' }
  'runtimebroker.exe' = @{ Dirs = @($sys32); Parent = 'svchost.exe' }
  'dllhost.exe'       = @{ Dirs = @($sys32, "$winDir\syswow64"); Parent = '' }
  'conhost.exe'       = @{ Dirs = @($sys32); Parent = '' }
  'spoolsv.exe'       = @{ Dirs = @($sys32); Parent = 'services.exe' }
  'searchindexer.exe' = @{ Dirs = @($sys32); Parent = 'services.exe' }
  'fontdrvhost.exe'   = @{ Dirs = @($sys32); Parent = '' }
  'sihost.exe'        = @{ Dirs = @($sys32); Parent = 'svchost.exe' }
  'ctfmon.exe'        = @{ Dirs = @($sys32); Parent = '' }
  'dwm.exe'           = @{ Dirs = @($sys32); Parent = '' }
  'wmiprvse.exe'      = @{ Dirs = @("$sys32\wbem", "$winDir\syswow64\wbem"); Parent = 'svchost.exe' }
  'audiodg.exe'       = @{ Dirs = @($sys32); Parent = '' }
  'msmpeng.exe'       = @{ Dirs = @("$env:ProgramData\Microsoft\Windows Defender\Platform", "$env:ProgramFiles\Windows Defender"); Parent = '' }
  'securityhealthservice.exe' = @{ Dirs = @($sys32); Parent = '' }
}
$SysBaseNames = @($SysProc.Keys | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_) })

$MinerNames = 'xmrig|xmr-stak|minerd|cpuminer|nbminer|t-rex|phoenixminer|lolminer|gminer|teamredminer|claymore|ethminer|nanominer|srbminer|bzminer|cgminer|bfgminer|ccminer|kawpowminer|nicehash|minergate|ewbf|bminer|wildrig'
$MinerRx = 'stratum2?\+|xmrig|--donate-level|cryptonight|randomx|nicehash|minerd|cpuminer|ethminer|nbminer|phoenixminer|lolminer|teamredminer|--algo[ =]|-o\s+\S+:\d{4,5}\s+-u\s'
$MinerPorts = @(3333, 4444, 5555, 6666, 7777, 9999, 14433, 14444, 45560, 45700)
$RatRx = 'anydesk|teamviewer|tv_w32|tv_x64|rustdesk|ultravnc|winvnc|tightvnc|tvnserver|screenconnect|connectwise|splashtop|srservice|ammyy|aa_v3|logmein|lmiignition|meshagent|remotepc|supremo|ateraagent|netsupport|client32|radmin|rutserv|rfusclient|dwagent|dameware|remoteutilities|zohoassist|gotomypc|g2ax|ngrok|frpc|remoting_host|screenconnect'
$SpyRx = 'keylog|spyrix|refog|kidlogger|hoverwatch|actualspy|actual spy|webwatcher|qustodio|flexispy|spytech|netvizor|realtime-spy|pc pandora|pcpandora|ardamax|wolfeye|teramind|activtrak|veriato|hubstaff|time doctor|timedoctor|controlio|work examiner|workexaminer|interguard|staffcop|kickidler|mipko|bosspy|sniperspy|spector ?pro|mobistealth|spyera|ikeymonitor|clevguard|kidsguard|spyhuman|employee monitor|stealthgenie|lightlogger|revealer'
$AvDomainRx = 'microsoft|windowsupdate|defender|kaspersky|avast|avg\.|eset|malwarebytes|virustotal|bitdefender|norton|mcafee|sophos|trendmicro|drweb|avira'

# ---------------------------------------------------------------- helper functions
function Esc($s) { if ($null -eq $s) { return '' }; return [System.Net.WebUtility]::HtmlEncode([string]$s) }

function Get-Lev($a, $b) {
  $la = $a.Length; $lb = $b.Length
  $d = New-Object 'int[,]' ($la + 1), ($lb + 1)
  for ($i = 0; $i -le $la; $i++) { $d[$i, 0] = $i }
  for ($j = 0; $j -le $lb; $j++) { $d[0, $j] = $j }
  for ($i = 1; $i -le $la; $i++) {
    for ($j = 1; $j -le $lb; $j++) {
      $c = if ($a[$i - 1] -eq $b[$j - 1]) { 0 } else { 1 }
      $i1 = $i - 1; $j1 = $j - 1
      $x1 = $d[$i1, $j] + 1
      $x2 = $d[$i, $j1] + 1
      $x3 = $d[$i1, $j1] + $c
      $d[$i, $j] = [Math]::Min([Math]::Min($x1, $x2), $x3)
    }
  }
  return $d[$la, $lb]
}

function Test-PrivateIp($ip) {
  if (-not $ip) { return $true }
  if ($ip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|::1$|::$|fe80:|fc|fd)') { return $true }
  return $false
}

$FileCache = @{}
function Normalize-Path($p) {
  if ([string]::IsNullOrWhiteSpace($p)) { return $p }
  $p = $p -replace '^\\\\\?\\', '' -replace '^\\\?\?\\', ''
  if ($p -match '^\\SystemRoot\\') { $p = $env:SystemRoot + $p.Substring(11) }
  return $p
}

function Get-FileTrust($path) {
  $path = Normalize-Path $path
  if ([string]::IsNullOrWhiteSpace($path)) { return $null }
  $key = $path.ToLower()
  if ($FileCache.ContainsKey($key)) { return $FileCache[$key] }
  $o = [pscustomobject]@{ Path = $path; Exists = $false; Status = ''; Signer = ''; IsMs = $false; Hash = ''; Company = ''; Size = 0; NotBefore = $null }
  if (Test-Path -LiteralPath $path -PathType Leaf) {
    $o.Exists = $true
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    $o.Status = [string]$sig.Status
    if ($sig.SignerCertificate) {
      $s = $sig.SignerCertificate.Subject
      if ($s -match 'CN="([^"]+)"') { $o.Signer = $Matches[1] }
      elseif ($s -match 'CN=([^,]+)') { $o.Signer = $Matches[1] }
      else { $o.Signer = $s }
    }
    if ($sig.SignerCertificate) { $o.NotBefore = $sig.SignerCertificate.NotBefore }
    $o.IsMs = ($o.Status -eq 'Valid' -and $o.Signer -match '^Microsoft (Windows|Corporation|Windows Publisher)$')
    $fi = Get-Item -LiteralPath $path -Force
    $o.Size = $fi.Length
    $o.Company = $fi.VersionInfo.CompanyName
    if ($fi.Length -lt 200MB) { $o.Hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
  }
  $FileCache[$key] = $o
  return $o
}

function Get-ExePathFromCommand($cmd) {
  if ([string]::IsNullOrWhiteSpace($cmd)) { return $null }
  $c = $cmd.Trim()
  if ($c -match '^"([^"]+)"') { $p = $Matches[1] }
  elseif ($c -match '^([A-Za-z]:\\.*?\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js))(\s|$)') { $p = $Matches[1] }
  elseif ($c -match '^(\S+)') { $p = $Matches[1] }
  else { return $null }
  $p = [Environment]::ExpandEnvironmentVariables($p)
  if ($p -match '^[A-Za-z]:\\') { return $p }
  foreach ($base in @("$env:SystemRoot\System32", $env:SystemRoot)) {
    $cand = Join-Path $base $p
    if (Test-Path -LiteralPath $cand -PathType Leaf) { return $cand }
  }
  return $null
}

function Get-LocationReason($path) {
  $l = $path.ToLower()
  if ($l -match '\\appdata\\local\\temp\\|\\windows\\temp\\|\\temp\\|\\tmp\\') { return @{ P = 3; T = 'runs from a Temp folder (typical place for malware)' } }
  if ($l -match '\\users\\public\\|\\\$recycle\.bin\\|\\downloads\\') { return @{ P = 3; T = 'runs from Public / Downloads / Recycle Bin' } }
  if ($l -match '\\programdata\\' -and $l -notmatch '\\programdata\\(microsoft|package cache)\\') { return @{ P = 2; T = 'runs from ProgramData' } }
  if ($l -match '\\appdata\\(roaming|local)\\') { return @{ P = 1; T = 'runs from AppData (legitimate programs do this too, and so does malware)' } }
  return $null
}

function Get-PathReasons($path, [switch]$Stale) {
  $r = New-Object System.Collections.Generic.List[object]
  $path = Normalize-Path $path
  if ([string]::IsNullOrWhiteSpace($path)) { return ,$r }
  $t = Get-FileTrust $path
  if (-not $t.Exists) {
    if ($Stale) { $r.Add(@{ P = 1; T = 'entry points to a file that does not exist (most likely the program was uninstalled but the entry remained)' }) }
    else { $r.Add(@{ P = 5; T = 'the running process image is missing on disk (deleted after launch or replaced)' }) }
    return ,$r
  }
  $isStore = ($path -match '\\WindowsApps\\')
  $name = [IO.Path]::GetFileName($path).ToLower()
  $ext = [IO.Path]::GetExtension($name)
  $dir = [IO.Path]::GetDirectoryName($path).ToLower()
  $base = [IO.Path]::GetFileNameWithoutExtension($name)

  if ($ext -in '.exe', '.dll', '.sys', '.scr', '.com' -and -not $isStore) {
    switch ($t.Status) {
      'Valid' { }
      'UnknownError' { $r.Add(@{ P = 1; T = 'could not verify the signature' }) }
      'NotSigned' { $r.Add(@{ P = 2; T = 'no digital signature' }) }
      'HashMismatch' { $r.Add(@{ P = 6; T = 'signed, but the file was modified after signing (HashMismatch)' }) }
      default { $r.Add(@{ P = 3; T = "signature is invalid ($($t.Status))" }) }
    }
  }
  if (-not $isStore) { $loc = Get-LocationReason $path; if ($loc) { $r.Add($loc) } }

  if ($SysProc.ContainsKey($name)) {
    $ok = $false
    foreach ($d in $SysProc[$name].Dirs) {
      $dl = $d.ToLower()
      if ($dir -eq $dl -or $dir.StartsWith($dl + '\')) { $ok = $true }
    }
    if (-not $ok) { $r.Add(@{ P = 8; T = "masquerades as the system process $name but lives in $dir" }) }
    elseif (-not $t.IsMs) { $r.Add(@{ P = 6; T = "has the name of the system process $name but is not signed by Microsoft ($($t.Signer))" }) }
  }
  elseif (-not $t.IsMs -and $base.Length -ge 5) {
    foreach ($sn in $SysBaseNames) {
      $dist = Get-Lev $base $sn
      if (($dist -eq 1) -or ($dist -eq 2 -and $base.Length -ge 8)) {
        $r.Add(@{ P = 8; T = "the name '$base' looks suspiciously like the system name '$sn'" }); break
      }
    }
  }
  if (($name -match '[a-z]') -and ($name -match '[\u0400-\u04FF]')) { $r.Add(@{ P = 5; T = 'the file name mixes Latin and Cyrillic letters (homoglyph trick)' }) }
  if ($name -match '\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip|rar)\.(exe|scr|com|bat|cmd)$') { $r.Add(@{ P = 7; T = 'double extension (document.pdf.exe)' }) }
  if ($t.Status -ne 'Valid' -and $base -match '^[a-z0-9]{6,16}$' -and $base -match '\d' -and $base -match '[a-z]') {
    $r.Add(@{ P = 2; T = 'the file name looks like random characters' })
  }
  if ($base -match $MinerNames) { $r.Add(@{ P = 8; T = 'the file name matches a known miner' }) }
  if ($base -match $SpyRx) { $r.Add(@{ P = 6; T = 'the file name matches known stalkerware / a keylogger' }) }
  elseif ($base -match $RatRx) { $r.Add(@{ P = 4; T = 'remote-access tool - make sure you installed it yourself' }) }
  return ,$r
}

function Get-CmdReasons($cmd) {
  $r = New-Object System.Collections.Generic.List[object]
  if ([string]::IsNullOrWhiteSpace($cmd)) { return ,$r }
  if ($cmd -match $MinerRx) { $r.Add(@{ P = 8; T = 'the command line shows miner indicators (stratum pool / algorithm / wallet)' }) }
  if ($cmd -match '(?i)\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}') { $r.Add(@{ P = 5; T = 'encoded (base64) PowerShell command' }) }
  if ($cmd -match '(?i)-w(indowstyle)?\s+hidden') { $r.Add(@{ P = 3; T = 'launched with a hidden window' }) }
  if ($cmd -match '(?i)downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient') { $r.Add(@{ P = 4; T = 'PowerShell downloads data from the network right in the command' }) }
  if ($cmd -match '(?i)frombase64string') { $r.Add(@{ P = 3; T = 'the command decodes base64 and possibly runs hidden code' }) }
  if ($cmd -match '(?i)\biex\b|invoke-expression') { $r.Add(@{ P = 2; T = 'the command executes a string as code (Invoke-Expression) - seen in legitimate shells and in malicious scripts' }) }
  if ($cmd -match '(?i)(mshta|regsvr32|certutil|bitsadmin|wscript|cscript)(\.exe)?["'']?\s.*https?://') { $r.Add(@{ P = 5; T = 'a system utility runs something from an internet URL' }) }
  if ($cmd -match '(?i)certutil.*-urlcache') { $r.Add(@{ P = 5; T = 'certutil downloads a file from the internet' }) }
  return ,$r
}

function Sum-Reasons($list) {
  $seen = @{}; $sum = 0
  foreach ($x in $list) { if (-not $seen.ContainsKey($x.T)) { $seen[$x.T] = 1; $sum += $x.P } }
  return $sum
}
function Uniq-Texts($list) {
  $seen = @{}; $out = New-Object System.Collections.Generic.List[string]
  foreach ($x in ($list | Sort-Object { -$_.P })) { if (-not $seen.ContainsKey($x.T)) { $seen[$x.T] = 1; $out.Add($x.T) } }
  return ,$out
}
function Get-SevClass($pts) { if ($pts -ge 8) { 'high' } elseif ($pts -ge 4) { 'med' } elseif ($pts -ge 2) { 'low' } else { 'info' } }
function Get-SevName($pts) { if ($pts -ge 8) { 'High' } elseif ($pts -ge 4) { 'Medium' } elseif ($pts -ge 2) { 'Low' } else { 'Info' } }

$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding($Points, $Category, $Title, $Reasons, $Target, $Hash) {
  if ($Points -lt 2) { return }
  $Findings.Add([pscustomobject]@{ Points = $Points; Category = $Category; Title = $Title; Reasons = @($Reasons); Target = $Target; Hash = $Hash })
}

# ---------------------------------------------------------------- 1. processes + CPU/GPU sampling
Write-Step 'Collecting processes and network connections...'
$cim = @(Get-CimInstance Win32_Process)
$byId = @{}
foreach ($p in $cim) { $byId[[int]$p.ProcessId] = $p }
$cores = [Environment]::ProcessorCount

$netByPid = @{}
foreach ($c in @(Get-NetTCPConnection)) {
  if ($c.State -notin 'Established', 'Listen') { continue }
  $id = [int]$c.OwningProcess
  if (-not $netByPid.ContainsKey($id)) { $netByPid[$id] = New-Object System.Collections.Generic.List[object] }
  $netByPid[$id].Add($c)
}

Write-Step "Sampling CPU/GPU load ($SampleSeconds s) - better not to run anything meanwhile..."
$cpu0 = @{}
foreach ($p in [Diagnostics.Process]::GetProcesses()) { try { $cpu0[$p.Id] = $p.TotalProcessorTime.TotalSeconds } catch { } }
$sw = [Diagnostics.Stopwatch]::StartNew()
$gpuSum = @{}; $gpuN = 0
try {
  $gs = Get-Counter -Counter '\GPU Engine(*)\Utilization Percentage' -SampleInterval 1 -MaxSamples $SampleSeconds -ErrorAction Stop
  foreach ($s in $gs) {
    $gpuN++
    foreach ($c in $s.CounterSamples) {
      if ($c.InstanceName -match 'pid_(\d+)_') {
        $id = [int]$Matches[1]
        if (-not $gpuSum.ContainsKey($id)) { $gpuSum[$id] = 0.0 }
        $gpuSum[$id] += $c.CookedValue
      }
    }
  }
} catch {
  $rest = $SampleSeconds - $sw.Elapsed.TotalSeconds
  if ($rest -gt 0) { Start-Sleep -Seconds ([int][Math]::Ceiling($rest)) }
}
$el = [Math]::Max($sw.Elapsed.TotalSeconds, 1)
$cpuPct = @{}
foreach ($p in [Diagnostics.Process]::GetProcesses()) {
  try { if ($cpu0.ContainsKey($p.Id)) { $cpuPct[$p.Id] = [Math]::Round(($p.TotalProcessorTime.TotalSeconds - $cpu0[$p.Id]) / ($el * $cores) * 100, 1) } } catch { }
}
$gpuPct = @{}
foreach ($k in $gpuSum.Keys) { $gpuPct[$k] = [Math]::Min(100, [Math]::Round($gpuSum[$k] / [Math]::Max($gpuN, 1), 1)) }

Write-Step 'Checking signatures and process behavior...'
$groups = @{}
foreach ($p in $cim) {
  $id = [int]$p.ProcessId
  if ($id -eq 0 -or $id -eq 4 -or $id -eq $PID) { continue }
  $key = if ($p.ExecutablePath) { $p.ExecutablePath.ToLower() } else { 'name:' + $p.Name.ToLower() }
  if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object] }
  $groups[$key].Add($p)
}

$TopLoad = New-Object System.Collections.Generic.List[object]
$NetRows = New-Object System.Collections.Generic.List[object]
$pseudo = 'system', 'registry', 'memory compression', 'secure system', 'vmmem', 'vmmemwsl', 'system idle process'

foreach ($key in $groups.Keys) {
  $inst = $groups[$key]
  $first = $inst[0]
  $name = $first.Name; $lname = $name.ToLower()
  $path = $first.ExecutablePath
  $reasons = New-Object System.Collections.Generic.List[object]
  $trust = $null
  if ($path) {
    foreach ($x in (Get-PathReasons $path)) { $reasons.Add($x) }
    $trust = Get-FileTrust $path
  } elseif ($isAdmin -and $lname -notin $pseudo) {
    $reasons.Add(@{ P = 1; T = 'could not determine the process image path (normal for protected system processes)' })
  }

  $cmdHits = New-Object System.Collections.Generic.List[string]
  $cpuSum = 0.0; $gpuMax = 0.0
  $ext = 0; $mine = New-Object System.Collections.Generic.List[string]; $listenAll = 0
  foreach ($p in $inst) {
    $id = [int]$p.ProcessId
    foreach ($x in (Get-CmdReasons $p.CommandLine)) {
      $reasons.Add($x)
      if ($cmdHits.Count -lt 2 -and $p.CommandLine -notin $cmdHits) { $cmdHits.Add($p.CommandLine) }
    }
    if ($lname -eq 'svchost.exe' -and $p.CommandLine -and $p.CommandLine -notmatch '\s-k\s') {
      $reasons.Add(@{ P = 5; T = 'svchost started without the -k parameter (real svchost instances always have it)' })
    }
    if ($SysProc.ContainsKey($lname) -and $SysProc[$lname].Parent) {
      $par = $byId[[int]$p.ParentProcessId]
      if ($par -and $par.Name.ToLower() -ne $SysProc[$lname].Parent) {
        $reasons.Add(@{ P = 4; T = "unexpected parent process:$($par.Name) (expected$($SysProc[$lname].Parent))" })
      }
    }
    if ($cpuPct.ContainsKey($id)) { $cpuSum += $cpuPct[$id] }
    if ($gpuPct.ContainsKey($id) -and $gpuPct[$id] -gt $gpuMax) { $gpuMax = $gpuPct[$id] }
    foreach ($c in $netByPid[$id]) {
      if ($c.State -eq 'Listen') {
        if ($c.LocalAddress -in '0.0.0.0', '::') { $listenAll++ }
      } elseif (-not (Test-PrivateIp $c.RemoteAddress)) {
        $ext++
        if ([int]$c.RemotePort -in $MinerPorts) { $mine.Add("$($c.RemoteAddress):$($c.RemotePort)") }
        $NetRows.Add([pscustomobject]@{ Process = $name; ProcId = $id; Remote = $c.RemoteAddress; Port = $c.RemotePort; Signer = $(if ($trust) { $trust.Signer } else { '' }); Status = $(if ($trust) { $trust.Status } else { '' }); Path = $path })
      }
    }
  }
  $notValid = [bool]($trust -and $trust.Status -ne 'Valid' -and $path -notmatch '\\WindowsApps\\')
  if ($cpuSum -ge 25 -and $notValid -and $lname -notin $pseudo) { $reasons.Add(@{ P = 2; T = "high CPU load ($([Math]::Round($cpuSum,0))% of all cores) from an unsigned program" }) }
  if ($gpuMax -ge 40 -and $notValid -and $lname -notin $pseudo) { $reasons.Add(@{ P = 2; T = "high GPU load ($gpuMax%) from an unsigned program" }) }
  if ($ext -gt 0 -and $notValid -and $lname -notin $pseudo) { $reasons.Add(@{ P = 2; T = "an unsigned program talks to the internet ($ext connections)" }) }
  if ($mine.Count -gt 0) { $reasons.Add(@{ P = 3; T = "connections to ports typical for mining pools:$((@($mine | Select-Object -Unique)) -join ', ')" }) }
  if ($listenAll -gt 0 -and $notValid -and $lname -notin $pseudo) { $reasons.Add(@{ P = 2; T = 'an unsigned program listens for incoming network connections' }) }

  $TopLoad.Add([pscustomobject]@{ Name = $name; Count = $inst.Count; Cpu = [Math]::Round($cpuSum, 1); Gpu = $gpuMax; Signer = $(if ($trust) { $trust.Signer } else { '' }); Path = $path })

  $pts = Sum-Reasons $reasons
  if ($pts -ge 2) {
    $ids = ($inst | Select-Object -First 5 | ForEach-Object { $_.ProcessId }) -join ', '
    $title = "$name  (PID: $ids$(if ($inst.Count -gt 5) { '...' }))"
    $tgt = if ($path) { $path } else { '(path unknown)' }
    if ($cmdHits.Count -gt 0) { foreach ($ch in $cmdHits) { $tgt += "`n> " + $(if ($ch.Length -gt 400) { $ch.Substring(0, 400) + '...' } else { $ch }) } }
    elseif ($inst[0].CommandLine -and $inst.Count -eq 1) { $tgt += "`n" + $inst[0].CommandLine }
    Add-Finding $pts 'Process' $title (Uniq-Texts $reasons) $tgt $(if ($trust) { $trust.Hash } else { '' })
  }
}

# hidden processes: cross-check two sources
Write-Step 'Cross-checking process lists (looking for processes hidden from Task Manager)...'
$gpIds = @([Diagnostics.Process]::GetProcesses() | ForEach-Object { $_.Id })
$cimIds = @(Get-CimInstance Win32_Process | ForEach-Object { [int]$_.ProcessId })
$onlyGp = @($gpIds | Where-Object { $_ -ne 0 -and $_ -notin $cimIds })
Start-Sleep -Milliseconds 700
foreach ($id in $onlyGp) {
  $still = Get-Process -Id $id
  $inCim = Get-CimInstance Win32_Process -Filter "ProcessId=$id"
  if ($still -and -not $inCim) {
    Add-Finding 4 'Process' "PID $id ($($still.ProcessName)) is visible in one process listing but hidden in another" @('mismatch between two ways of listing processes - a rootkit sign; often a false alarm (the process has just exited)') '' ''
  }
}

# ---------------------------------------------------------------- 1b. injected DLLs and memory without a file
$ForeignDlls = New-Object System.Collections.Generic.List[object]
function Test-SameApp($a, $b) {
  $sa = $a.ToLower().Split('\'); $sb2 = $b.ToLower().Split('\')
  $n = 0
  for ($i = 0; $i -lt [Math]::Min($sa.Length, $sb2.Length); $i++) { if ($sa[$i] -eq $sb2[$i]) { $n++ } else { break } }
  $need = if ($a.ToLower() -match '^[a-z]:\\users\\') { 6 } else { 3 }
  return ($n -ge $need)
}

if (-not $SkipModules) {
  if (-not $isAdmin) { Write-Host '[!] Without administrator rights the module list is unavailable for many processes - the DLL check will be incomplete.' -ForegroundColor Yellow }
  Write-Step 'Checking DLLs loaded into processes (injection) and executable memory without a file - the slowest stage...'
  if (-not ('MemScan' -as [type])) {
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class MemScan {
  [StructLayout(LayoutKind.Sequential)] public struct MBI { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }
  [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern UIntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, UIntPtr len);
  public static int CountRwx(int pid) {
    IntPtr h = OpenProcess(0x0400, false, pid);
    if (h == IntPtr.Zero) return -1;
    int n = 0; long addr = 0; MBI m;
    while (VirtualQueryEx(h, (IntPtr)addr, out m, (UIntPtr)Marshal.SizeOf(typeof(MBI))) != UIntPtr.Zero) {
      long size = m.RegionSize.ToInt64();
      if (m.State == 0x1000 && m.Type == 0x20000 && m.Protect == 0x40) n++;
      addr = m.BaseAddress.ToInt64() + size;
      if (size <= 0 || addr <= 0 || addr > 0x7FFFFFFFFFFF) break;
    }
    CloseHandle(h);
    return n;
  }
}
'@
  }
  $jitHosts = 'powershell|pwsh|dotnet|code|node|electron|chrome|msedge|firefox|brave|discord|slack|teams|telegram|claude|java|python|steam|epicgames|cef|webview'
  $modSeen = @{}
  $rwxOne = New-Object System.Collections.Generic.List[string]
  foreach ($pr in [Diagnostics.Process]::GetProcesses()) {
    if ($pr.Id -le 4 -or $pr.Id -eq $PID) { continue }
    $exePath = $null; $mods = $null
    try { $exePath = Normalize-Path $pr.MainModule.FileName; $mods = $pr.Modules } catch { continue }
    if (-not $exePath -or -not $mods) { continue }
    $pt = Get-FileTrust $exePath
    $pIsSystem = [bool]($pt -and $pt.IsMs)
    $pname = $pr.ProcessName
    foreach ($m in $mods) {
      $mp = Normalize-Path $m.FileName
      if (-not $mp -or $mp -ieq $exePath) { continue }
      $k = ($pname + '|' + $mp).ToLower()
      if ($modSeen.ContainsKey($k)) { continue }
      $modSeen[$k] = 1
      $mt = Get-FileTrust $mp
      if (-not $mt) { continue }
      $isStore = ($mp -match '\\WindowsApps\\' -or $mp -match '(?i)\\windows\\(assembly\\nativeimages_|microsoft\.net\\assembly\\)')
      $reasons = New-Object System.Collections.Generic.List[object]
      if (-not $mt.Exists) {
        $reasons.Add(@{ P = 4; T = 'a DLL is loaded into the process but its file is missing on disk (deleted or replaced)' })
      } else {
        $loc = Get-LocationReason $mp
        if ($mt.Status -eq 'HashMismatch') { $reasons.Add(@{ P = 6; T = 'the DLL was modified after signing (HashMismatch)' }) }
        if ($pIsSystem) {
          if ($mt.Status -notin 'Valid', 'UnknownError' -and -not $isStore) { $reasons.Add(@{ P = 5; T = "a DLL without a valid signature is loaded into the Microsoft system process ($pname) ($($mt.Status))" }) }
          elseif ($loc -and $loc.P -ge 2 -and -not $mt.IsMs) { $reasons.Add(@{ P = 6; T = "a DLL from a user-writable folder is loaded into the system process ($pname)" }) }
          elseif (-not $mt.IsMs -and $mt.Exists -and $mp -notmatch '(?i)\\assembly\\nativeimages_') { $ForeignDlls.Add([pscustomobject]@{ Process = $pname; Dll = $mp; Signer = $mt.Signer; Status = $mt.Status }) }
        } else {
          if ($mt.Status -eq 'NotSigned' -and -not $isStore -and -not (Test-SameApp $exePath $mp) -and $mp -notmatch '(?i)^c:\\windows\\') {
            $reasons.Add(@{ P = 3; T = "an unsigned DLL located away from the program $pname (injection or a foreign library)" })
          }
          if ($loc -and $loc.P -ge 3 -and -not (Test-SameApp $exePath $mp)) { $reasons.Add($loc) }
        }
      }
      $pts = Sum-Reasons $reasons
      if ($pts -ge 3) { Add-Finding $pts 'Injected DLL' "$pname <- $([IO.Path]::GetFileName($mp))" (Uniq-Texts $reasons) $mp $mt.Hash }
    }
    # executable memory without a file - only in processes where JIT is not expected
    if ($exePath.ToLower().StartsWith($winDir) -and $pname -notmatch $jitHosts) {
      $n = [MemScan]::CountRwx($pr.Id)
      $isDotnet = [bool]($mods | Where-Object { $_.ModuleName -match '^(clr|coreclr|clrjit|mscoree)\.dll$' })
      if ($n -eq 1) { $rwxOne.Add("$pname (PID $($pr.Id))") }
      elseif ($n -ge 2 -and -not $isDotnet) {
        Add-Finding 4 'Injected DLL' "$pname (PID $($pr.Id)): $n memory regions that are read+write+execute without a backing file" @('a system process without .NET/JIT has several executable memory regions not backed by a file - this is what injected code (shellcode, reflective DLL) looks like. Protective drivers can do this too') $exePath ''
      }
    }
  }
  if ($rwxOne.Count -ge 3) {
    Add-Finding 2 'Injected DLL' "$($rwxOne.Count) system processes each have one executable memory region without a file (uniform pattern)" @('the same picture across many processes points to a shared mechanism rather than targeted injection: usually protective hooks of an antivirus or driver. If you have no antivirus, take a closer look') (($rwxOne | Select-Object -First 25) -join ', ') ''
  }
}
# ---------------------------------------------------------------- 2. autostart
$Autoruns = New-Object System.Collections.Generic.List[object]
function Test-Autorun($Source, $Name, $Cmd, $Category) {
  $exp = [Environment]::ExpandEnvironmentVariables([string]$Cmd)
  $reasons = New-Object System.Collections.Generic.List[object]
  $path = Get-ExePathFromCommand $exp
  $trust = $null
  if ($path) {
    foreach ($x in (Get-PathReasons $path -Stale)) { $reasons.Add($x) }
    $trust = Get-FileTrust $path
  }
  foreach ($x in (Get-CmdReasons $exp)) { $reasons.Add($x) }
  # scripts in user folders launched through interpreters
  foreach ($m in [regex]::Matches($exp, '([A-Za-z]:\\[^"''\r\n]+?\.(ps1|vbs|vbe|js|jse|bat|cmd|hta|wsf))', 'IgnoreCase')) {
    $sp = $m.Groups[1].Value
    $lr = Get-LocationReason $sp
    if ($lr) { $reasons.Add(@{ P = [Math]::Max($lr.P, 2); T = "runs a script from a user-writable folder:$sp" }) }
    if (-not (Test-Path -LiteralPath $sp)) { $reasons.Add(@{ P = 3; T = "script not found:$sp" }) }
  }
  $pts = Sum-Reasons $reasons
  $isMs = ($trust -and $trust.IsMs)
  $Autoruns.Add([pscustomobject]@{ Source = $Source; Name = $Name; Command = $exp; Signer = $(if ($trust) { $trust.Signer } else { '' }); Status = $(if ($trust) { $trust.Status } else { '?' }); IsMs = $isMs; Points = $pts; Hash = $(if ($trust) { $trust.Hash } else { '' }) })
  if ($pts -ge 2) {
    Add-Finding $pts $Category "$Source`: $Name" (Uniq-Texts $reasons) $exp $(if ($trust) { $trust.Hash } else { '' })
  }
}

Write-Step 'Checking autostart (registry, Startup folders)...'
$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)
foreach ($k in $runKeys) {
  $props = Get-ItemProperty -Path $k
  if (-not $props) { continue }
  foreach ($pr in $props.PSObject.Properties) {
    if ($pr.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
    Test-Autorun ($k -replace '^HKLM:\\SOFTWARE\\', 'HKLM\' -replace '^HKCU:\\SOFTWARE\\', 'HKCU\') $pr.Name ([string]$pr.Value) 'Autostart'
  }
}
$wsh = New-Object -ComObject WScript.Shell
foreach ($sf in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
  foreach ($f in @(Get-ChildItem -LiteralPath $sf -File -Force)) {
    if ($f.Name -ieq 'desktop.ini') { continue }
    if ($f.Extension -ieq '.lnk') {
      $lnk = $wsh.CreateShortcut($f.FullName)
      Test-Autorun 'Startup folder' $f.Name ("`"$($lnk.TargetPath)`" $($lnk.Arguments)") 'Autostart'
    } else {
      Test-Autorun 'Startup folder' $f.Name ("`"$($f.FullName)`"") 'Autostart'
    }
  }
}

Write-Step 'Checking scheduled tasks...'
foreach ($t in @(Get-ScheduledTask)) {
  $isMsTask = ($t.TaskPath -like '\Microsoft\*')
  foreach ($a in $t.Actions) {
    if (-not $a.Execute) { continue }
    $cmd = ("$($a.Execute) $($a.Arguments)").Trim()
    $src = "Task $($t.TaskPath)$($t.TaskName)"
    if ($isMsTask) {
      # for system tasks we only check that they do not point outside Windows
      $pth = Get-ExePathFromCommand ([Environment]::ExpandEnvironmentVariables($cmd))
      if ($pth -and $pth.ToLower().StartsWith($winDir)) { continue }
    }
    Test-Autorun $src $t.TaskName $cmd 'Scheduler'
    if (-not $isMsTask -and $t.Settings.Hidden) {
      Add-Finding 2 'Scheduler' "$src (hidden task)" @('the task is flagged as hidden (Hidden)') $cmd ''
    }
  }
}

Write-Step 'Checking services (including DLLs inside svchost)...'
$ServiceRows = New-Object System.Collections.Generic.List[object]
foreach ($s in @(Get-CimInstance Win32_Service)) {
  $cmd = [string]$s.PathName
  if (-not $cmd) { continue }
  $exe = Get-ExePathFromCommand $cmd
  $target = $exe
  if ($exe -and $exe.ToLower().EndsWith('\svchost.exe')) {
    $dll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters").ServiceDll
    if (-not $dll) { $dll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)").ServiceDll }
    if ($dll) { $target = [Environment]::ExpandEnvironmentVariables([string]$dll) }
  }
  if (-not $target) { continue }
  $reasons = New-Object System.Collections.Generic.List[object]
  foreach ($x in (Get-PathReasons $target -Stale)) { $reasons.Add($x) }
  foreach ($x in (Get-CmdReasons $cmd)) { $reasons.Add($x) }
  if ($cmd -notmatch '^"' -and $cmd -match '^[A-Za-z]:\\[^"]*\s[^"]*\.exe' -and $cmd -notmatch '^[A-Za-z]:\\.*?\.exe\s*(-|/|$)') {
    $reasons.Add(@{ P = 1; T = 'service path with spaces and no quotes (privilege-escalation weakness)' })
  }
  $trust = Get-FileTrust $target
  $pts = Sum-Reasons $reasons
  if ($trust -and -not $trust.IsMs) {
    $ServiceRows.Add([pscustomobject]@{ Name = $s.Name; Display = $s.DisplayName; State = $s.State; Mode = $s.StartMode; Target = $target; Signer = $trust.Signer; Status = $trust.Status; Points = $pts })
  }
  if ($pts -ge 2) {
    Add-Finding $pts 'Service' "Service $($s.Name) ($($s.DisplayName))" (Uniq-Texts $reasons) "$target`n$cmd" $(if ($trust) { $trust.Hash } else { '' })
  }
}

# ---------------------------------------------------------------- 3. registry, WMI, protection
Write-Step 'Checking WMI subscriptions, Winlogon, IFEO, AppInit, Defender, hosts, proxy...'
foreach ($c in @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer)) {
  if ($c.CimClass.CimClassName -eq 'NTEventLogEventConsumer') { continue }
  $body = "$($c.CommandLineTemplate) $($c.ExecutablePath) $($c.ScriptText)".Trim()
  if ($body.Length -gt 400) { $body = $body.Substring(0, 400) + '...' }
  Add-Finding 7 'WMI' "WMI subscription:$($c.Name) [$($c.CimClass.CimClassName)]" @('a permanent WMI subscription runs commands on its own - a favorite way to hide autostart; rare in ordinary programs') $body ''
}
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$wlp = Get-ItemProperty $wl
if ($wlp.Shell -and $wlp.Shell -ne 'explorer.exe') { Add-Finding 8 'Registry' 'Winlogon: the shell (Shell) was changed' @('something other than explorer.exe starts at sign-in') ([string]$wlp.Shell) '' }
if ($wlp.Userinit -and $wlp.Userinit -notmatch '(?i)^c:\\windows\\system32\\userinit\.exe,?$') { Add-Finding 8 'Registry' 'Winlogon: Userinit was changed' @('something else starts alongside userinit.exe at sign-in') ([string]$wlp.Userinit) '' }
$hs = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Shell
if ($hs) { Add-Finding 8 'Registry' 'Winlogon (HKCU): a custom shell is set' @('a normal Windows installation never has this') ([string]$hs) '' }
foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
  $dbg = (Get-ItemProperty $k.PSPath).Debugger
  if ($dbg) { Add-Finding 6 'Registry' "IFEO: $($k.PSChildName) is hijacked by a debugger" @('another program runs instead (Image File Execution Options). Task Manager replacements legitimately do this, but malware persists this way too') ([string]$dbg) '' }
}
$aw = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
if ($aw.AppInit_DLLs -and $aw.LoadAppInit_DLLs -eq 1) { Add-Finding 6 'Registry' 'AppInit_DLLs: a DLL is injected into every program' @('the library is loaded into every process that has a UI') ([string]$aw.AppInit_DLLs) '' }

$mp = Get-MpPreference
if ($mp) {
  foreach ($e in @($mp.ExclusionPath)) { if ($e -and $e -notmatch '^N/A') { Add-Finding 3 'Protection' "Defender exclusion (path):$e" @('Defender scans nothing in this folder. Miners like adding such exclusions; developers have them too - think whether you added this one') $e '' } }
  foreach ($e in @($mp.ExclusionProcess)) { if ($e -and $e -notmatch '^N/A') { Add-Finding 3 'Protection' "Defender exclusion (process):$e" @('Defender does not scan this process') $e '' } }
  foreach ($e in @($mp.ExclusionExtension)) { if ($e -and $e -notmatch '^N/A') { Add-Finding 2 'Protection' "Defender exclusion (extension):$e" @('Defender does not scan files with this extension') $e '' } }
  if (-not $isAdmin) { Add-Finding 0 'Protection' 'Defender exclusions are not visible without administrator rights' @('') '' '' }
}
$ms = Get-MpComputerStatus
$otherAv = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Where-Object { $_.displayName -notmatch '^(Windows|Microsoft) Defender' } | ForEach-Object { $_.displayName })
if ($ms -and -not $ms.RealTimeProtectionEnabled -and $otherAv.Count -eq 0) { Add-Finding 5 'Protection' 'Defender real-time protection is off and no other antivirus was found' @('malware often disables Defender first - turn protection back on in Windows Security') '' '' }
elseif ($otherAv.Count -eq 0 -and -not $ms) { Add-Finding 3 'Protection' 'No working antivirus was found' @('Windows reports no antivirus product') '' '' }

$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostLines = @(Get-Content $hostsFile | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_ -notmatch '(?i)\blocalhost\b' })
if ($hostLines.Count -gt 0 -and $hostLines.Count -le 60) {
  foreach ($l in $hostLines) {
    if ($l -match $AvDomainRx) { Add-Finding 5 'Network' 'The hosts file blocks/redirects an antivirus or update site' @('malware does this to stop protection from updating') $l '' }
    else { Add-Finding 2 'Network' 'Non-standard hosts entry' @('the entry redirects a domain to another address - make sure you added it yourself') $l '' }
  }
} elseif ($hostLines.Count -gt 60) {
  Add-Finding 2 'Network' "The hosts file has $($hostLines.Count) entries" @('looks like an ad block list; if you did not install one, check the file') $hostsFile ''
}
$is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
if ($is.ProxyEnable -eq 1 -and $is.ProxyServer) { Add-Finding 3 'Network' "System proxy is enabled:$($is.ProxyServer)" @('all web traffic goes through the specified server. If you did not set up a proxy/VPN yourself, treat this with suspicion') ([string]$is.ProxyServer) '' }
if ($is.AutoConfigURL) { Add-Finding 3 'Network' "A proxy auto-config (PAC) script is set" @('a PAC script can redirect traffic to a foreign server') ([string]$is.AutoConfigURL) '' }

foreach ($u in @(Get-LocalUser)) {
  if ($u.Name -like '*$') { Add-Finding 5 'Account' "Local user hidden by name (the name ends with a dollar sign):$($u.Name)" @('such a name hides the account from some listings') $u.Name '' }
}
$admins = @(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { $_.Name })

# ---------------------------------------------------------------- 4. camera, microphone, screen, location
Write-Step 'Reading the camera, microphone and screen access log...'
$Consents = New-Object System.Collections.Generic.List[object]
$capNames = [ordered]@{ webcam = 'Camera'; microphone = 'Microphone'; location = 'Location'; graphicsCaptureProgrammatic = 'Screen capture'; graphicsCaptureWithoutBorder = 'Screen capture (borderless)' }
$consentBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
function Add-Consent($cap, $key, $nonPackaged) {
  $pr = Get-ItemProperty $key.PSPath
  $st = [Int64]$pr.LastUsedTimeStart; $sp = [Int64]$pr.LastUsedTimeStop
  if ($st -le 0) { return }
  $app = if ($nonPackaged) { $key.PSChildName -replace '#', '\' } else { $key.PSChildName }
  $Consents.Add([pscustomobject]@{
      Cap = $capNames[$cap]; CapKey = $cap; App = $app; NonPackaged = $nonPackaged
      Start = [DateTime]::FromFileTime($st); Stop = $(if ($sp -gt 0) { [DateTime]::FromFileTime($sp) } else { $null })
      InUse = ($sp -eq 0 -or $st -gt $sp)
    })
}
foreach ($cap in $capNames.Keys) {
  $root = "$consentBase\$cap"
  if (-not (Test-Path $root)) { continue }
  foreach ($k in @(Get-ChildItem $root)) {
    if ($k.PSChildName -eq 'NonPackaged') { foreach ($k2 in @(Get-ChildItem $k.PSPath)) { Add-Consent $cap $k2 $true } }
    else { Add-Consent $cap $k $false }
  }
}
foreach ($c in $Consents) {
  if (-not $c.NonPackaged) { continue }
  $t = Get-FileTrust $c.App
  $recent = ($c.Start -gt (Get-Date).AddDays(-30))
  $reasons = New-Object System.Collections.Generic.List[object]
  if (-not $t -or -not $t.Exists) { }
  else {
    foreach ($x in (Get-PathReasons $c.App)) { $reasons.Add($x) }
    if ($t.Status -ne 'Valid' -and $recent) { $reasons.Add(@{ P = 2; T = "an unsigned program used:$($c.Cap.ToLower()) (last time$($c.Start.ToString('yyyy-MM-dd HH:mm')))" }) }
  }
  if ($c.InUse -and $t -and $t.Status -ne 'Valid') { $reasons.Add(@{ P = 3; T = "USING RIGHT NOW:$($c.Cap.ToLower())" }) }
  $pts = Sum-Reasons $reasons
  if ($pts -ge 3) { Add-Finding $pts 'Camera/Mic' "$($c.Cap): $([IO.Path]::GetFileName($c.App))" (Uniq-Texts $reasons) $c.App $(if ($t) { $t.Hash } else { '' }) }
}

# ---------------------------------------------------------------- 5. installed programs
Write-Step 'Reviewing installed programs...'
$Programs = @()
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
  $Programs += @(Get-ItemProperty $k | Where-Object { $_.DisplayName })
}
foreach ($pg in $Programs) {
  if ($pg.DisplayName -match $SpyRx) { Add-Finding 6 'Program' "Monitoring program installed:$($pg.DisplayName)" @('the name matches a known keylogger / monitoring program. If you did not install it, this is very likely what you are looking for') "$($pg.InstallLocation) $($pg.Publisher)" '' }
  elseif ($pg.DisplayName -match $RatRx) { Add-Finding 4 'Program' "Remote-access program installed:$($pg.DisplayName)" @('such programs let someone view and control the computer. If you did not install it yourself, remove it') "$($pg.InstallLocation) $($pg.Publisher)" '' }
  elseif ($pg.DisplayName -match $MinerNames) { Add-Finding 8 'Program' "Miner installed:$($pg.DisplayName)" @('the name matches a known miner') "$($pg.InstallLocation)" '' }
}

# ---------------------------------------------------------------- 6. browser extensions
Write-Step 'Reviewing Chrome / Edge / Brave extensions...'
$Exts = New-Object System.Collections.Generic.List[object]
$browsers = [ordered]@{ Chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data"; Edge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"; Brave = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
$sensitive = 'webRequest', 'webRequestBlocking', 'cookies', 'history', 'clipboardRead', 'debugger', 'proxy', 'nativeMessaging', 'management'
foreach ($bn in $browsers.Keys) {
  $ud = $browsers[$bn]
  if (-not (Test-Path $ud)) { continue }
  foreach ($prof in @(Get-ChildItem $ud -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
    foreach ($ed in @(Get-ChildItem "$($prof.FullName)\Extensions" -Directory)) {
      $vd = Get-ChildItem $ed.FullName -Directory | Sort-Object Name | Select-Object -Last 1
      if (-not $vd) { continue }
      $mf = Join-Path $vd.FullName 'manifest.json'
      if (-not (Test-Path $mf)) { continue }
      try { $m = Get-Content $mf -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
      $nm = [string]$m.name
      if ($nm -like '__MSG_*') {
        $mk = $nm -replace '^__MSG_|__$', ''
        foreach ($loc in @($m.default_locale, 'en', 'en_US', 'ru', 'uk')) {
          if (-not $loc) { continue }
          $lf = Join-Path $vd.FullName "_locales\$loc\messages.json"
          if (Test-Path $lf) { try { $mj = Get-Content $lf -Raw -Encoding UTF8 | ConvertFrom-Json; $v = $mj.$mk.message; if ($v) { $nm = $v; break } } catch { } }
        }
      }
      $perms = @(); foreach ($x in @($m.permissions) + @($m.host_permissions) + @($m.optional_permissions)) { if ($x -is [string]) { $perms += $x } }
      foreach ($cs in @($m.content_scripts)) { foreach ($mt in @($cs.matches)) { if ($mt) { $perms += $mt } } }
      $broad = [bool]($perms | Where-Object { $_ -in '<all_urls>', '*://*/*', 'http://*/*', 'https://*/*' })
      $sens = @($perms | Where-Object { $_ -in $sensitive })
      $sideload = -not $m.update_url
      $pts = 0; $why = @()
      if ($broad) { $pts += 1; $why += 'access to all websites' }
      if ($sens.Count -ge 2) { $pts += 1; $why += "sensitive permissions:$($sens -join ', ')" }
      if ($sideload) { $pts += 2; $why += 'no update URL - not installed from a store (manually or by a program)' }
      $Exts.Add([pscustomobject]@{ Browser = $bn; Profile = $prof.Name; Id = $ed.Name; Name = $nm; Version = $m.version; Broad = $broad; Sens = ($sens -join ', '); Sideload = $sideload; Points = $pts })
      if ($pts -ge 3) { Add-Finding $pts 'Extension' "$bn`: $nm" $why "id: $($ed.Name)  ($($prof.Name))" '' }
    }
  }
}

# ---------------------------------------------------------------- 7. file search (optional)
if ($DeepFiles) {
  Write-Step 'Searching user folders for miner files by name (slow)...'
  $roots = @($env:TEMP, "$env:LOCALAPPDATA", "$env:APPDATA", $env:ProgramData, "$env:PUBLIC", "$env:USERPROFILE\Downloads")
  foreach ($f in @(Get-ChildItem -Path $roots -Recurse -Depth 4 -File -Force | Where-Object { $_.Name -match $MinerNames -or $_.Name -match '(?i)^(config|pools?)\.json$' -and (Select-String -Path $_.FullName -Pattern 'stratum|"pools"|donate-level' -Quiet) })) {
    Add-Finding 7 'File' "File that looks like a miner:$($f.Name)" @('the name or contents point to a miner') $f.FullName ''
  }
}

# ---------------------------------------------------------------- 8. signature publishers (hunting for stolen / suspicious certificates)
Write-Step 'Analyzing digital signature publishers...'
function Get-NameToken($s) {
  $stop = 'inc', 'llc', 'ltd', 'corp', 'corporation', 'co', 'gmbh', 'the', 'pbc', 'limited', 'sa', 'ooo', 'ag', 'srl', 'bv', 'oy', 'ab', 'company', 'technologies', 'technology', 'software'
  $w = ($s.ToLower() -replace '[^a-z0-9\u0400-\u04FF ]', ' ') -split '\s+' | Where-Object { $_ -and $_ -notin $stop }
  return ($w | Select-Object -First 1)
}
$SignerRows = @{}
foreach ($t in @($FileCache.Values)) {
  if (-not $t.Exists -or $t.Status -ne 'Valid' -or $t.IsMs -or -not $t.Signer) { continue }
  if (-not $SignerRows.ContainsKey($t.Signer)) { $SignerRows[$t.Signer] = [pscustomobject]@{ Signer = $t.Signer; Files = 0; Issued = $t.NotBefore; Example = $t.Path } }
  $SignerRows[$t.Signer].Files++
  if ($t.NotBefore -and $SignerRows[$t.Signer].Issued -and $t.NotBefore -gt $SignerRows[$t.Signer].Issued) { $SignerRows[$t.Signer].Issued = $t.NotBefore }
  # signed by one publisher while the file properties name another - a classic sign of a forged or stolen certificate
  $loc = Get-LocationReason $t.Path
  if ($t.Company -and $loc -and $loc.P -ge 2 -and $t.Path -notmatch '\\WindowsApps\\') {
    $tok1 = Get-NameToken $t.Signer; $tok2 = Get-NameToken $t.Company
    if ($tok1 -and $tok2 -and ($t.Signer.ToLower() -notlike "*$tok2*") -and ($t.Company.ToLower() -notlike "*$tok1*")) {
      Add-Finding 3 'Signature' "Signed by '$($t.Signer)' but the file properties name the company '$($t.Company)'" @('the signing publisher and the declared vendor differ and the file sits in a user-writable folder - typical for repackaged third-party programs and for files signed with a certificate that is not theirs') $t.Path $t.Hash
    }
  }
}

# ---------------------------------------------------------------- 9. VirusTotal reputation (optional, only hashes are sent)
$VtRows = New-Object System.Collections.Generic.List[object]
if ($UseVirusTotal) {
  $vtKey = $env:VT_API_KEY
  if (-not $vtKey) { Write-Host '[!] For -UseVirusTotal set your key in the VT_API_KEY environment variable (free key: virustotal.com -> profile -> API key). Skipping.' -ForegroundColor Yellow }
  else {
    Write-Step "Checking hashes against VirusTotal (up to $VtMax files, about 4 requests per minute - this is slow)..."
    $prio = New-Object System.Collections.Generic.List[string]
    foreach ($f in $Findings) { if ($f.Hash -and $f.Hash -notin $prio) { $prio.Add($f.Hash) } }
    foreach ($t in @($FileCache.Values)) {
      if ($t.Exists -and $t.Hash -and -not $t.IsMs -and $t.Path -notmatch '\\WindowsApps\\' -and $t.Hash -notin $prio) { $prio.Add($t.Hash) }
    }
    $done = 0
    foreach ($hs in ($prio | Select-Object -First $VtMax)) {
      try {
        $resp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hs" -Headers @{ 'x-apikey' = $vtKey } -TimeoutSec 20 -ErrorAction Stop
        $st = $resp.data.attributes.last_analysis_stats
        $VtRows.Add([pscustomobject]@{ Hash = $hs; Malicious = [int]$st.malicious; Suspicious = [int]$st.suspicious; Known = $true; Name = $resp.data.attributes.meaningful_name })
        $path = ($FileCache.Values | Where-Object { $_.Hash -eq $hs } | Select-Object -First 1).Path
        if ($st.malicious -ge 3) { Add-Finding 9 'VirusTotal' "VirusTotal: $($st.malicious) engines flag this file as malicious" @("the file $path is detected as malicious (malicious: $($st.malicious), suspicious: $($st.suspicious)) - the signature can still be valid if the certificate was stolen") $path $hs }
        elseif ($st.malicious -ge 1) { Add-Finding 4 'VirusTotal' "VirusTotal: $($st.malicious) detection(s) on this file" @('one or two detections are usually false positives, but check the file via the hash link') $path $hs }
      } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 404) { $VtRows.Add([pscustomobject]@{ Hash = $hs; Malicious = 0; Suspicious = 0; Known = $false; Name = '' }) }
        elseif ($code -eq 401 -or $code -eq 403) { Write-Host '[!] VirusTotal rejected the key - stopping the check.' -ForegroundColor Yellow; break }
        elseif ($code -eq 429) { Start-Sleep -Seconds 60 }
      }
      $done++
      Start-Sleep -Seconds 16
    }
  }
}

# ---------------------------------------------------------------- report
Write-Step 'Building the report...'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportPath = Join-Path $OutDir "report-$stamp.html"
$sorted = @($Findings | Sort-Object -Property @{ Expression = { $_.Points }; Descending = $true }, Category)
$cHigh = @($sorted | Where-Object { $_.Points -ge 8 }).Count
$cMed = @($sorted | Where-Object { $_.Points -ge 4 -and $_.Points -lt 8 }).Count
$cLow = @($sorted | Where-Object { $_.Points -lt 4 }).Count

$sb = New-Object System.Text.StringBuilder
function A($s) { [void]$sb.AppendLine($s) }
A '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Report: hidden programs</title><style>'
A ':root{--bg:#fff;--fg:#1c1f24;--mut:#667085;--card:#f6f7f9;--line:#e3e6eb;--high:#d92d20;--med:#dc6803;--low:#b69300;--info:#667085;--ok:#079455}'
A '@media(prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e6e8ec;--mut:#98a2b3;--card:#1c1f25;--line:#2c313a;--high:#f97066;--med:#fdb022;--low:#e5c94a;--info:#98a2b3;--ok:#47cd89}}'
A 'body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}'
A 'h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:36px 0 10px}.mut{color:var(--mut)}.sum{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}'
A '.pill{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px}.pill b{font-size:22px;display:block}'
A '.f{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--info);border-radius:8px;padding:12px 14px;margin:10px 0}'
A '.f.high{border-left-color:var(--high)}.f.med{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}'
A '.badge{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;border-radius:99px;border:1px solid currentColor;margin-right:6px}.b-high{color:var(--high)}.b-med{color:var(--med)}.b-low{color:var(--low)}.b-info{color:var(--info)}'
A '.f ul{margin:6px 0 6px 18px;padding:0}code,pre{font:12.5px/1.45 ui-monospace,Consolas,monospace}pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;margin:6px 0 0;white-space:pre-wrap;word-break:break-all}'
A 'table{border-collapse:collapse;width:100%;font-size:13.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600}td.p{font:12px ui-monospace,Consolas,monospace;word-break:break-all}'
A '.tw{overflow-x:auto}a{color:inherit}.note{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}</style></head><body><main>'
A "<h1>Report: hidden and masquerading programs</h1><div class='mut'>$(Esc $env:COMPUTERNAME) | $(Get-Date -Format 'yyyy-MM-dd HH:mm') | $(if($isAdmin){'run as administrator'}else{'<b>without administrator rights - the report is incomplete</b>'})</div>"
A "<div class='sum'><div class='pill'><b style='color:var(--high)'>$cHigh</b>high risk</div><div class='pill'><b style='color:var(--med)'>$cMed</b>medium</div><div class='pill'><b style='color:var(--low)'>$cLow</b>low</div><div class='pill'><b>$($groups.Count)</b>programs running</div><div class='pill'><b>$($Autoruns.Count)</b>autostart entries</div></div>"
A "<div class='note'><b>How to read this.</b> This is not an antivirus and not a verdict: the scanner shows <i>indicators</i> (signature, launch location, behavior, persistence). Many ordinary programs are unsigned or live in AppData - look at the reasons in each card and at whether you recognize the program. Nothing was deleted or uploaded: to check a file on VirusTotal, click the link next to its hash (only the hash is sent, not the file).</div>"

A '<h2>Findings</h2>'
if ($sorted.Count -eq 0) { A "<p style='color:var(--ok)'><b>No obvious indicators found.</b> This is not a guarantee: see "What the scanner cannot see" below.</p>" }
foreach ($f in $sorted) {
  $cl = Get-SevClass $f.Points
  A "<div class='f $cl'><span class='badge b-$cl'>$(Get-SevName $f.Points)</span><span class='mut'>$(Esc $f.Category)</span> <b>$(Esc $f.Title)</b><ul>"
  foreach ($r in $f.Reasons) { if ($r) { A "<li>$(Esc $r)</li>" } }
  A '</ul>'
  if ($f.Target) { A "<pre>$(Esc $f.Target)</pre>" }
  if ($f.Hash) { A "<div class='mut' style='margin-top:6px;font-size:12px'>SHA256: <code>$($f.Hash)</code> | <a href='https://www.virustotal.com/gui/file/$($f.Hash)' target='_blank' rel='noopener'>check on VirusTotal</a></div>" }
  A '</div>'
}

A '<h2>Heaviest programs (CPU / GPU during sampling)</h2><div class="tw"><table><tr><th>Program</th><th>Instances</th><th>CPU, %</th><th>GPU, %</th><th>Signer</th><th>Path</th></tr>'
foreach ($t in ($TopLoad | Sort-Object { $_.Cpu + $_.Gpu } -Descending | Select-Object -First 12)) {
  A "<tr><td>$(Esc $t.Name)</td><td>$($t.Count)</td><td>$($t.Cpu)</td><td>$($t.Gpu)</td><td>$(Esc $t.Signer)</td><td class='p'>$(Esc $t.Path)</td></tr>"
}
A '</table></div><p class="mut">Percent of the combined power of all cores. A miner usually keeps a steady 30-100% on an unfamiliar program even when you are doing nothing.</p>'

A '<h2>Who talks to the internet</h2><div class="tw"><table><tr><th>Program</th><th>PID</th><th>To</th><th>Signer</th><th>Path</th></tr>'
foreach ($n in ($NetRows | Sort-Object @{ Expression = { $_.Status -eq 'Valid' } }, Process | Select-Object -First 250)) {
  A "<tr><td>$(Esc $n.Process)</td><td>$($n.ProcId)</td><td>$(Esc $n.Remote):$($n.Port)</td><td>$(Esc $(if($n.Signer){$n.Signer}else{'- none -'}))</td><td class='p'>$(Esc $n.Path)</td></tr>"
}
A '</table></div><p class="mut">Programs without a valid signature come first. For an unknown IP you can look up the owner on who.is / ipinfo.io.</p>'

A '<h2>Camera, microphone, screen and location access</h2><div class="tw"><table><tr><th>What</th><th>Program</th><th>Last used</th><th>Now</th></tr>'
foreach ($c in ($Consents | Sort-Object Start -Descending | Select-Object -First 60)) {
  A "<tr><td>$(Esc $c.Cap)</td><td class='p'>$(Esc $c.App)</td><td>$($c.Start.ToString('yyyy-MM-dd HH:mm'))</td><td>$(if($c.InUse){'<b style=""color:var(--med)"">in use</b>'}else{'-'})</td></tr>"
}
A '</table></div><p class="mut">This log is kept by Windows itself. An unfamiliar program in the camera/microphone list is the main sign of spying.</p>'

A '<h2>Autostart entries, tasks and services not from Microsoft</h2><div class="tw"><table><tr><th>Where</th><th>Name</th><th>Command</th><th>Signer</th></tr>'
foreach ($a in ($Autoruns | Where-Object { -not $_.IsMs } | Sort-Object Points -Descending | Select-Object -First 200)) {
  A "<tr><td>$(Esc $a.Source)</td><td>$(Esc $a.Name)</td><td class='p'>$(Esc $a.Command)</td><td>$(Esc $(if($a.Signer){$a.Signer}else{$a.Status}))</td></tr>"
}
foreach ($s in ($ServiceRows | Sort-Object Points -Descending)) {
  A "<tr><td>Service ($(Esc $s.State), $(Esc $s.Mode))</td><td>$(Esc $s.Name)</td><td class='p'>$(Esc $s.Target)</td><td>$(Esc $(if($s.Signer){$s.Signer}else{$s.Status}))</td></tr>"
}
A '</table></div>'

if ($Exts.Count -gt 0) {
  A '<h2>Browser extensions with broad permissions</h2><div class="tw"><table><tr><th>Browser</th><th>Name</th><th>All sites</th><th>Sensitive permissions</th><th>Sideloaded</th><th>ID</th></tr>'
  foreach ($e in ($Exts | Where-Object { $_.Points -ge 1 } | Sort-Object Points -Descending)) {
    A "<tr><td>$(Esc $e.Browser) / $(Esc $e.Profile)</td><td>$(Esc $e.Name)</td><td>$(if($e.Broad){'yes'}else{''})</td><td>$(Esc $e.Sens)</td><td>$(if($e.Sideload){'<b>yes</b>'}else{''})</td><td class='p'>$(Esc $e.Id)</td></tr>"
  }
  A '</table></div><p class="mut">An extension with access to all sites sees everything you type in the browser. Remove the ones you do not use: chrome://extensions or edge://extensions.</p>'
}

if ($ForeignDlls.Count -gt 0) {
  A '<h2>Third-party DLLs inside Windows system processes</h2><div class="tw"><table><tr><th>Process</th><th>DLL</th><th>Signer</th></tr>'
  foreach ($d in ($ForeignDlls | Sort-Object Signer, Process | Select-Object -First 120)) {
    A "<tr><td>$(Esc $d.Process)</td><td class='p'>$(Esc $d.Dll)</td><td>$(Esc $d.Signer)</td></tr>"
  }
  A '</table></div><p class="mut">Signed third-party DLLs in explorer/svchost are common (antivirus, graphics drivers, shell extensions). Look for what you do not recognize.</p>'
}
if ($SignerRows.Count -gt 0) {
  A '<h2>Signature publishers of running and loaded files</h2><div class="tw"><table><tr><th>Publisher</th><th>Files</th><th>Certificate issued</th><th>Example</th></tr>'
  foreach ($s in ($SignerRows.Values | Sort-Object Files | Select-Object -First 80)) {
    A "<tr><td>$(Esc $s.Signer)</td><td>$($s.Files)</td><td>$(if($s.Issued){$s.Issued.ToString('yyyy-MM-dd')})</td><td class='p'>$(Esc $s.Example)</td></tr>"
  }
  A '</table></div><p class="mut">Publishers with only one or two files come first. An unfamiliar publisher with a recent certificate and a file in AppData is a reason to check the file. A stolen certificate cannot be told apart by the signature alone: use the VirusTotal check (-UseVirusTotal) for that.</p>'
}
if ($VtRows.Count -gt 0) {
  $unk = @($VtRows | Where-Object { -not $_.Known }).Count
  A "<h2>VirusTotal</h2><p>Hashes checked:$($VtRows.Count). Unknown to VirusTotal:$unk (a new or rare file - not necessarily malicious, but worth a closer look).</p>"
}
A "<h2>Administrators on this computer</h2><p>$(Esc ($admins -join ', '))</p><p class='mut'>There should be no unfamiliar accounts here.</p>"
A '<h2>What the scanner cannot see</h2><div class="note"><ul><li><b>Kernel-level rootkits</b> and malicious drivers - they can hide from any program running inside Windows. This needs a check from outside the system: Microsoft Defender Offline or Kaspersky Rescue Disk.</li><li><b>Spyware hiding inside signed or legitimate programs</b> - a file signed with a stolen certificate looks valid by signature alone (use the VirusTotal check), and well-hidden injection (for example manually mapped code) may leave no trace in the module list.</li><li><b>Router, phone, cloud accounts</b> - these are separate places for surveillance (check "devices signed in to your account" in Google/Microsoft/Apple).</li></ul><p><b>What to do next:</b> 1) check the found files on VirusTotal by hash; 2) run <i>Autoruns</i> and <i>Process Explorer</i> (Sysinternals) with VirusTotal checking enabled; 3) run a full Defender + Malwarebytes scan; 4) if you suspect surveillance, change passwords from a <i>different</i> device and enable two-factor authentication.</p></div>'
A '</main></body></html>'

[IO.File]::WriteAllText($reportPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

Write-Host ''
Write-Host "Done. High risk: $cHigh, medium: $cMed, low: $cLow" -ForegroundColor Green
foreach ($f in ($sorted | Select-Object -First 8)) {
  $col = if ($f.Points -ge 8) { 'Red' } elseif ($f.Points -ge 4) { 'Yellow' } else { 'Gray' }
  Write-Host ("  [{0}] {1}: {2}" -f (Get-SevName $f.Points), $f.Category, $f.Title) -ForegroundColor $col
}
Write-Host "Report: $reportPath" -ForegroundColor Cyan
if (-not $NoOpen) { Start-Process $reportPath }
if ($Pause) { Read-Host 'Press Enter to close the window' }
