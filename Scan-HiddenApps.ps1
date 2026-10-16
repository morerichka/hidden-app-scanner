<#
  Scan-HiddenApps.ps1 — аудит скрытых / замаскированных программ (майнеры, шпионы, RAT).
  ТОЛЬКО ЧТЕНИЕ: ничего не удаляет, не меняет, никуда не отправляет данные.
  Результат: HTML-отчёт в папке reports\.
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
  Write-Host 'Запрашиваю права администратора (нужны, чтобы видеть все процессы и службы)...' -ForegroundColor Yellow
  $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Pause -SampleSeconds $SampleSeconds"
  if ($DeepFiles) { $argList += ' -DeepFiles' }
  if ($SkipModules) { $argList += ' -SkipModules' }
  if ($UseVirusTotal) { $argList += " -UseVirusTotal -VtMax $VtMax" }
  try { Start-Process powershell.exe -Verb RunAs -ArgumentList $argList -ErrorAction Stop; exit }
  catch { Write-Host 'UAC отклонён — продолжаю без прав администратора, отчёт будет менее полным.' -ForegroundColor Yellow }
}

function Write-Step($t) { Write-Host "[*] $t" -ForegroundColor Cyan }

# ---------------------------------------------------------------- справочники
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

# ---------------------------------------------------------------- вспомогательные функции
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
  if ($l -match '\\appdata\\local\\temp\\|\\windows\\temp\\|\\temp\\|\\tmp\\') { return @{ P = 3; T = 'запускается из папки Temp (типичное место для малвари)' } }
  if ($l -match '\\users\\public\\|\\\$recycle\.bin\\|\\downloads\\') { return @{ P = 3; T = 'запускается из Public / Downloads / Корзины' } }
  if ($l -match '\\programdata\\' -and $l -notmatch '\\programdata\\(microsoft|package cache)\\') { return @{ P = 2; T = 'запускается из ProgramData' } }
  if ($l -match '\\appdata\\(roaming|local)\\') { return @{ P = 1; T = 'запускается из AppData (так делают и нормальные программы, и малварь)' } }
  return $null
}

function Get-PathReasons($path, [switch]$Stale) {
  $r = New-Object System.Collections.Generic.List[object]
  $path = Normalize-Path $path
  if ([string]::IsNullOrWhiteSpace($path)) { return ,$r }
  $t = Get-FileTrust $path
  if (-not $t.Exists) {
    if ($Stale) { $r.Add(@{ P = 1; T = 'запись ведёт на несуществующий файл (скорее всего, программу удалили, а запись осталась)' }) }
    else { $r.Add(@{ P = 5; T = 'файл запущенного процесса не найден на диске (удалён после запуска или подменён)' }) }
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
      'UnknownError' { $r.Add(@{ P = 1; T = 'не удалось проверить подпись' }) }
      'NotSigned' { $r.Add(@{ P = 2; T = 'нет цифровой подписи' }) }
      'HashMismatch' { $r.Add(@{ P = 6; T = 'подпись есть, но файл изменён после подписания (HashMismatch)' }) }
      default { $r.Add(@{ P = 3; T = "подпись недействительна ($($t.Status))" }) }
    }
  }
  if (-not $isStore) { $loc = Get-LocationReason $path; if ($loc) { $r.Add($loc) } }

  if ($SysProc.ContainsKey($name)) {
    $ok = $false
    foreach ($d in $SysProc[$name].Dirs) {
      $dl = $d.ToLower()
      if ($dir -eq $dl -or $dir.StartsWith($dl + '\')) { $ok = $true }
    }
    if (-not $ok) { $r.Add(@{ P = 8; T = "маскируется под системный процесс $name, но лежит в $dir" }) }
    elseif (-not $t.IsMs) { $r.Add(@{ P = 6; T = "носит имя системного процесса $name, но подписан не Microsoft ($($t.Signer))" }) }
  }
  elseif (-not $t.IsMs -and $base.Length -ge 5) {
    foreach ($sn in $SysBaseNames) {
      $dist = Get-Lev $base $sn
      if (($dist -eq 1) -or ($dist -eq 2 -and $base.Length -ge 8)) {
        $r.Add(@{ P = 8; T = "имя «$base» подозрительно похоже на системное «$sn»" }); break
      }
    }
  }
  if (($name -match '[a-z]') -and ($name -match '[\u0400-\u04FF]')) { $r.Add(@{ P = 5; T = 'в имени файла смешаны латиница и кириллица (подмена букв)' }) }
  if ($name -match '\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip|rar)\.(exe|scr|com|bat|cmd)$') { $r.Add(@{ P = 7; T = 'двойное расширение (документ.pdf.exe)' }) }
  if ($t.Status -ne 'Valid' -and $base -match '^[a-z0-9]{6,16}$' -and $base -match '\d' -and $base -match '[a-z]') {
    $r.Add(@{ P = 2; T = 'имя файла похоже на случайный набор символов' })
  }
  if ($base -match $MinerNames) { $r.Add(@{ P = 8; T = 'имя файла совпадает с известным майнером' }) }
  if ($base -match $SpyRx) { $r.Add(@{ P = 6; T = 'имя файла совпадает с известной программой слежки / кейлоггером' }) }
  elseif ($base -match $RatRx) { $r.Add(@{ P = 4; T = 'программа удалённого доступа — убедитесь, что вы сами её ставили' }) }
  return ,$r
}

function Get-CmdReasons($cmd) {
  $r = New-Object System.Collections.Generic.List[object]
  if ([string]::IsNullOrWhiteSpace($cmd)) { return ,$r }
  if ($cmd -match $MinerRx) { $r.Add(@{ P = 8; T = 'в командной строке признаки майнера (пул stratum / алгоритм / кошелёк)' }) }
  if ($cmd -match '(?i)\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}') { $r.Add(@{ P = 5; T = 'закодированная (base64) команда PowerShell' }) }
  if ($cmd -match '(?i)-w(indowstyle)?\s+hidden') { $r.Add(@{ P = 3; T = 'запуск со скрытым окном' }) }
  if ($cmd -match '(?i)downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient') { $r.Add(@{ P = 4; T = 'PowerShell скачивает данные из сети прямо в команде' }) }
  if ($cmd -match '(?i)frombase64string') { $r.Add(@{ P = 3; T = 'команда раскодирует base64 и, возможно, выполняет скрытый код' }) }
  if ($cmd -match '(?i)\biex\b|invoke-expression') { $r.Add(@{ P = 2; T = 'команда выполняет строку как код (Invoke-Expression) — бывает у легитимных оболочек и у вредоносных скриптов' }) }
  if ($cmd -match '(?i)(mshta|regsvr32|certutil|bitsadmin|wscript|cscript)(\.exe)?["'']?\s.*https?://') { $r.Add(@{ P = 5; T = 'системная утилита запускает что-то по ссылке из интернета' }) }
  if ($cmd -match '(?i)certutil.*-urlcache') { $r.Add(@{ P = 5; T = 'certutil скачивает файл из интернета' }) }
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
function Get-SevName($pts) { if ($pts -ge 8) { 'Высокий' } elseif ($pts -ge 4) { 'Средний' } elseif ($pts -ge 2) { 'Низкий' } else { 'Инфо' } }

$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding($Points, $Category, $Title, $Reasons, $Target, $Hash) {
  if ($Points -lt 2) { return }
  $Findings.Add([pscustomobject]@{ Points = $Points; Category = $Category; Title = $Title; Reasons = @($Reasons); Target = $Target; Hash = $Hash })
}

# ---------------------------------------------------------------- 1. процессы + замер CPU/GPU
Write-Step 'Собираю процессы и сетевые подключения...'
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

Write-Step "Замеряю нагрузку CPU/GPU ($SampleSeconds сек) — лучше ничего не запускать в это время..."
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

Write-Step 'Проверяю подписи и поведение процессов...'
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
    $reasons.Add(@{ P = 1; T = 'не удалось определить путь к файлу процесса (у защищённых системных процессов это нормально)' })
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
      $reasons.Add(@{ P = 5; T = 'svchost запущен без параметра -k (настоящие svchost всегда запускаются с ним)' })
    }
    if ($SysProc.ContainsKey($lname) -and $SysProc[$lname].Parent) {
      $par = $byId[[int]$p.ParentProcessId]
      if ($par -and $par.Name.ToLower() -ne $SysProc[$lname].Parent) {
        $reasons.Add(@{ P = 4; T = "неожиданный родительский процесс: $($par.Name) (ожидается $($SysProc[$lname].Parent))" })
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
  if ($cpuSum -ge 25 -and $notValid -and $lname -notin $pseudo) { $reasons.Add(@{ P = 2; T = "высокая нагрузка CPU ($([Math]::Round($cpuSum,0))% всех ядер) у неподписанной программы" }) }
  if ($gpuMax -ge 40 -and $notValid -and $lname -notin $pseudo) { $reasons.Add(@{ P = 2; T = "высокая нагрузка GPU ($gpuMax%) у неподписанной программы" }) }
  if ($ext -gt 0 -and $notValid -and $lname -notin $pseudo) { $reasons.Add(@{ P = 2; T = "неподписанная программа обменивается данными с интернетом ($ext соед.)" }) }
  if ($mine.Count -gt 0) { $reasons.Add(@{ P = 3; T = "подключения к портам, типичным для майнинг-пулов: $((@($mine | Select-Object -Unique)) -join ', ')" }) }
  if ($listenAll -gt 0 -and $notValid -and $lname -notin $pseudo) { $reasons.Add(@{ P = 2; T = 'неподписанная программа слушает входящие соединения из сети' }) }

  $TopLoad.Add([pscustomobject]@{ Name = $name; Count = $inst.Count; Cpu = [Math]::Round($cpuSum, 1); Gpu = $gpuMax; Signer = $(if ($trust) { $trust.Signer } else { '' }); Path = $path })

  $pts = Sum-Reasons $reasons
  if ($pts -ge 2) {
    $ids = ($inst | Select-Object -First 5 | ForEach-Object { $_.ProcessId }) -join ', '
    $title = "$name  (PID: $ids$(if ($inst.Count -gt 5) { '…' }))"
    $tgt = if ($path) { $path } else { '(путь неизвестен)' }
    if ($cmdHits.Count -gt 0) { foreach ($ch in $cmdHits) { $tgt += "`n> " + $(if ($ch.Length -gt 400) { $ch.Substring(0, 400) + '…' } else { $ch }) } }
    elseif ($inst[0].CommandLine -and $inst.Count -eq 1) { $tgt += "`n" + $inst[0].CommandLine }
    Add-Finding $pts 'Процесс' $title (Uniq-Texts $reasons) $tgt $(if ($trust) { $trust.Hash } else { '' })
  }
}

# скрытые процессы: сверка двух источников
Write-Step 'Сверяю списки процессов (поиск скрытых от диспетчера)...'
$gpIds = @([Diagnostics.Process]::GetProcesses() | ForEach-Object { $_.Id })
$cimIds = @(Get-CimInstance Win32_Process | ForEach-Object { [int]$_.ProcessId })
$onlyGp = @($gpIds | Where-Object { $_ -ne 0 -and $_ -notin $cimIds })
Start-Sleep -Milliseconds 700
foreach ($id in $onlyGp) {
  $still = Get-Process -Id $id
  $inCim = Get-CimInstance Win32_Process -Filter "ProcessId=$id"
  if ($still -and -not $inCim) {
    Add-Finding 4 'Процесс' "PID $id ($($still.ProcessName)) виден в одном списке процессов, но скрыт в другом" @('расхождение между двумя способами перечисления процессов — признак руткита; часто бывает и ложным (процесс только что завершился)') '' ''
  }
}

# ---------------------------------------------------------------- 1б. внедрённые DLL и память без файла
$ForeignDlls = New-Object System.Collections.Generic.List[object]
function Test-SameApp($a, $b) {
  $sa = $a.ToLower().Split('\'); $sb2 = $b.ToLower().Split('\')
  $n = 0
  for ($i = 0; $i -lt [Math]::Min($sa.Length, $sb2.Length); $i++) { if ($sa[$i] -eq $sb2[$i]) { $n++ } else { break } }
  $need = if ($a.ToLower() -match '^[a-z]:\\users\\') { 6 } else { 3 }
  return ($n -ge $need)
}

if (-not $SkipModules) {
  if (-not $isAdmin) { Write-Host '[!] Без прав администратора список модулей у многих процессов недоступен — проверка DLL будет неполной.' -ForegroundColor Yellow }
  Write-Step 'Проверяю загруженные в процессы DLL (внедрение) и исполняемую память без файла — это самый долгий этап...'
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
        $reasons.Add(@{ P = 4; T = 'DLL загружена в процесс, но файла на диске нет (удалён или подменён)' })
      } else {
        $loc = Get-LocationReason $mp
        if ($mt.Status -eq 'HashMismatch') { $reasons.Add(@{ P = 6; T = 'DLL изменена после подписания (HashMismatch)' }) }
        if ($pIsSystem) {
          if ($mt.Status -notin 'Valid', 'UnknownError' -and -not $isStore) { $reasons.Add(@{ P = 5; T = "в системный процесс Microsoft ($pname) загружена DLL без действительной подписи ($($mt.Status))" }) }
          elseif ($loc -and $loc.P -ge 2 -and -not $mt.IsMs) { $reasons.Add(@{ P = 6; T = "в системный процесс ($pname) загружена DLL из пользовательской папки" }) }
          elseif (-not $mt.IsMs -and $mt.Exists -and $mp -notmatch '(?i)\\assembly\\nativeimages_') { $ForeignDlls.Add([pscustomobject]@{ Process = $pname; Dll = $mp; Signer = $mt.Signer; Status = $mt.Status }) }
        } else {
          if ($mt.Status -eq 'NotSigned' -and -not $isStore -and -not (Test-SameApp $exePath $mp) -and $mp -notmatch '(?i)^c:\\windows\\') {
            $reasons.Add(@{ P = 3; T = "неподписанная DLL, лежащая не рядом с программой $pname (внедрение или чужая библиотека)" })
          }
          if ($loc -and $loc.P -ge 3 -and -not (Test-SameApp $exePath $mp)) { $reasons.Add($loc) }
        }
      }
      $pts = Sum-Reasons $reasons
      if ($pts -ge 3) { Add-Finding $pts 'Внедрённая DLL' "$pname ← $([IO.Path]::GetFileName($mp))" (Uniq-Texts $reasons) $mp $mt.Hash }
    }
    # исполняемая память без файла — только в процессах, где JIT не ожидается
    if ($exePath.ToLower().StartsWith($winDir) -and $pname -notmatch $jitHosts) {
      $n = [MemScan]::CountRwx($pr.Id)
      $isDotnet = [bool]($mods | Where-Object { $_.ModuleName -match '^(clr|coreclr|clrjit|mscoree)\.dll$' })
      if ($n -eq 1) { $rwxOne.Add("$pname (PID $($pr.Id))") }
      elseif ($n -ge 2 -and -not $isDotnet) {
        Add-Finding 4 'Внедрённая DLL' "$pname (PID $($pr.Id)): $n областей памяти «чтение+запись+исполнение» без файла" @('в системном процессе без .NET/JIT есть несколько исполняемых областей памяти, не привязанных к файлу — так выглядит внедрённый код (shellcode, reflective DLL). Бывает и у защитных драйверов') $exePath ''
      }
    }
  }
  if ($rwxOne.Count -ge 3) {
    Add-Finding 2 'Внедрённая DLL' "В $($rwxOne.Count) системных процессах найдено по одной исполняемой области памяти без файла (единый шаблон)" @('одинаковая картина сразу во многих процессах — признак общего механизма, а не точечного внедрения: обычно это защитные хуки антивируса или драйвера (у вас стоит Bitdefender). Если антивируса нет — стоит присмотреться') (($rwxOne | Select-Object -First 25) -join ', ') ''
  }
}
# ---------------------------------------------------------------- 2. автозапуск
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
  # скрипты в пользовательских папках, запускаемые через интерпретаторы
  foreach ($m in [regex]::Matches($exp, '([A-Za-z]:\\[^"''\r\n]+?\.(ps1|vbs|vbe|js|jse|bat|cmd|hta|wsf))', 'IgnoreCase')) {
    $sp = $m.Groups[1].Value
    $lr = Get-LocationReason $sp
    if ($lr) { $reasons.Add(@{ P = [Math]::Max($lr.P, 2); T = "запускает скрипт из пользовательской папки: $sp" }) }
    if (-not (Test-Path -LiteralPath $sp)) { $reasons.Add(@{ P = 3; T = "скрипт не найден: $sp" }) }
  }
  $pts = Sum-Reasons $reasons
  $isMs = ($trust -and $trust.IsMs)
  $Autoruns.Add([pscustomobject]@{ Source = $Source; Name = $Name; Command = $exp; Signer = $(if ($trust) { $trust.Signer } else { '' }); Status = $(if ($trust) { $trust.Status } else { '?' }); IsMs = $isMs; Points = $pts; Hash = $(if ($trust) { $trust.Hash } else { '' }) })
  if ($pts -ge 2) {
    Add-Finding $pts $Category "$Source`: $Name" (Uniq-Texts $reasons) $exp $(if ($trust) { $trust.Hash } else { '' })
  }
}

Write-Step 'Проверяю автозагрузку (реестр, папки Startup)...'
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
    Test-Autorun ($k -replace '^HKLM:\\SOFTWARE\\', 'HKLM\' -replace '^HKCU:\\SOFTWARE\\', 'HKCU\') $pr.Name ([string]$pr.Value) 'Автозапуск'
  }
}
$wsh = New-Object -ComObject WScript.Shell
foreach ($sf in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
  foreach ($f in @(Get-ChildItem -LiteralPath $sf -File -Force)) {
    if ($f.Name -ieq 'desktop.ini') { continue }
    if ($f.Extension -ieq '.lnk') {
      $lnk = $wsh.CreateShortcut($f.FullName)
      Test-Autorun 'Папка Startup' $f.Name ("`"$($lnk.TargetPath)`" $($lnk.Arguments)") 'Автозапуск'
    } else {
      Test-Autorun 'Папка Startup' $f.Name ("`"$($f.FullName)`"") 'Автозапуск'
    }
  }
}

Write-Step 'Проверяю планировщик заданий...'
foreach ($t in @(Get-ScheduledTask)) {
  $isMsTask = ($t.TaskPath -like '\Microsoft\*')
  foreach ($a in $t.Actions) {
    if (-not $a.Execute) { continue }
    $cmd = ("$($a.Execute) $($a.Arguments)").Trim()
    $src = "Задание $($t.TaskPath)$($t.TaskName)"
    if ($isMsTask) {
      # у системных заданий проверяем только то, что они не ведут за пределы Windows
      $pth = Get-ExePathFromCommand ([Environment]::ExpandEnvironmentVariables($cmd))
      if ($pth -and $pth.ToLower().StartsWith($winDir)) { continue }
    }
    Test-Autorun $src $t.TaskName $cmd 'Планировщик'
    if (-not $isMsTask -and $t.Settings.Hidden) {
      Add-Finding 2 'Планировщик' "$src (скрытое задание)" @('задание помечено как скрытое (Hidden)') $cmd ''
    }
  }
}

Write-Step 'Проверяю службы (в т.ч. DLL внутри svchost)...'
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
    $reasons.Add(@{ P = 1; T = 'путь к службе с пробелами без кавычек (уязвимость повышения прав)' })
  }
  $trust = Get-FileTrust $target
  $pts = Sum-Reasons $reasons
  if ($trust -and -not $trust.IsMs) {
    $ServiceRows.Add([pscustomobject]@{ Name = $s.Name; Display = $s.DisplayName; State = $s.State; Mode = $s.StartMode; Target = $target; Signer = $trust.Signer; Status = $trust.Status; Points = $pts })
  }
  if ($pts -ge 2) {
    Add-Finding $pts 'Служба' "Служба $($s.Name) ($($s.DisplayName))" (Uniq-Texts $reasons) "$target`n$cmd" $(if ($trust) { $trust.Hash } else { '' })
  }
}

# ---------------------------------------------------------------- 3. реестр, WMI, защита
Write-Step 'Проверяю WMI-подписки, Winlogon, IFEO, AppInit, Defender, hosts, прокси...'
foreach ($c in @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer)) {
  if ($c.CimClass.CimClassName -eq 'NTEventLogEventConsumer') { continue }
  $body = "$($c.CommandLineTemplate) $($c.ExecutablePath) $($c.ScriptText)".Trim()
  if ($body.Length -gt 400) { $body = $body.Substring(0, 400) + '…' }
  Add-Finding 7 'WMI' "WMI-подписка: $($c.Name) [$($c.CimClass.CimClassName)]" @('постоянная WMI-подписка выполняет команды сама — любимый способ спрятать автозапуск; у обычных программ встречается редко') $body ''
}
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$wlp = Get-ItemProperty $wl
if ($wlp.Shell -and $wlp.Shell -ne 'explorer.exe') { Add-Finding 8 'Реестр' 'Winlogon: изменена оболочка (Shell)' @('вместо explorer.exe при входе запускается другое') ([string]$wlp.Shell) '' }
if ($wlp.Userinit -and $wlp.Userinit -notmatch '(?i)^c:\\windows\\system32\\userinit\.exe,?$') { Add-Finding 8 'Реестр' 'Winlogon: изменён Userinit' @('при входе в систему вместе с userinit.exe запускается что-то ещё') ([string]$wlp.Userinit) '' }
$hs = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Shell
if ($hs) { Add-Finding 8 'Реестр' 'Winlogon (HKCU): задана пользовательская оболочка' @('такого у обычной Windows не бывает') ([string]$hs) '' }
foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
  $dbg = (Get-ItemProperty $k.PSPath).Debugger
  if ($dbg) { Add-Finding 6 'Реестр' "IFEO: $($k.PSChildName) перехватывается отладчиком" @('вместо программы запускается другая (Image File Execution Options). Легально так подменяют диспетчер задач, но малварь тоже так закрепляется') ([string]$dbg) '' }
}
$aw = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
if ($aw.AppInit_DLLs -and $aw.LoadAppInit_DLLs -eq 1) { Add-Finding 6 'Реестр' 'AppInit_DLLs: DLL внедряется во все программы' @('библиотека подгружается в каждый процесс с интерфейсом') ([string]$aw.AppInit_DLLs) '' }

$mp = Get-MpPreference
if ($mp) {
  foreach ($e in @($mp.ExclusionPath)) { if ($e -and $e -notmatch '^N/A') { Add-Finding 3 'Защита' "Исключение Defender (путь): $e" @('в этой папке Defender ничего не проверяет. Майнеры любят добавлять такие исключения; у разработчиков они тоже бывают — вспомните, добавляли ли вы это') $e '' } }
  foreach ($e in @($mp.ExclusionProcess)) { if ($e -and $e -notmatch '^N/A') { Add-Finding 3 'Защита' "Исключение Defender (процесс): $e" @('этот процесс Defender не проверяет') $e '' } }
  foreach ($e in @($mp.ExclusionExtension)) { if ($e -and $e -notmatch '^N/A') { Add-Finding 2 'Защита' "Исключение Defender (расширение): $e" @('файлы с таким расширением Defender не проверяет') $e '' } }
  if (-not $isAdmin) { Add-Finding 0 'Защита' 'Исключения Defender без прав администратора не видны' @('') '' '' }
}
$ms = Get-MpComputerStatus
$otherAv = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Where-Object { $_.displayName -notmatch '^(Windows|Microsoft) Defender' } | ForEach-Object { $_.displayName })
if ($ms -and -not $ms.RealTimeProtectionEnabled -and $otherAv.Count -eq 0) { Add-Finding 5 'Защита' 'Защита в реальном времени Defender выключена, другого антивируса не найдено' @('малварь часто выключает Defender в первую очередь — включите защиту в «Безопасности Windows»') '' '' }
elseif ($otherAv.Count -eq 0 -and -not $ms) { Add-Finding 3 'Защита' 'Не удалось найти работающий антивирус' @('Windows не сообщает ни об одном антивирусе') '' '' }

$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostLines = @(Get-Content $hostsFile | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_ -notmatch '(?i)\blocalhost\b' })
if ($hostLines.Count -gt 0 -and $hostLines.Count -le 60) {
  foreach ($l in $hostLines) {
    if ($l -match $AvDomainRx) { Add-Finding 5 'Сеть' 'Файл hosts блокирует/перенаправляет сайт антивируса или обновлений' @('так малварь мешает обновлять защиту') $l '' }
    else { Add-Finding 2 'Сеть' 'Нестандартная запись в hosts' @('запись перенаправляет домен на другой адрес — проверьте, что вы её добавляли сами') $l '' }
  }
} elseif ($hostLines.Count -gt 60) {
  Add-Finding 2 'Сеть' "В hosts $($hostLines.Count) записей" @('похоже на блок-лист рекламы; если вы такого не ставили — проверьте файл') $hostsFile ''
}
$is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
if ($is.ProxyEnable -eq 1 -and $is.ProxyServer) { Add-Finding 3 'Сеть' "Включён системный прокси: $($is.ProxyServer)" @('весь веб-трафик идёт через указанный сервер. Если вы не настраивали прокси/VPN — это повод насторожиться') ([string]$is.ProxyServer) '' }
if ($is.AutoConfigURL) { Add-Finding 3 'Сеть' "Задан скрипт автонастройки прокси (PAC)" @('PAC-скрипт может перенаправлять трафик на чужой сервер') ([string]$is.AutoConfigURL) '' }

foreach ($u in @(Get-LocalUser)) {
  if ($u.Name -like '*$') { Add-Finding 5 'Аккаунт' "Скрытый по имени локальный пользователь (имя оканчивается на знак доллара): $($u.Name)" @('такое имя скрывает аккаунт от части списков') $u.Name '' }
}
$admins = @(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { $_.Name })

# ---------------------------------------------------------------- 4. камера, микрофон, экран, геолокация
Write-Step 'Читаю журнал доступа к камере, микрофону, экрану...'
$Consents = New-Object System.Collections.Generic.List[object]
$capNames = [ordered]@{ webcam = 'Камера'; microphone = 'Микрофон'; location = 'Геолокация'; graphicsCaptureProgrammatic = 'Захват экрана'; graphicsCaptureWithoutBorder = 'Захват экрана (без рамки)' }
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
    if ($t.Status -ne 'Valid' -and $recent) { $reasons.Add(@{ P = 2; T = "неподписанная программа использовала: $($c.Cap.ToLower()) (последний раз $($c.Start.ToString('dd.MM.yyyy HH:mm')))" }) }
  }
  if ($c.InUse -and $t -and $t.Status -ne 'Valid') { $reasons.Add(@{ P = 3; T = "ПРЯМО СЕЙЧАС использует: $($c.Cap.ToLower())" }) }
  $pts = Sum-Reasons $reasons
  if ($pts -ge 3) { Add-Finding $pts 'Камера/микрофон' "$($c.Cap): $([IO.Path]::GetFileName($c.App))" (Uniq-Texts $reasons) $c.App $(if ($t) { $t.Hash } else { '' }) }
}

# ---------------------------------------------------------------- 5. установленные программы
Write-Step 'Просматриваю список установленных программ...'
$Programs = @()
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
  $Programs += @(Get-ItemProperty $k | Where-Object { $_.DisplayName })
}
foreach ($pg in $Programs) {
  if ($pg.DisplayName -match $SpyRx) { Add-Finding 6 'Программа' "Установлена программа слежения: $($pg.DisplayName)" @('название совпадает с известным кейлоггером / программой мониторинга. Если вы её не ставили — это почти наверняка то, что вы ищете') "$($pg.InstallLocation) $($pg.Publisher)" '' }
  elseif ($pg.DisplayName -match $RatRx) { Add-Finding 4 'Программа' "Установлена программа удалённого доступа: $($pg.DisplayName)" @('через такие программы кто-то может видеть и управлять компьютером. Если не ставили сами — удалите') "$($pg.InstallLocation) $($pg.Publisher)" '' }
  elseif ($pg.DisplayName -match $MinerNames) { Add-Finding 8 'Программа' "Установлен майнер: $($pg.DisplayName)" @('название совпадает с известным майнером') "$($pg.InstallLocation)" '' }
}

# ---------------------------------------------------------------- 6. расширения браузеров
Write-Step 'Просматриваю расширения Chrome / Edge / Brave...'
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
      if ($broad) { $pts += 1; $why += 'доступ ко всем сайтам' }
      if ($sens.Count -ge 2) { $pts += 1; $why += "чувствительные права: $($sens -join ', ')" }
      if ($sideload) { $pts += 2; $why += 'нет адреса обновления — установлено не из магазина (вручную / программой)' }
      $Exts.Add([pscustomobject]@{ Browser = $bn; Profile = $prof.Name; Id = $ed.Name; Name = $nm; Version = $m.version; Broad = $broad; Sens = ($sens -join ', '); Sideload = $sideload; Points = $pts })
      if ($pts -ge 3) { Add-Finding $pts 'Расширение' "$bn`: $nm" $why "id: $($ed.Name)  ($($prof.Name))" '' }
    }
  }
}

# ---------------------------------------------------------------- 7. поиск файлов (опционально)
if ($DeepFiles) {
  Write-Step 'Ищу файлы майнеров по именам в пользовательских папках (долго)...'
  $roots = @($env:TEMP, "$env:LOCALAPPDATA", "$env:APPDATA", $env:ProgramData, "$env:PUBLIC", "$env:USERPROFILE\Downloads")
  foreach ($f in @(Get-ChildItem -Path $roots -Recurse -Depth 4 -File -Force | Where-Object { $_.Name -match $MinerNames -or $_.Name -match '(?i)^(config|pools?)\.json$' -and (Select-String -Path $_.FullName -Pattern 'stratum|"pools"|donate-level' -Quiet) })) {
    Add-Finding 7 'Файл' "Файл, похожий на майнер: $($f.Name)" @('имя или содержимое указывает на майнер') $f.FullName ''
  }
}

# ---------------------------------------------------------------- 8. издатели подписей (поиск «краденых» / подозрительных сертификатов)
Write-Step 'Анализирую издателей цифровых подписей...'
function Get-NameToken($s) {
  $stop = 'inc', 'llc', 'ltd', 'corp', 'corporation', 'co', 'gmbh', 'the', 'pbc', 'limited', 'sa', 'ooo', 'ag', 'srl', 'bv', 'oy', 'ab', 'company', 'technologies', 'technology', 'software'
  $w = ($s.ToLower() -replace '[^a-z0-9Ѐ-ӿ ]', ' ') -split '\s+' | Where-Object { $_ -and $_ -notin $stop }
  return ($w | Select-Object -First 1)
}
$SignerRows = @{}
foreach ($t in @($FileCache.Values)) {
  if (-not $t.Exists -or $t.Status -ne 'Valid' -or $t.IsMs -or -not $t.Signer) { continue }
  if (-not $SignerRows.ContainsKey($t.Signer)) { $SignerRows[$t.Signer] = [pscustomobject]@{ Signer = $t.Signer; Files = 0; Issued = $t.NotBefore; Example = $t.Path } }
  $SignerRows[$t.Signer].Files++
  if ($t.NotBefore -and $SignerRows[$t.Signer].Issued -and $t.NotBefore -gt $SignerRows[$t.Signer].Issued) { $SignerRows[$t.Signer].Issued = $t.NotBefore }
  # подпись одного издателя, а в свойствах файла указан другой — классический признак подделки/чужого сертификата
  $loc = Get-LocationReason $t.Path
  if ($t.Company -and $loc -and $loc.P -ge 2 -and $t.Path -notmatch '\\WindowsApps\\') {
    $tok1 = Get-NameToken $t.Signer; $tok2 = Get-NameToken $t.Company
    if ($tok1 -and $tok2 -and ($t.Signer.ToLower() -notlike "*$tok2*") -and ($t.Company.ToLower() -notlike "*$tok1*")) {
      Add-Finding 3 'Подпись' "Подписан «$($t.Signer)», но в свойствах файла компания «$($t.Company)»" @('издатель подписи и заявленный производитель не совпадают, а файл лежит в пользовательской папке — так бывает у упакованных чужих программ и у файлов, подписанных не своим сертификатом') $t.Path $t.Hash
    }
  }
}

# ---------------------------------------------------------------- 9. репутация по VirusTotal (по желанию, отправляются только хэши)
$VtRows = New-Object System.Collections.Generic.List[object]
if ($UseVirusTotal) {
  $vtKey = $env:VT_API_KEY
  if (-not $vtKey) { Write-Host '[!] Для -UseVirusTotal задайте ключ в переменной окружения VT_API_KEY (бесплатный ключ: virustotal.com → профиль → API key). Пропускаю.' -ForegroundColor Yellow }
  else {
    Write-Step "Сверяю хэши с VirusTotal (до $VtMax штук, ~4 запроса в минуту — это долго)..."
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
        if ($st.malicious -ge 3) { Add-Finding 9 'VirusTotal' "VirusTotal: $($st.malicious) антивирусов считают файл вредоносным" @("файл $path определяется как вредоносный (malicious: $($st.malicious), suspicious: $($st.suspicious)) — подпись при этом может быть валидной, если сертификат украден") $path $hs }
        elseif ($st.malicious -ge 1) { Add-Finding 4 'VirusTotal' "VirusTotal: $($st.malicious) срабатывание(й) на файл" @('одно-два срабатывания чаще ложные, но проверьте файл по ссылке с хэшем') $path $hs }
      } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 404) { $VtRows.Add([pscustomobject]@{ Hash = $hs; Malicious = 0; Suspicious = 0; Known = $false; Name = '' }) }
        elseif ($code -eq 401 -or $code -eq 403) { Write-Host '[!] VirusTotal отклонил ключ — останавливаю проверку.' -ForegroundColor Yellow; break }
        elseif ($code -eq 429) { Start-Sleep -Seconds 60 }
      }
      $done++
      Start-Sleep -Seconds 16
    }
  }
}

# ---------------------------------------------------------------- отчёт
Write-Step 'Формирую отчёт...'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportPath = Join-Path $OutDir "report-$stamp.html"
$sorted = @($Findings | Sort-Object -Property @{ Expression = { $_.Points }; Descending = $true }, Category)
$cHigh = @($sorted | Where-Object { $_.Points -ge 8 }).Count
$cMed = @($sorted | Where-Object { $_.Points -ge 4 -and $_.Points -lt 8 }).Count
$cLow = @($sorted | Where-Object { $_.Points -lt 4 }).Count

$sb = New-Object System.Text.StringBuilder
function A($s) { [void]$sb.AppendLine($s) }
A '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Отчёт: скрытые программы</title><style>'
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
A "<h1>Отчёт: скрытые и замаскированные программы</h1><div class='mut'>$(Esc $env:COMPUTERNAME) · $(Get-Date -Format 'dd.MM.yyyy HH:mm') · $(if($isAdmin){'запущено от администратора'}else{'<b>без прав администратора — отчёт неполный</b>'})</div>"
A "<div class='sum'><div class='pill'><b style='color:var(--high)'>$cHigh</b>высокий риск</div><div class='pill'><b style='color:var(--med)'>$cMed</b>средний</div><div class='pill'><b style='color:var(--low)'>$cLow</b>низкий</div><div class='pill'><b>$($groups.Count)</b>программ запущено</div><div class='pill'><b>$($Autoruns.Count)</b>записей автозапуска</div></div>"
A "<div class='note'><b>Как читать.</b> Это не антивирус и не вердикт: сканер показывает <i>признаки</i> (подпись, место запуска, поведение, закрепление в системе). Много обычных программ неподписаны или лежат в AppData — смотрите на причины в каждой карточке и на то, узнаёте ли вы программу. Ничего не удалялось и не отправлялось: чтобы проверить файл на VirusTotal, нажмите ссылку у хэша (уйдёт только хэш, не файл).</div>"

A '<h2>Что найдено</h2>'
if ($sorted.Count -eq 0) { A "<p style='color:var(--ok)'><b>Явных признаков не найдено.</b> Это не гарантия: см. раздел «Чего сканер не видит» внизу.</p>" }
foreach ($f in $sorted) {
  $cl = Get-SevClass $f.Points
  A "<div class='f $cl'><span class='badge b-$cl'>$(Get-SevName $f.Points)</span><span class='mut'>$(Esc $f.Category)</span> <b>$(Esc $f.Title)</b><ul>"
  foreach ($r in $f.Reasons) { if ($r) { A "<li>$(Esc $r)</li>" } }
  A '</ul>'
  if ($f.Target) { A "<pre>$(Esc $f.Target)</pre>" }
  if ($f.Hash) { A "<div class='mut' style='margin-top:6px;font-size:12px'>SHA256: <code>$($f.Hash)</code> · <a href='https://www.virustotal.com/gui/file/$($f.Hash)' target='_blank' rel='noopener'>проверить на VirusTotal</a></div>" }
  A '</div>'
}

A '<h2>Самые нагруженные программы (CPU / GPU за время замера)</h2><div class="tw"><table><tr><th>Программа</th><th>Экз.</th><th>CPU, %</th><th>GPU, %</th><th>Подпись</th><th>Путь</th></tr>'
foreach ($t in ($TopLoad | Sort-Object { $_.Cpu + $_.Gpu } -Descending | Select-Object -First 12)) {
  A "<tr><td>$(Esc $t.Name)</td><td>$($t.Count)</td><td>$($t.Cpu)</td><td>$($t.Gpu)</td><td>$(Esc $t.Signer)</td><td class='p'>$(Esc $t.Path)</td></tr>"
}
A '</table></div><p class="mut">Процент — от суммарной мощности всех ядер. Майнер обычно держит постоянные 30–100% на неизвестной программе, даже когда вы ничего не делаете.</p>'

A '<h2>Кто ходит в интернет</h2><div class="tw"><table><tr><th>Программа</th><th>PID</th><th>Куда</th><th>Подпись</th><th>Путь</th></tr>'
foreach ($n in ($NetRows | Sort-Object @{ Expression = { $_.Status -eq 'Valid' } }, Process | Select-Object -First 250)) {
  A "<tr><td>$(Esc $n.Process)</td><td>$($n.ProcId)</td><td>$(Esc $n.Remote):$($n.Port)</td><td>$(Esc $(if($n.Signer){$n.Signer}else{'— нет —'}))</td><td class='p'>$(Esc $n.Path)</td></tr>"
}
A '</table></div><p class="mut">Сверху — программы без действительной подписи. Для неизвестного IP можно посмотреть владельца на who.is / ipinfo.io.</p>'

A '<h2>Доступ к камере, микрофону, экрану, геолокации</h2><div class="tw"><table><tr><th>Что</th><th>Программа</th><th>Последний раз</th><th>Сейчас</th></tr>'
foreach ($c in ($Consents | Sort-Object Start -Descending | Select-Object -First 60)) {
  A "<tr><td>$(Esc $c.Cap)</td><td class='p'>$(Esc $c.App)</td><td>$($c.Start.ToString('dd.MM.yyyy HH:mm'))</td><td>$(if($c.InUse){'<b style=""color:var(--med)"">используется</b>'}else{'—'})</td></tr>"
}
A '</table></div><p class="mut">Это журнал самой Windows. Незнакомая программа в списке камеры/микрофона — главный признак шпионажа.</p>'

A '<h2>Автозапуск, задания и службы не от Microsoft</h2><div class="tw"><table><tr><th>Где</th><th>Имя</th><th>Команда</th><th>Подпись</th></tr>'
foreach ($a in ($Autoruns | Where-Object { -not $_.IsMs } | Sort-Object Points -Descending | Select-Object -First 200)) {
  A "<tr><td>$(Esc $a.Source)</td><td>$(Esc $a.Name)</td><td class='p'>$(Esc $a.Command)</td><td>$(Esc $(if($a.Signer){$a.Signer}else{$a.Status}))</td></tr>"
}
foreach ($s in ($ServiceRows | Sort-Object Points -Descending)) {
  A "<tr><td>Служба ($(Esc $s.State), $(Esc $s.Mode))</td><td>$(Esc $s.Name)</td><td class='p'>$(Esc $s.Target)</td><td>$(Esc $(if($s.Signer){$s.Signer}else{$s.Status}))</td></tr>"
}
A '</table></div>'

if ($Exts.Count -gt 0) {
  A '<h2>Расширения браузеров с широкими правами</h2><div class="tw"><table><tr><th>Браузер</th><th>Название</th><th>Все сайты</th><th>Чувствительные права</th><th>Не из магазина</th><th>ID</th></tr>'
  foreach ($e in ($Exts | Where-Object { $_.Points -ge 1 } | Sort-Object Points -Descending)) {
    A "<tr><td>$(Esc $e.Browser) / $(Esc $e.Profile)</td><td>$(Esc $e.Name)</td><td>$(if($e.Broad){'да'}else{''})</td><td>$(Esc $e.Sens)</td><td>$(if($e.Sideload){'<b>да</b>'}else{''})</td><td class='p'>$(Esc $e.Id)</td></tr>"
  }
  A '</table></div><p class="mut">Расширение с доступом ко всем сайтам видит всё, что вы вводите в браузере. Удалите те, которыми не пользуетесь: chrome://extensions или edge://extensions.</p>'
}

if ($ForeignDlls.Count -gt 0) {
  A '<h2>Сторонние DLL внутри системных процессов Windows</h2><div class="tw"><table><tr><th>Процесс</th><th>DLL</th><th>Подпись</th></tr>'
  foreach ($d in ($ForeignDlls | Sort-Object Signer, Process | Select-Object -First 120)) {
    A "<tr><td>$(Esc $d.Process)</td><td class='p'>$(Esc $d.Dll)</td><td>$(Esc $d.Signer)</td></tr>"
  }
  A '</table></div><p class="mut">Подписанные сторонние DLL в explorer/svchost обычны (антивирус, драйверы видеокарты, расширения проводника). Смотрите на то, чего вы не узнаёте.</p>'
}
if ($SignerRows.Count -gt 0) {
  A '<h2>Издатели подписей запущенных и загруженных файлов</h2><div class="tw"><table><tr><th>Издатель</th><th>Файлов</th><th>Сертификат выдан</th><th>Пример</th></tr>'
  foreach ($s in ($SignerRows.Values | Sort-Object Files | Select-Object -First 80)) {
    A "<tr><td>$(Esc $s.Signer)</td><td>$($s.Files)</td><td>$(if($s.Issued){$s.Issued.ToString('dd.MM.yyyy')})</td><td class='p'>$(Esc $s.Example)</td></tr>"
  }
  A '</table></div><p class="mut">Сверху — издатели с одним-двумя файлами. Незнакомый издатель с недавним сертификатом и файлом из AppData — повод проверить файл. Краденый сертификат по подписи не отличить: для этого есть проверка по VirusTotal (-UseVirusTotal).</p>'
}
if ($VtRows.Count -gt 0) {
  $unk = @($VtRows | Where-Object { -not $_.Known }).Count
  A "<h2>VirusTotal</h2><p>Проверено хэшей: $($VtRows.Count). Не известны VirusTotal: $unk (новый или редкий файл — не обязательно вредоносный, но стоит присмотреться).</p>"
}
A "<h2>Администраторы на этом компьютере</h2><p>$(Esc ($admins -join ', '))</p><p class='mut'>Незнакомых аккаунтов здесь быть не должно.</p>"
A '<h2>Чего сканер не видит</h2><div class="note"><ul><li><b>Руткиты уровня ядра</b> и вредоносные драйверы — они умеют прятаться от любых программ внутри Windows. Для этого нужна проверка вне системы: Microsoft Defender Offline или Kaspersky Rescue Disk.</li><li><b>Шпионское ПО в подписанных/легитимных оболочках</b> (подписанный по краденому сертификату файл, DLL-инъекции в доверенные процессы).</li><li><b>Роутер, телефон, облачные аккаунты</b> — это отдельные места слежки (проверьте «устройства, вошедшие в аккаунт» в Google/Microsoft/Apple).</li></ul><p><b>Что сделать после:</b> 1) проверить найденные файлы на VirusTotal по хэшу; 2) запустить <i>Autoruns</i> и <i>Process Explorer</i> (Sysinternals) с включённой проверкой VirusTotal; 3) полное сканирование Defender + Malwarebytes; 4) если есть подозрение на слежку — сменить пароли с <i>другого</i> устройства и включить двухфакторную защиту.</p></div>'
A '</main></body></html>'

[IO.File]::WriteAllText($reportPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

Write-Host ''
Write-Host "Готово. Высокий риск: $cHigh, средний: $cMed, низкий: $cLow" -ForegroundColor Green
foreach ($f in ($sorted | Select-Object -First 8)) {
  $col = if ($f.Points -ge 8) { 'Red' } elseif ($f.Points -ge 4) { 'Yellow' } else { 'Gray' }
  Write-Host ("  [{0}] {1}: {2}" -f (Get-SevName $f.Points), $f.Category, $f.Title) -ForegroundColor $col
}
Write-Host "Отчёт: $reportPath" -ForegroundColor Cyan
if (-not $NoOpen) { Start-Process $reportPath }
if ($Pause) { Read-Host 'Нажмите Enter, чтобы закрыть окно' }
