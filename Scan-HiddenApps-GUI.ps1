<#
  Scan-HiddenApps-GUI.ps1 — окно-оболочка для Scan-HiddenApps.ps1.
  Запускает сканер (только чтение), показывает ход выполнения и открывает HTML-отчёт.
#>
[CmdletBinding()]
param(
  [switch]$NoElevate,
  [switch]$AutoRun,          # для самопроверки: запустить скан сразу, сохранить снимок окна и закрыться
  [string]$ShotPath = ''
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$scanner = Join-Path $here 'Scan-HiddenApps.ps1'
$reportsDir = Join-Path $here 'reports'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $NoElevate) {
  try {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" -ErrorAction Stop
    exit
  } catch { }  # UAC отклонён — работаем без прав администратора
}
if (-not (Test-Path $scanner)) { throw "Не найден $scanner" }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$font = New-Object System.Drawing.Font('Segoe UI', 9.5)
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Поиск скрытых программ'
$form.Size = New-Object System.Drawing.Size(860, 660)
$form.MinimumSize = New-Object System.Drawing.Size(760, 560)
$form.StartPosition = 'CenterScreen'
$form.Font = $font

function New-Ctl($type, $x, $y, $w, $h, $text) {
  $c = New-Object "System.Windows.Forms.$type"
  $c.Location = New-Object System.Drawing.Point($x, $y)
  $c.Size = New-Object System.Drawing.Size($w, $h)
  if ($null -ne $text) { $c.Text = $text }
  return $c
}

$lblTitle = New-Ctl Label 16 12 800 28 'Поиск скрытых и замаскированных программ'
$lblTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 14)
$lblInfo = New-Ctl Label 16 44 810 38 'Майнеры, шпионские программы, маскировка под системные процессы, внедрённые DLL. Программа только читает данные: ничего не удаляет и не отправляет (кроме хэшей файлов в VirusTotal, если вы это включили).'
$lblAdmin = New-Ctl Label 16 84 810 22 $(if ($isAdmin) { 'Права администратора: есть — результат будет полным.' } else { 'Права администратора: нет — результат будет неполным. Перезапустите и подтвердите запрос Windows.' })
$lblAdmin.ForeColor = $(if ($isAdmin) { [System.Drawing.Color]::FromArgb(7, 148, 85) } else { [System.Drawing.Color]::FromArgb(220, 104, 3) })

$grp = New-Ctl GroupBox 16 112 810 128 'Параметры'
$cbModules = New-Ctl CheckBox 14 24 380 22 'Искать внедрённые DLL и память без файла (+1–2 мин)'
$cbModules.Checked = $true
$cbDeep = New-Ctl CheckBox 14 50 380 22 'Искать файлы майнеров по именам (очень долго)'
$lblSample = New-Ctl Label 14 80 220 22 'Замер нагрузки CPU/GPU, секунд:'
$nudSample = New-Ctl NumericUpDown 236 77 60 24 $null
$nudSample.Minimum = 3; $nudSample.Maximum = 60; $nudSample.Value = 8
$cbVt = New-Ctl CheckBox 420 24 380 22 'Проверять файлы по VirusTotal (нужен ключ)'
$lblKey = New-Ctl Label 420 52 70 22 'Ключ API:'
$txtKey = New-Ctl TextBox 492 49 300 24 $null
$txtKey.UseSystemPasswordChar = $true
$txtKey.Enabled = $false
$lblMax = New-Ctl Label 420 82 238 22 'Макс. файлов (~16 с на файл):'
$nudMax = New-Ctl NumericUpDown 660 79 60 24 $null
$nudMax.Minimum = 5; $nudMax.Maximum = 300; $nudMax.Value = 40; $nudMax.Enabled = $false
$cbVt.Add_CheckedChanged({ $txtKey.Enabled = $cbVt.Checked; $nudMax.Enabled = $cbVt.Checked })
$grp.Controls.AddRange(@($cbModules, $cbDeep, $lblSample, $nudSample, $cbVt, $lblKey, $txtKey, $lblMax, $nudMax))

$btnStart = New-Ctl Button 16 250 160 34 'Сканировать'
$btnStart.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
$btnStop = New-Ctl Button 184 250 110 34 'Остановить'
$btnStop.Enabled = $false
$btnOpen = New-Ctl Button 302 250 150 34 'Открыть отчёт'
$btnOpen.Enabled = $false
$btnFolder = New-Ctl Button 460 250 150 34 'Папка с отчётами'

$bar = New-Ctl ProgressBar 16 292 810 8 $null
$bar.Style = 'Continuous'
$log = New-Ctl TextBox 16 308 810 270 $null
$log.Multiline = $true; $log.ReadOnly = $true; $log.ScrollBars = 'Vertical'
$log.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$log.Anchor = 'Top,Bottom,Left,Right'
$status = New-Ctl Label 16 586 810 22 'Готов к запуску.'
$status.Anchor = 'Bottom,Left,Right'
foreach ($c in @($lblTitle, $lblInfo, $lblAdmin, $grp, $btnStart, $btnStop, $btnOpen, $btnFolder, $bar, $log, $status)) { $form.Controls.Add($c) }
foreach ($c in @($lblInfo, $lblAdmin, $grp, $bar)) { $c.Anchor = 'Top,Left,Right' }

$script:queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
$script:proc = $null
$script:reportPath = $null
$script:summary = ''
$script:evOut = $null
$script:evErr = $null

function Add-Log($line) {
  $log.AppendText($line + [Environment]::NewLine)
  if ($line -match '^Отчёт:\s*(.+)$') { $script:reportPath = $Matches[1].Trim() }
  if ($line -match '^Готово') { $script:summary = $line }
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$timer.Add_Tick({
    $line = $null
    while ($script:queue.TryDequeue([ref]$line)) { if ($null -ne $line) { Add-Log $line } }
    if ($script:proc -and $script:proc.HasExited) {
      Start-Sleep -Milliseconds 300
      while ($script:queue.TryDequeue([ref]$line)) { if ($null -ne $line) { Add-Log $line } }
      $timer.Stop()
      foreach ($e in @($script:evOut, $script:evErr)) { if ($e) { Unregister-Event -SourceIdentifier $e.Name -ErrorAction SilentlyContinue } }
      $code = $script:proc.ExitCode
      $script:proc = $null
      $bar.Style = 'Continuous'; $bar.Value = 0
      $btnStart.Enabled = $true; $btnStop.Enabled = $false; $grp.Enabled = $true
      if (-not $script:reportPath) {
        $newest = Get-ChildItem $reportsDir -Filter 'report-*.html' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
        if ($newest) { $script:reportPath = $newest.FullName }
      }
      if ($script:reportPath -and (Test-Path $script:reportPath) -and $code -eq 0) {
        $btnOpen.Enabled = $true
        $status.Text = if ($script:summary) { $script:summary } else { 'Готово.' }
        if (-not $AutoRun) { Start-Process $script:reportPath }
      } else {
        $status.Text = "Сканирование завершилось без отчёта (код $code). Подробности — в журнале выше."
      }
      if ($AutoRun) {
        if ($ShotPath) {
          $bmp = New-Object System.Drawing.Bitmap($form.Width, $form.Height)
          $form.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $form.Width, $form.Height)))
          $bmp.Save($ShotPath, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
        }
        $form.Close()
      }
    }
  })

function Start-Scan {
  $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$scanner`" -NoElevate -NoOpen -SampleSeconds $([int]$nudSample.Value)"
  if (-not $cbModules.Checked) { $argList += ' -SkipModules' }
  if ($cbDeep.Checked) { $argList += ' -DeepFiles' }
  if ($cbVt.Checked) {
    if (-not $txtKey.Text.Trim()) { [System.Windows.Forms.MessageBox]::Show('Введите ключ VirusTotal API или снимите галочку.', 'Нужен ключ') | Out-Null; return }
    $argList += " -UseVirusTotal -VtMax $([int]$nudMax.Value)"
  }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = 'powershell.exe'
  $psi.Arguments = $argList
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
  $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
  if ($cbVt.Checked) { $psi.EnvironmentVariables['VT_API_KEY'] = $txtKey.Text.Trim() }   # ключ живёт только в памяти этого запуска
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  $script:reportPath = $null; $script:summary = ''
  $script:evOut = Register-ObjectEvent -InputObject $p -EventName OutputDataReceived -MessageData $script:queue -Action { if ($null -ne $EventArgs.Data) { $Event.MessageData.Enqueue($EventArgs.Data) } }
  $script:evErr = Register-ObjectEvent -InputObject $p -EventName ErrorDataReceived -MessageData $script:queue -Action { if ($null -ne $EventArgs.Data) { $Event.MessageData.Enqueue('! ' + $EventArgs.Data) } }
  $log.Clear()
  [void]$p.Start()
  $p.BeginOutputReadLine(); $p.BeginErrorReadLine()
  $script:proc = $p
  $btnStart.Enabled = $false; $btnStop.Enabled = $true; $btnOpen.Enabled = $false; $grp.Enabled = $false
  $bar.Style = 'Marquee'
  $status.Text = 'Идёт сканирование… не закрывайте окно. Полный скан занимает 2–5 минут.'
  $timer.Start()
}

$btnStart.Add_Click({ Start-Scan })
$btnStop.Add_Click({
    if ($script:proc -and -not $script:proc.HasExited) {
      & taskkill.exe /PID $script:proc.Id /T /F | Out-Null
      Add-Log '--- остановлено пользователем ---'
    }
  })
$btnOpen.Add_Click({ if ($script:reportPath -and (Test-Path $script:reportPath)) { Start-Process $script:reportPath } })
$btnFolder.Add_Click({ if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir | Out-Null }; Start-Process $reportsDir })
$form.Add_FormClosing({
    if ($script:proc -and -not $script:proc.HasExited) { & taskkill.exe /PID $script:proc.Id /T /F | Out-Null }
  })
if ($AutoRun) { $form.Add_Shown({ Start-Scan }) }
[void]$form.ShowDialog()
