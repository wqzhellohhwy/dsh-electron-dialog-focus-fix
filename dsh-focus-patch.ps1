<#
  dsh-focus-patch.ps1 —— 一键工具：探测 / 打补丁 / 回滚

  这是 patch-focus-fix.py 的薄封装，给不想敲 Python 的人用。
  真正的分析逻辑全在 Python 脚本里（自动定位补丁点、生成补丁、写回 PE）；
  这里只负责三件事：调用它、报告状态、管好备份。

  用法：
    pwsh -File dsh-focus-patch.ps1 -Status     # 看当前状态（只读，不改任何东西）
    pwsh -File dsh-focus-patch.ps1 -Apply      # 打补丁（幂等：已打过会跳过）
    pwsh -File dsh-focus-patch.ps1 -Revert     # 回滚到备份

  可选参数：
    -Exe    <路径>   指定目标可执行文件（默认自动探测，也认环境变量 DSH_EXE）
    -Helper <路径>   指定 helper（默认自动探测，也认环境变量 DSH_FOCUS_HELPER）

  说明：本文件是 UTF-8 with BOM，Windows PowerShell 5.1 也能正确读中文。
#>
param(
  [switch]$Status,
  [switch]$Apply,
  [switch]$Revert,
  [string]$Exe,
  [string]$Helper
)

$ErrorActionPreference = 'Stop'

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Py   = Join-Path $Here 'patch-focus-fix.py'

function Fail($msg) { Write-Host "错误：$msg" -ForegroundColor Red; exit 1 }
function Info($msg) { Write-Host $msg }
function Ok($msg)   { Write-Host $msg -ForegroundColor Green }

if (-not (Test-Path $Py)) { Fail "找不到 patch-focus-fix.py（应与本脚本同目录）：$Py" }

# ── 找一个可用的 python ──
function Get-Python {
  foreach ($cand in @('python', 'py', 'python3')) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
  }
  return $null
}
$python = Get-Python
if (-not $python) { Fail '找不到 python。请先安装 Python 3 并确保在 PATH 里。' }

# 统一用 UTF-8 跑 Python，避免中文输出在 GBK 控制台乱码
function Invoke-Patcher([string[]]$Extra) {
  $argv = @('-X', 'utf8', $Py)
  if ($Exe)    { $argv += @('--exe',    $Exe) }
  if ($Helper) { $argv += @('--helper', $Helper) }
  $argv += $Extra
  & $python @argv
  return $LASTEXITCODE
}

# ── 默认动作：报状态 ──
if (-not ($Apply -or $Revert)) { $Status = $true }

if ($Status) {
  Info '=== 状态 ==='
  $code = Invoke-Patcher @('--probe')
  if ($code -eq 0) {
    Ok ''
    Ok '探测成功 —— 目标可以被打补丁。用 -Apply 实际执行。'
  } else {
    Info ''
    Info '探测未通过（原因见上方输出）。若显示已存在 .fix 段，说明补丁已经在里面了。'
  }

  # 附带报告一下备份情况
  try {
    $target = $Exe
    if (-not $target -and $env:DSH_EXE) { $target = $env:DSH_EXE }
    if ($target) {
      $bak = Get-ChildItem (Split-Path -Parent $target) -Filter ((Split-Path -Leaf $target) + '.bak-focusfix-*') -ErrorAction SilentlyContinue
      Info ''
      Info ('备份：' + $(if ($bak) { ($bak | Select-Object -First 1).Name } else { '（无）' }))
    }
  } catch { }
  exit 0
}

if ($Revert) {
  Info '=== 回滚 ==='
  $target = $Exe
  if (-not $target -and $env:DSH_EXE) { $target = $env:DSH_EXE }
  if (-not $target) {
    # 让 Python 帮我们把目标探出来（--probe 会打印目标路径）
    $probe = & $python -X utf8 $Py --probe 2>&1 | Out-String
    $m = [regex]::Match($probe, '目标 exe\s*:\s*(.+)')
    if ($m.Success) { $target = $m.Groups[1].Value.Trim() }
  }
  if (-not $target -or -not (Test-Path $target)) { Fail '定位不到目标 exe，请用 -Exe 指定。' }

  $bak = Get-ChildItem (Split-Path -Parent $target) -Filter ((Split-Path -Leaf $target) + '.bak-focusfix-*') -ErrorAction SilentlyContinue |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $bak) { Fail "没找到备份（期望形如 <exe>.bak-focusfix-<日期>）。" }

  Info "  目标：$target"
  Info "  备份：$($bak.FullName)"

  # 先尝试正常关闭应用，占着文件是复制不动的
  $procName = [IO.Path]::GetFileNameWithoutExtension($target)
  $running = Get-Process -Name $procName -ErrorAction SilentlyContinue
  if ($running) {
    Info '  正在关闭应用…'
    $running | ForEach-Object { $_.CloseMainWindow() | Out-Null }
    Start-Sleep -Seconds 6
    Get-Process -Name $procName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 4
  }

  Copy-Item $bak.FullName $target -Force
  $same = (Get-FileHash $target).Hash -eq (Get-FileHash $bak.FullName).Hash
  if (-not $same) { Fail '回滚后哈希不一致，请手工检查。' }
  Ok "  已还原（哈希一致）。"

  if ($running) {
    Info '  重新启动应用…'
    Start-Process -FilePath $target | Out-Null
  }
  exit 0
}

if ($Apply) {
  Info '=== 打补丁 ==='
  if (-not $Helper) {
    $guess = Join-Path $Here 'helper\focus-helper.exe'
    if (-not (Test-Path $guess)) { $guess = Join-Path $Here 'focus-helper.exe' }
    if (Test-Path $guess) { $Helper = $guess }
  }
  if ($Helper) { Info "  helper：$Helper" }
  else { Info '  警告：没找到 focus-helper.exe，补丁仍会生成，但运行时必须能在这个路径找到它。' }

  $code = Invoke-Patcher @('--install')
  if ($code -eq 0) {
    Ok ''
    Ok '完成。请重启目标应用使其生效。'
    Info '提示：exe 被修改后数字签名会失效，杀软可能报警；随时可以用 -Revert 还原。'
  } else {
    exit $code
  }
}
