# build-helper.ps1 —— 从 focus-helper.cs 编译出 focus-helper.exe
#
# helper 是**构建产物**，不入版本库；克隆之后请先跑一次本脚本。
#
#   pwsh -NoProfile -File build-helper.ps1
#
# 编译器探测顺序：
#   1. .NET Framework 4 自带的 csc.exe（Windows 自带，不需要装 SDK）
#   2. Visual Studio 的 Roslyn csc.exe（装了 VS 的话）
#
# 本文件是 UTF-8 with BOM，Windows PowerShell 5.1 也能正确读中文。

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$cs   = Join-Path $here 'focus-helper.cs'
$exe  = Join-Path $here 'focus-helper.exe'

if (-not (Test-Path $cs)) { throw "找不到源码：$cs" }

# ── 探测 C# 编译器 ──
$candidates = New-Object System.Collections.Generic.List[string]

# 1) .NET Framework 4（几乎所有 Windows 都有）
$windir = $env:WINDIR
if (-not $windir) { $windir = 'C:\Windows' }
$candidates.Add((Join-Path $windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'))
$candidates.Add((Join-Path $windir 'Microsoft.NET\Framework\v4.0.30319\csc.exe'))

# 2) Visual Studio 的 Roslyn（VS 2017+ 在 MSBuild 目录下）
foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
  if (-not $root) { continue }
  $pattern = Join-Path $root 'Microsoft Visual Studio\*\*\MSBuild\Current\Bin\Roslyn\csc.exe'
  Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object { $candidates.Add($_.FullName) }
}

$csc = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $csc) {
  throw @'
找不到 C# 编译器（csc.exe）。请任选其一：
  - 启用 .NET Framework 4（Windows 功能里的「.NET Framework 4.x」）
  - 安装 Visual Studio（任意版本，带 MSBuild 即可）
'@
}

Write-Host "使用编译器：$csc"
Write-Host "正在编译…"
& $csc /target:exe /out:"$exe" /optimize+ /nologo "$cs"
if ($LASTEXITCODE -ne 0) { throw "csc 返回 $LASTEXITCODE" }
if (-not (Test-Path $exe)) { throw '没有产出 exe' }

$kb = [math]::Round((Get-Item $exe).Length / 1KB, 1)
Write-Host "完成 -> $exe（$kb KB）"

# 冒烟测试：跑一次确认 exe 能正常启动
$t = Measure-Command { & $exe --quiet 2>&1 | Out-Null }
Write-Host ("冒烟测试：exit={0} 耗时={1}ms" -f $LASTEXITCODE, [int]$t.TotalMilliseconds)
Write-Host '（exit=3 表示没找到目标窗口，属正常 —— 目标应用没在跑而已）'
