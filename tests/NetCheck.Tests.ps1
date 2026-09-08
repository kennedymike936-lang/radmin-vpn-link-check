<#
  NetCheck.Tests.ps1 - 纯函数单元测试(无需Pester)
  用法: pwsh -File tests\NetCheck.Tests.ps1   (全部通过时 exit 0, 否则 exit 1)
#>
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'NetCheck.ps1'
. $scriptPath   # dot-source: 只加载函数, 不执行 Main

$pass = 0; $fail = 0
function Assert-Equal {
    param($Expected, $Actual, [string]$Name)
    if ("$Expected" -eq "$Actual") { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name (期望 [$Expected], 实际 [$Actual])" -ForegroundColor Red }
}
function Assert-True  { param($Cond, [string]$Name); if ($Cond) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $Name" -ForegroundColor Red } }
function Assert-Null  { param($Val, [string]$Name); if ($null -eq $Val) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $Name (期望null)" -ForegroundColor Red } }

function New-StunXorResp {
    param([string]$Ip = '192.168.1.5', [int]$Port = 40000, [int]$Type = 0x0020)
    $resp = New-Object byte[] 32
    $resp[0] = 0x01; $resp[1] = 0x01
    $resp[2] = 0; $resp[3] = 12
    $resp[4] = 0x21; $resp[5] = 0x12; $resp[6] = 0xA4; $resp[7] = 0x42
    $resp[20] = ($Type -shr 8) -band 0xFF; $resp[21] = $Type -band 0xFF
    $resp[22] = 0; $resp[23] = 8
    $resp[24] = 0; $resp[25] = 1
    $o = $Ip.Split('.')
    $ipB = @([byte]$o[0], [byte]$o[1], [byte]$o[2], [byte]$o[3])
    $pB = @((($Port -shr 8) -band 0xFF), ($Port -band 0xFF))
    if ($Type -eq 0x0020) {
        $magic = @(0x21, 0x12, 0xA4, 0x42)
        $pB = @(($pB[0] -bxor 0x21), ($pB[1] -bxor 0x12))
        for ($k = 0; $k -lt 4; $k++) { $ipB[$k] = $ipB[$k] -bxor $magic[$k] }
    }
    $resp[26] = $pB[0]; $resp[27] = $pB[1]
    for ($k = 0; $k -lt 4; $k++) { $resp[28 + $k] = $ipB[$k] }
    return ,$resp
}

Write-Host ''
Write-Host '=== ConvertTo-StunMapped ===' -ForegroundColor Cyan
$r = New-StunXorResp -Ip '192.168.1.5' -Port 40000
$m = ConvertTo-StunMapped -Resp $r -Server 'test'
Assert-Equal '192.168.1.5' $m.MappedIP 'XOR-MAPPED-ADDRESS 解析IP'
Assert-Equal 40000 $m.MappedPort 'XOR-MAPPED-ADDRESS 解析端口'
$r2 = New-StunXorResp -Ip '10.0.0.1' -Port 12345 -Type 0x0001
$m2 = ConvertTo-StunMapped -Resp $r2
Assert-Equal '10.0.0.1' $m2.MappedIP 'MAPPED-ADDRESS(0x0001) 解析IP'
Assert-Equal 12345 $m2.MappedPort 'MAPPED-ADDRESS(0x0001) 解析端口'
$bad1 = New-StunXorResp; $bad1[4] = 0x00
Assert-Null (ConvertTo-StunMapped -Resp $bad1) 'magic cookie 错误 → 返回null'
$bad2 = New-StunXorResp; $bad2[1] = 0x11
Assert-Null (ConvertTo-StunMapped -Resp $bad2) '消息类型不是 binding success → 返回null'
Assert-Null (ConvertTo-StunMapped -Resp (New-Object byte[] 8)) '响应过短 → 返回null'

Write-Host ''
Write-Host '=== Get-LatencyVerdict ===' -ForegroundColor Cyan
Assert-Equal 'GOOD' (Get-LatencyVerdict -AvgMs 60 -LossCount 0 -TotalCount 10) '60ms无丢包 → GOOD'
Assert-Equal 'FAIR' (Get-LatencyVerdict -AvgMs 250 -LossCount 0 -TotalCount 10) '250ms → FAIR'
Assert-Equal 'POOR' (Get-LatencyVerdict -AvgMs 500 -LossCount 0 -TotalCount 10) '500ms → POOR'
Assert-Equal 'UNSTABLE_LOSSY' (Get-LatencyVerdict -AvgMs 100 -LossCount 5 -TotalCount 10) '丢包50% → UNSTABLE_LOSSY'
Assert-Equal 'GOOD' (Get-LatencyVerdict -AvgMs 120 -LossCount 1 -TotalCount 10) '丢包10%平均120 → GOOD(丢包未过半)'
Assert-Equal 'UNREACHABLE' (Get-LatencyVerdict -AvgMs 0 -LossCount 0 -TotalCount 0) '无探测 → UNREACHABLE'

Write-Host ''
Write-Host '=== Get-NatVerdict ===' -ForegroundColor Cyan
$one = @([pscustomobject]@{ Status = 'OK'; MappedIP = '1.2.3.4'; MappedPort = 1000 })
Assert-Equal 'UNDETERMINED' (Get-NatVerdict -Results $one).Type '仅1个应答 → UNDETERMINED'
$cone = @(
    [pscustomobject]@{ Status = 'OK'; MappedIP = '1.2.3.4'; MappedPort = 1000 },
    [pscustomobject]@{ Status = 'OK'; MappedIP = '1.2.3.4'; MappedPort = 1000 })
Assert-Equal 'CONE_LIKE' (Get-NatVerdict -Results $cone).Type '同IP同端口 → CONE_LIKE'
$sym = @(
    [pscustomobject]@{ Status = 'OK'; MappedIP = '1.2.3.4'; MappedPort = 1000 },
    [pscustomobject]@{ Status = 'OK'; MappedIP = '1.2.3.4'; MappedPort = 2000 })
Assert-Equal 'PORT_VARYING' (Get-NatVerdict -Results $sym).Type '同IP不同端口 → PORT_VARYING'
$multi = @(
    [pscustomobject]@{ Status = 'OK'; MappedIP = '1.2.3.4'; MappedPort = 1000 },
    [pscustomobject]@{ Status = 'OK'; MappedIP = '5.6.7.8'; MappedPort = 1000 })
Assert-Equal 'MULTI_EXIT' (Get-NatVerdict -Results $multi).Type '不同IP → MULTI_EXIT'
$mixed = @(
    [pscustomobject]@{ Status = 'TIMEOUT'; MappedIP = ''; MappedPort = 0 },
    [pscustomobject]@{ Status = 'OK'; MappedIP = '1.2.3.4'; MappedPort = 1000 },
    [pscustomobject]@{ Status = 'OK'; MappedIP = '1.2.3.4'; MappedPort = 1000 })
Assert-Equal 'CONE_LIKE' (Get-NatVerdict -Results $mixed).Type '忽略失败项, 2个OK → CONE_LIKE'

Write-Host ''
Write-Host '=== Get-RelayVerdict ===' -ForegroundColor Cyan
Assert-Equal 'RELAY_SUSPECTED' (Get-RelayVerdict -LatencyVerdict 'POOR' -HasForeignConn $true) 'POOR+境外连接 → RELAY_SUSPECTED'
Assert-Equal 'POOR_UNCONFIRMED' (Get-RelayVerdict -LatencyVerdict 'POOR' -HasForeignConn $false) 'POOR无证据 → POOR_UNCONFIRMED'
Assert-Equal 'NONE' (Get-RelayVerdict -LatencyVerdict 'GOOD' -HasForeignConn $true) 'GOOD → NONE'
Assert-Equal 'LOSSY' (Get-RelayVerdict -LatencyVerdict 'UNSTABLE_LOSSY' -HasForeignConn $false) '丢包严重 → LOSSY'

Write-Host ''
Write-Host '=== Mask-Ip ===' -ForegroundColor Cyan
Assert-Equal '26.187.x.x' (Mask-Ip '26.187.21.13') 'IPv4脱敏'
Assert-Equal '2409:8a20:c5a:3240::x' (Mask-Ip '2409:8a20:c5a:3240:d578:9dec:9298:7d62') 'IPv6脱敏'

Write-Host ''
Write-Host "结果: $pass 通过, $fail 失败" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }


