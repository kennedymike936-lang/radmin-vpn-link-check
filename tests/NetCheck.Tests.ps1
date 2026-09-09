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
    for ($k = 0; $k -lt 12; $k++) { $resp[8 + $k] = $k + 1 }   # 事务ID: 1..12
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
function New-Tid { param([int]$Base); $t = New-Object byte[] 12; for ($k = 0; $k -lt 12; $k++) { $t[$k] = $Base + $k }; return ,$t }

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
# 事务ID 校验
$tidMatch = New-Tid -Base 1
Assert-Equal '192.168.1.5' (ConvertTo-StunMapped -Resp $r -Tid $tidMatch).MappedIP 'TID 匹配 → 正常解析'
$tidWrong = New-Tid -Base 100
Assert-Null (ConvertTo-StunMapped -Resp $r -Tid $tidWrong) 'TID 不匹配 → 返回null'
# 截断报文: 属性声称8字节, 但报文在IP数据处截断
$trunc = New-StunXorResp
$short = New-Object byte[] 27
[Array]::Copy($trunc, $short, 27)
Assert-Null (ConvertTo-StunMapped -Resp $short) '属性声称8字节但报文截断 → 返回null'

Write-Host ''
Write-Host '=== Get-PingStats (PS5.1/PS7 兼容) ===' -ForegroundColor Cyan
$ps5 = @([pscustomobject]@{ ResponseTime = 60 }, [pscustomobject]@{ ResponseTime = 120 })
$s = Get-PingStats -Replies $ps5
Assert-Equal 90 $s.Avg 'PS5.1 ResponseTime 平均'
Assert-Equal 2 $s.Ok 'PS5.1 成功数'
Assert-Equal 0 $s.Loss 'PS5.1 丢包0'
$ps7 = @([pscustomobject]@{ Status = 'Success'; Latency = 800 }, [pscustomobject]@{ Status = 'Success'; Latency = 900 })
$s7 = Get-PingStats -Replies $ps7
Assert-Equal 850 $s7.Avg 'PS7 Latency 平均(800/900)'
Assert-Equal 2 $s7.Ok 'PS7 成功数'
$ps7mix = @([pscustomobject]@{ Status = 'TimedOut'; Latency = 0 }, [pscustomobject]@{ Status = 'Success'; Latency = 100 })
$s7m = Get-PingStats -Replies $ps7mix
Assert-Equal 1 $s7m.Ok 'PS7 TimedOut 不计入成功'
Assert-Equal 1 $s7m.Loss 'PS7 丢包=1'
Assert-Equal 100 $s7m.Avg 'PS7 只统计成功的延迟'
Assert-Null (Get-PingStats -Replies @()).Avg '空回复 → Avg null'

Write-Host ''
Write-Host '=== Get-LatencyVerdict / Get-LossVerdict ===' -ForegroundColor Cyan
Assert-Equal 'GOOD' (Get-LatencyVerdict -AvgMs 60) '60ms → GOOD'
Assert-Equal 'FAIR' (Get-LatencyVerdict -AvgMs 250) '250ms → FAIR'
Assert-Equal 'POOR' (Get-LatencyVerdict -AvgMs 500) '500ms → POOR'
Assert-Equal 'UNKNOWN' (Get-LatencyVerdict -AvgMs $null) '无数据 → UNKNOWN'
Assert-Equal 'NONE' (Get-LossVerdict -LossCount 0 -TotalCount 10) '0丢包 → NONE'
Assert-Equal 'MILD' (Get-LossVerdict -LossCount 2 -TotalCount 10) '2/10丢包 → MILD(单独提醒, 不再算GOOD)'
Assert-Equal 'HEAVY' (Get-LossVerdict -LossCount 5 -TotalCount 10) '5/10丢包 → HEAVY'
Assert-Equal 'HEAVY' (Get-LossVerdict -LossCount 3 -TotalCount 10) '3/10丢包(30%) → HEAVY'

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

Write-Host ''
Write-Host '=== Get-RelayVerdict ===' -ForegroundColor Cyan
Assert-Equal 'RELAY_SUSPECTED' (Get-RelayVerdict -LatencyVerdict 'POOR' -HasForeignConn $true) 'POOR+境外连接 → RELAY_SUSPECTED'
Assert-Equal 'POOR_UNCONFIRMED' (Get-RelayVerdict -LatencyVerdict 'POOR' -HasForeignConn $false) 'POOR无证据 → POOR_UNCONFIRMED'
Assert-Equal 'NONE' (Get-RelayVerdict -LatencyVerdict 'GOOD' -HasForeignConn $true) 'GOOD → NONE'

Write-Host ''
Write-Host '=== Mask-Ip ===' -ForegroundColor Cyan
Assert-Equal '26.187.x.x' (Mask-Ip '26.187.21.13') 'IPv4脱敏'
Assert-Equal '2409:8a20:c5a:3240::x' (Mask-Ip '2409:8a20:c5a:3240:d578:9dec:9298:7d62') 'IPv6脱敏'

Write-Host ''
Write-Host '=== Merge-ChangeList (重复修复保住原始状态) ===' -ForegroundColor Cyan
$existing = @([pscustomobject]@{ Kind = 'Profile'; Target = 'Radmin VPN'; Previous = 'Public' })
$new = @(
    [pscustomobject]@{ Kind = 'Profile'; Target = 'Radmin VPN'; Previous = 'Private' },
    [pscustomobject]@{ Kind = 'Rule'; Target = 'NetCheck-Radmin-VPN'; Previous = '' })
$merged = @(Merge-ChangeList -Existing $existing -New $new)
Assert-Equal 2 $merged.Count '合并后共2项(重复项不叠加)'
Assert-Equal 'Public' $merged[0].Previous '保留第一次修改前的状态 Public'
Assert-Equal 'NetCheck-Radmin-VPN' $merged[1].Target '新规则项被保留'

Write-Host ''
Write-Host '=== Expand-Changes (嵌套状态防御) ===' -ForegroundColor Cyan
$nested = @(, @(
    [pscustomobject]@{ Kind = 'Profile'; Target = 'Radmin VPN'; Previous = 'Public' },
    [pscustomobject]@{ Kind = 'Rule'; Target = 'R1'; Previous = '' },
    [pscustomobject]@{ Kind = 'Rule'; Target = 'R2'; Previous = '' }))
$flat2 = @(Expand-Changes -Items $nested)
Assert-Equal 3 $flat2.Count '嵌套状态扁平化 → 3项'
Assert-Equal 'Radmin VPN' $flat2[0].Target '扁平后第一项 Target'
Assert-Equal 'R1' $flat2[1].Target '扁平后第二项 Target'
$flatOk = @(Expand-Changes -Items @([pscustomobject]@{ Kind = 'Rule'; Target = 'R1'; Previous = '' }))
Assert-Equal 1 $flatOk.Count '扁平状态原样返回1项'

Write-Host ''
Write-Host '=== ConvertTo-CompareSource / Get-Val (完整报告 vs 分享报告) ===' -ForegroundColor Cyan
$full = [pscustomobject]@{ tool = 'NetCheck'; version = '0.2.1'; generated = 't'; facts = [pscustomobject]@{ avgMs = 60; localV6 = $true; natType = 'CONE_LIKE' } }
$src = ConvertTo-CompareSource -Obj $full
Assert-Equal 60 (Get-Val $src 'avgMs') '完整报告: 从 facts 取 avgMs'
Assert-Equal 'True' (Get-Val $src 'localV6') '完整报告: 从 facts 取 localV6'
$share = [pscustomobject]@{ tool = 'NetCheck'; version = '0.2.1'; avgMs = 60; localV6 = $true }
Assert-Equal 60 (Get-Val (ConvertTo-CompareSource -Obj $share) 'avgMs') '分享报告: 顶层取 avgMs'
Assert-Equal '数据缺失' (Get-Val $src 'lossVerdict') '字段缺失 → 显示数据缺失'

Write-Host ''
Write-Host "结果: $pass 通过, $fail 失败" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }



