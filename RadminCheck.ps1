<#
  Radmin VPN (蓝盾) 链路体检脚本
  --------------------------------------------
  普通用法(只读体检, 无需管理员):
      双击 RadminCheck.bat  或运行:  pwsh -File RadminCheck.ps1

  修复模式(需要管理员, 会自动放行防火墙 + 设网卡为"专用"):
      右键本文件 -> 使用 PowerShell 运行;  或  pwsh -File RadminCheck.ps1 -Fix

  可选参数:
      -PeerIP '26.x.x.x'   手动指定朋友IP(找不到同伴时用)
      -PingCount 10        每次ping次数(默认8)
      -SkipGeo             跳过服务器归属地查询(更快)
#>
param(
    [int]$PingCount = 8,
    [string]$PeerIP = '',
    [switch]$Fix,
    [switch]$SkipGeo
)

$ErrorActionPreference = 'SilentlyContinue'
$adapterName = 'Radmin VPN'

function Section($t) {
    Write-Host ''
    Write-Host ('=' * 62) -ForegroundColor Cyan
    Write-Host ("  " + $t) -ForegroundColor Cyan
    Write-Host ('=' * 62) -ForegroundColor Cyan
}
function Ok($m)   { Write-Host '  [OK]   ' -NoNewline -ForegroundColor Green;  Write-Host $m }
function Warn($m) { Write-Host '  [!]    ' -NoNewline -ForegroundColor Yellow; Write-Host $m }
function Bad($m)  { Write-Host '  [X]    ' -NoNewline -ForegroundColor Red;    Write-Host $m }
function Info($m) { Write-Host '  [i]    ' -NoNewline -ForegroundColor DarkGray; Write-Host $m }
function Geo($ip) {
    if ($SkipGeo) { return '跳过' }
    try {
        $u = "http://ipinfo.io/$ip/json"
        if ($ip -match ':') { $u = "http://ipinfo.io/[$ip]/json" }
        $j = Invoke-RestMethod -Uri $u -TimeoutSec 6
        if ($j.country -eq 'CN') { return ("$($j.city)/$($j.region)/中国 ($($j.org))") }
        return ("$($j.city), $($j.country) ($($j.org))")
    } catch { return '归属查询失败(无外网?)' }
}

# ---------- 0. 权限 ----------
$isAdmin = $false
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
if ($Fix -and -not $isAdmin) {
    Bad '-Fix 需要管理员权限, 请右键"以管理员身份运行"'
    $Fix = $false
}

# ---------- 1. 蓝盾本体 ----------
Section '1. 蓝盾 (Radmin VPN) 本体状态'
$svc = Get-Service RvControlSvc -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq 'Running') { Ok "服务 RvControlSvc: Running" }
    else { Bad "服务 RvControlSvc: $($svc.Status)" }
} else { Bad '未找到 Radmin VPN 服务(未安装?)' }

$gui = Get-Process RvRvpnGui -ErrorAction SilentlyContinue
if ($gui) { Ok "界面进程 RvRvpnGui: 运行中 (PID $($gui.Id))" }
else { Warn '界面进程 RvRvpnGui 未运行(可手动打开蓝盾)' }

$ad = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
if ($ad) {
    if ($ad.Status -eq 'Up') { Ok "虚拟网卡 $adapterName : $($ad.Status), $($ad.LinkSpeed)" }
    else { Bad "虚拟网卡 $adapterName : $($ad.Status) (未启用?)" }
} else { Bad "找不到虚拟网卡 $adapterName (驱动/服务异常)" }

$ip4 = Get-NetIPAddress -InterfaceAlias $adapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue
if ($ip4) { Ok "我的虚拟 IP: $($ip4.IPAddress)" }
else { Bad '虚拟网卡没有 IPv4 地址(蓝盾没连上网络?)' }

# ---------- 2. 找同伴 ----------
Section '2. 寻找局域网同伴'
$peers = @()
if ($PeerIP) { $peers = @($PeerIP) }
elseif ($ad) {
    $mine = if ($ip4) { $ip4.IPAddress } else { '' }
    $cands = Get-NetNeighbor -InterfaceIndex $ad.ifIndex -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like '26.*' -and $_.IPAddress -notin @('26.0.0.1', '26.255.255.255', $mine) } |
        Select-Object -ExpandProperty IPAddress -Unique
    $peers = @($cands | Select-Object -First 3)
}
if ($peers.Count -eq 0) {
    Warn '没有找到在线的同伴。检查: ① 你和朋友都开着蓝盾且在同一个网络里; ② 朋友在线(蓝盾窗口能看到她)。也可用 -PeerIP 参数手动指定IP'
} else {
    $peers | ForEach-Object { Info "发现同伴: $_" }
}

# ---------- 3. ping 测试 ----------
Section '3. 到同伴的延迟测试'
foreach ($p in $peers) {
    Write-Host ("  --- ping {0} x {1} ---" -f $p, $PingCount) -ForegroundColor Gray
    $r = @(Test-Connection -ComputerName $p -Count $PingCount -ErrorAction SilentlyContinue)
    if ($r.Count -gt 0) {
        $m = $r | Measure-Object ResponseTime -Average -Minimum -Maximum
        $loss = $PingCount - $r.Count
        $avg = [math]::Round($m.Average, 1)
        $line = "平均 ${avg}ms | 最小 $($m.Minimum)ms | 最大 $($m.Maximum)ms | 丢包 $loss/$PingCount"
        if ($avg -lt 150)  { Ok $line }
        elseif ($avg -lt 300) { Warn "$line  (一般, 可玩但可能略卡)" }
        else { Bad "$line  (疑似走境外中继!)" }
    } else {
        Bad 'ping 不通 (对方不在线 / 蓝盾没连上 / 防火墙拦截)'
    }
}

# ---------- 4. 上网链路 ----------
$uplink = $null
Section '4. 你的上网链路(判断NAT类型)'
# 排除虚拟网卡(Radmin/Teredo/蓝牙), 只找真实上网链路
$uplinkCfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
    Where-Object { $_.IPv4DefaultGateway -and $_.InterfaceAlias -notmatch 'Radmin|VPN|Teredo|Bluetooth|蓝牙' } |
    Select-Object -First 1
if ($uplinkCfg) {
    $uplink = Get-NetAdapter -InterfaceIndex $uplinkCfg.InterfaceIndex -ErrorAction SilentlyContinue
    if ($uplink) {
        $desc = "$($uplink.Name) $($uplink.InterfaceDescription)"
        Info "上网网卡: $desc"
        if ($desc -match 'Remote NDIS|WWAN|USB|Mobile') { Warn '检测到手机USB共享/移动网卡 → 双重NAT, Radmin直连容易失败(尽量直连宽带/WiFi)' }
        elseif ($desc -match 'Wi-Fi|Wireless|WLAN') { Ok 'Wi-Fi 上网' }
        else { Ok '有线/其他方式上网' }
        $prof = Get-NetConnectionProfile -InterfaceIndex $uplink.InterfaceIndex -ErrorAction SilentlyContinue
        if ($prof) { Info "该网卡网络类型: $($prof.NetworkCategory)  (Private=专用更利于直连)" }
    }
} else { Warn '没找到带默认网关的网卡?' }
try {
    $me = Invoke-RestMethod -Uri 'http://ipinfo.io/json' -TimeoutSec 8
    Info "公网出口IP: $($me.ip) | $($me.city)/$($me.region)/$($me.country) | $($me.org)"
} catch { Warn '无法获取公网出口信息(无外网?)' }

# ---------- 5. 防火墙/网络类型 ----------
Section '5. 防火墙放行检查(直连相关)'
$rprof = Get-NetConnectionProfile -InterfaceAlias $adapterName -ErrorAction SilentlyContinue
if ($rprof) { Info "蓝盾虚拟网卡网络类型: $($rprof.NetworkCategory)" }
$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '^Radmin VPN' })
if ($rules.Count -gt 0) {
    foreach ($ru in $rules) {
        $line = "$($ru.DisplayName) | 方向:$($ru.Direction) | 动作:$($ru.Action) | 启用:$($ru.Enabled) | 配置文件:$($ru.Profile)"
        if ($ru.Enabled -and $ru.Direction -eq 'Inbound' -and $ru.Action -eq 'Allow') { Ok $line }
        else { Warn $line }
    }
} else {
    Warn '没有 Radmin 防火墙放行规则! 直连会受阻。管理员运行: 本脚本加 -Fix 可自动创建'
}

# ---------- 6. 蓝盾连的服务器 ----------
Section '6. 蓝盾当前连接的服务器(判断是否走中继)'
$seen = @{}
foreach ($pn in @('RvControlSvc', 'RvRvpnGui')) {
    $pr = Get-Process $pn -ErrorAction SilentlyContinue
    if (-not $pr) { continue }
    Get-NetTCPConnection -OwningProcess $pr.Id -State Established -ErrorAction SilentlyContinue | ForEach-Object {
        $ip = $_.RemoteAddress
        if ($ip -and $ip -notin @('0.0.0.0', '::') -and -not $seen.ContainsKey($ip)) {
            $seen[$ip] = $true
            $g = Geo $ip
            $tag = if ($g -match '中国|CN') { '(国内)' } else { '(非国内: Radmin常驻控制节点, 是否走中继请看第3节延迟)' }
            Write-Host ("  {0,-22} :{1,-6}  归属: {2} {3}" -f $ip, $_.RemotePort, $g, $tag)
        }
    }
}
if ($seen.Count -eq 0) { Info '暂未捕获到控制连接(蓝盾可能没完全连上)' }

# ---------- 结论 ----------
Section '体检结论速查'
Write-Host '  延迟参考: <150ms 直连良好 | 150~300ms 一般 | >300ms 疑似境外中继' -ForegroundColor Gray
Write-Host '  若延迟>300ms: ① 双方都重启一次蓝盾  ② 别用手机流量/USB共享(双重NAT)  ③ 双方防火墙放行' -ForegroundColor Yellow
Write-Host '  若反复不行: 换 ZeroTier / Tailscale / 蒲公英(对IPv6直连更友好)' -ForegroundColor Yellow

# ---------- 修复模式 ----------
if ($Fix) {
    Section '应用修复 (-Fix)'
    if ($ad) { Set-NetConnectionProfile -InterfaceAlias $adapterName -NetworkCategory Private -ErrorAction SilentlyContinue; Ok "已设 $adapterName 为专用(Private)" }
    if ($uplink) { Set-NetConnectionProfile -InterfaceIndex $uplink.InterfaceIndex -NetworkCategory Private -ErrorAction SilentlyContinue; Ok "已设 $($uplink.Name) 为专用(Private)" }
    $paths = @(
        @{ Name = 'Radmin VPN';     Path = 'C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe' },
        @{ Name = 'Radmin VPN Svc'; Path = 'C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe' }
    )
    foreach ($item in $paths) {
        if (Test-Path $item.Path) {
            $exists = Get-NetFirewallRule -DisplayName $item.Name -ErrorAction SilentlyContinue
            if (-not $exists) {
                New-NetFirewallRule -DisplayName $item.Name -Direction Inbound -Action Allow -Program $item.Path -Profile Any -ErrorAction SilentlyContinue | Out-Null
                Ok "已创建防火墙规则: $($item.Name)"
            } else { Info "防火墙规则已存在: $($item.Name)" }
        } else { Warn "找不到程序文件: $($item.Path)" }
    }
    Write-Host ''
    Ok '修复完成。建议你和朋友都重启一次蓝盾, 再重新运行本脚本复测。'
}
Write-Host ''



