<#
  联机组网体检 + 方案推荐 (NetCheck)
  ============================================
  一键盘点你的网络环境, 实测到朋友的延迟, 并自动推荐适合的组网方案
  (蓝盾Radmin / ZeroTier / Tailscale / EasyTier / UU局域网)

  普通用法(只读, 无需管理员):
      双击 NetCheck.bat   或  pwsh -File NetCheck.ps1
  修复蓝盾防火墙(-Fix, 需管理员):
      pwsh -File NetCheck.ps1 -Fix
  可选参数:
      -PeerIP '26.x.x.x'  手动指定朋友IP
      -PingCount 10       ping次数(默认8)
      -SkipGeo            跳过归属地查询
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

# STUN: 问公共STUN服务器"你看到我的公网IP:端口是什么"
function Get-StunMapped {
    param([string]$Host, [int]$Port = 3478, [int]$TimeoutMs = 3000)
    $u = $null
    try {
        $u = New-Object System.Net.Sockets.UdpClient
        $u.Client.ReceiveTimeout = $TimeoutMs
        $u.Client.SendTimeout = $TimeoutMs
        $u.Connect($Host, $Port)
        $req = New-Object byte[] 20
        $req[0] = 0; $req[1] = 1
        $req[4] = 0xD3; $req[5] = 0x12; $req[6] = 0xA4; $req[7] = 0x42
        $rnd = New-Object byte[] 12
        (New-Object System.Random).NextBytes($rnd)
        for ($k = 0; $k -lt 12; $k++) { $req[8 + $k] = $rnd[$k] }
        [void]$u.Send($req, 20)
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $u.Receive([ref]$ep)
        if (-not $resp -or $resp.Length -lt 20) { return $null }
        $i = 20; $mapIp = ''; $mapPort = 0
        while ($i -lt ($resp.Length - 3)) {
            $type = ($resp[$i] -shl 8) -bor $resp[$i + 1]
            $alen = ($resp[$i + 2] -shl 8) -bor $resp[$i + 3]
            if ($type -eq 0x0020 -and $alen -ge 8) {
                $mapPort = ((($resp[$i + 6] -shl 8) -bor $resp[$i + 7]) -bxor 0x2112) -band 0xFFFF
                $magic = @(0xD3, 0x12, 0xA4, 0x42)
                $b = New-Object byte[] 4
                for ($k = 0; $k -lt 4; $k++) { $b[$k] = $resp[$i + 8 + $k] -bxor $magic[$k] }
                $mapIp = "$($b[0]).$($b[1]).$($b[2]).$($b[3])"
                break
            }
            $i += 4 + $alen
            if ($alen % 4 -ne 0) { $i += 4 - ($alen % 4) }
        }
        if ($mapIp) { return [pscustomobject]@{ Server = $Host; MappedIP = $mapIp; MappedPort = $mapPort } }
        return $null
    } catch { return $null } finally { if ($u) { try { $u.Close() } catch {} } }
}

$isAdmin = $false
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
if ($Fix -and -not $isAdmin) { Bad '-Fix 需要管理员权限'; $Fix = $false }

# ---------- 1. 蓝盾现状 ----------
Section '1. 蓝盾 (Radmin VPN) 现状'
$svc = Get-Service RvControlSvc -ErrorAction SilentlyContinue
if ($svc) { if ($svc.Status -eq 'Running') { Ok "服务 RvControlSvc: Running" } else { Bad "服务: $($svc.Status)" } }
else { Info '未安装蓝盾(跳过本节相关项)' }
$ad = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
$ip4 = $null
if ($ad) {
    if ($ad.Status -eq 'Up') { Ok "虚拟网卡 $adapterName : Up" } else { Warn "虚拟网卡: $($ad.Status)" }
    $ip4 = Get-NetIPAddress -InterfaceAlias $adapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($ip4) { Ok "我的虚拟 IP: $($ip4.IPAddress)" }
}
$peers = @()
if ($PeerIP) { $peers = @($PeerIP) }
elseif ($ad) {
    $mine = if ($ip4) { $ip4.IPAddress } else { '' }
    $peers = @(Get-NetNeighbor -InterfaceIndex $ad.ifIndex -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like '26.*' -and $_.IPAddress -notin @('26.0.0.1', '26.255.255.255', $mine) } |
        Select-Object -ExpandProperty IPAddress -Unique | Select-Object -First 3)
}
if ($peers.Count -eq 0) { Info '未发现蓝盾同伴(没装/没连/对方不在线, 不影响后续检测)' }
foreach ($p in $peers) {
    $r = @(Test-Connection -ComputerName $p -Count $PingCount -ErrorAction SilentlyContinue)
    if ($r.Count -gt 0) {
        $m = $r | Measure-Object ResponseTime -Average -Minimum -Maximum
        $avg = [math]::Round($m.Average, 1)
        $line = "到 $p : 平均 ${avg}ms | 最小 $($m.Minimum)ms | 最大 $($m.Maximum)ms | 丢包 $($PingCount - $r.Count)/$PingCount"
        if ($avg -lt 150) { Ok $line }
        elseif ($avg -lt 300) { Warn "$line (一般)" }
        else { Bad "$line (疑似境外中继!)" }
    } else { Warn "ping $p 不通" }
}

# ---------- 2. 上网链路与NAT ----------
Section '2. 上网链路与 NAT 环境'
$uplinkCfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
    Where-Object { $_.IPv4DefaultGateway -and $_.InterfaceAlias -notmatch 'Radmin|VPN|Teredo|Bluetooth|蓝牙' } |
    Select-Object -First 1
$uplink = $null; $localIp = ''; $tether = $false
if ($uplinkCfg) {
    $uplink = Get-NetAdapter -InterfaceIndex $uplinkCfg.InterfaceIndex -ErrorAction SilentlyContinue
    if ($uplink) {
        $desc = "$($uplink.Name) $($uplink.InterfaceDescription)"
        Info "上网网卡: $desc"
        if ($desc -match 'Remote NDIS|WWAN|USB|Mobile') { $tether = $true; Warn '手机USB共享/移动网卡 → 双重NAT, 打洞难(尽量换宽带/WiFi直连)' }
        elseif ($desc -match 'Wi-Fi|Wireless|WLAN') { Ok 'Wi-Fi 上网' }
        else { Ok '有线/其他上网' }
        $localIp = ($uplinkCfg.IPv4Address | Select-Object -First 1).IPAddress
        Info "本地IP: $localIp"
    }
}
if ($localIp -match '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.') { Bad '本地IP落在 100.64.0.0/10 → 已是运营商级 CGNAT(大内网)! 直连打洞非常难' }
$publicIp = ''
$me = $null
try { $me = Invoke-RestMethod -Uri 'http://ipinfo.io/json' -TimeoutSec 8 } catch { Start-Sleep -Seconds 2; try { $me = Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec 8 } catch {} }
if ($me) { $publicIp = $me.ip; Info "公网出口: $($me.ip) | $($me.city)/$($me.region)/$($me.country) | $($me.org)" } else { Warn '无法获取公网出口(无外网?)' }
if ($publicIp -and $me.org -match 'Mobile|CMNET|移动|Unicom|联通|CHINANET|电信') {
    if ($me.org -match 'Mobile|CMNET|移动') { Warn '运营商: 移动 → 社区公认组网大内网重灾区(200ms+常见), 建议配合中转方案' }
    else { Ok "运营商: $($me.org)" }
}

# ---------- 3. STUN NAT类型探测 ----------
Section '3. STUN NAT 类型探测'
$stunResults = @()
foreach ($s in @('stun.chat.bilibili.com', 'stun.miwifi.com', 'stun.l.google.com')) {
    $res = Get-StunMapped -Host $s
    if ($res) { $stunResults += $res; Info "$($res.Server) 看到你: $($res.MappedIP):$($res.MappedPort)" }
}
if ($stunResults.Count -eq 0) { Warn 'STUN 全部超时(网络限制), 无法判定 NAT 类型' }
else {
    $ipSet = @($stunResults | Select-Object -ExpandProperty MappedIP -Unique)
    $portSet = @($stunResults | Select-Object -ExpandProperty MappedPort -Unique)
    if ($ipSet.Count -gt 1) { Bad '多个出口IP不一致 → 多线路/多出口NAT(打洞不稳定)' }
    if ($stunResults.Count -ge 2 -and $ipSet.Count -eq 1) {
        if ($portSet.Count -gt 1) { Bad '同一IP但端口会变 → 对称型 NAT(打洞最难的类型, 建议中转方案)' }
        else { Ok '同一IP且端口不变 → 锥形 NAT(打洞较容易, 直连方案成功率较高)' }
    }
    if ($publicIp) {
        $mapped = $stunResults[0].MappedIP
        if ($mapped -ne $publicIp) { Warn "STUN映射IP($mapped) 与公网出口($publicIp) 不一致 → 多层NAT/CGNAT" }
        elseif ($mapped -match '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.') { Bad "STUN映射IP($mapped) 在 CGNAT 段 → 运营商大内网" }
    }
}

# ---------- 4. IPv6 检测 ----------
Section '4. IPv6 检测'
$v6 = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike 'fe80:*' -and $_.IPAddress -notlike '::1*' -and $_.IPAddress -notlike 'fdfd:*' -and $_.InterfaceAlias -notmatch 'Teredo' })
if ($v6.Count -gt 0) { $v6 | ForEach-Object { Info "IPv6: $($_.IPAddress) ($($_.InterfaceAlias))" } } else { Warn '无公网 IPv6' }
$v6ok = $false
$pv6 = @(Test-Connection -ComputerName '2400:3200::1' -Count 2 -ErrorAction SilentlyContinue)
if ($pv6.Count -gt 0) { $v6ok = $true; Ok "IPv6 连通(阿里DNS): $($pv6[0].ResponseTime)ms → 可走 IPv6 直连" }
else { Warn 'IPv6 ping 不通(可能没有IPv6或路由器没放行)' }

# ---------- 5. 防火墙 ----------
Section '5. 防火墙放行检查(直连相关)'
$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '^Radmin VPN' })
if ($rules.Count -gt 0) {
    foreach ($ru in $rules) {
        if ($ru.Enabled -and $ru.Direction -eq 'Inbound' -and $ru.Action -eq 'Allow') { Ok "$($ru.DisplayName) 已放行" } else { Warn "$($ru.DisplayName) 异常" }
    }
} elseif ($svc) { Warn '蓝盾没有防火墙放行规则(-Fix 可自动补)' }

# ---------- 6. 推荐方案 ----------
Section '6. 推荐方案排序'
$rec = @()
if ($v6ok) { $rec += '① EasyTier 或 ZeroTier —— 你的网络有可用 IPv6, 它们支持 IPv6 直连, 成功率和延迟最优' }
else { $rec += '① 先想办法恢复 IPv6(路由器开 IPv6 或用有 IPv6 的线路) —— 这是国内组网最稳的直连通路' }
if ($stunResults.Count -ge 2 -and $portSet.Count -gt 1) { $rec += '② NAT 是对称型, 直连打洞难 → EasyTier(公共节点/自建) 或 UU局域网 走中转兜底' }
if ($localIp -match '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.' -or ($me -and $me.org -match 'Mobile|CMNET|移动')) { $rec += '③ 检测到 CGNAT/移动大内网 → 中转类方案优先: EasyTier 公共节点 / UU局域网 / 蒲公英' }
$coneDetected = ($stunResults.Count -ge 2 -and $ipSet.Count -eq 1 -and $portSet.Count -eq 1)
if (-not ($rec -match '②')) {
    if ($coneDetected) { $rec += '② NAT 是锥形, 直连可行 → ZeroTier / 蓝盾 都有机会直连' }
    else { $rec += '② NAT 类型未判定(探测受限) → 优先选带中转的方案; 直连类(蓝盾/ZeroTier)碰运气' }
}
$rec += '★ 兜底懒人方案: 网易UU加速器的「局域网联机」功能(免费) —— 不用注册组网工具, 双方各装UU点联机即可'
if ($tether) { $rec += '⚠ 当前用手机热点/共享: 建议换宽带直连, 任何方案都会更稳' }
$rec | ForEach-Object { Write-Host "  $_" }

Section '结论速查'
Write-Host '  延迟: <150ms 直连良好 | 150~300ms 一般 | >300ms 疑似境外中继' -ForegroundColor Gray
Write-Host '  方案选择: 有IPv6→EasyTier/ZeroTier; 移动/CGNAT→EasyTier中转或UU局域网; 电信联通锥形NAT→蓝盾/ZeroTier' -ForegroundColor Gray
Write-Host '  反复不行就上 UU局域网, 免费省事不折腾' -ForegroundColor Yellow

# ---------- 修复模式 ----------
if ($Fix) {
    Section '应用修复 (-Fix)'
    if ($ad) { Set-NetConnectionProfile -InterfaceAlias $adapterName -NetworkCategory Private -ErrorAction SilentlyContinue; Ok "已设 $adapterName 为专用" }
    if ($uplink) { Set-NetConnectionProfile -InterfaceIndex $uplink.InterfaceIndex -NetworkCategory Private -ErrorAction SilentlyContinue; Ok "已设 $($uplink.Name) 为专用" }
    foreach ($item in @(
        @{ Name = 'Radmin VPN';     Path = 'C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe' },
        @{ Name = 'Radmin VPN Svc'; Path = 'C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe' })) {
        if (Test-Path $item.Path) {
            if (-not (Get-NetFirewallRule -DisplayName $item.Name -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $item.Name -Direction Inbound -Action Allow -Program $item.Path -Profile Any -ErrorAction SilentlyContinue | Out-Null
                Ok "已创建规则: $($item.Name)"
            } else { Info "规则已存在: $($item.Name)" }
        }
    }
    Ok '修复完成, 建议双方重启蓝盾后复测'
}
Write-Host ''


