<#
  NetCheck v0.2.0 - 联机体检工具 (玩家向)
  ==========================================
  检测蓝盾(Radmin VPN)链路 + 网络环境(NAT/CGNAT/IPv6), 输出"现在怎样/依据/下一步"式报告。
  默认只读, 不修改任何系统设置。

  用法:
    双击 NetCheck.bat                    普通体检(自动保存 TXT+JSON 报告)
    -PeerIP '26.x.x.x'                   手动指定朋友的蓝盾IP
    -PeerIPv6 '2409:...'                 手动指定朋友的IPv6(用于检测IPv6直连)
    -Compare '朋友报告.json'              两端报告对照
    -Fix / -Fix -Force                   修复模式(先预览, 需管理员; -Force 跳过确认)
    -Undo                                撤销本工具做过的修改(读状态文件)
    -SkipGeo                             跳过IP归属地查询
    -NoSave                              不保存报告文件
#>
param(
    [int]$PingCount = 8,
    [string]$PeerIP = '',
    [string]$PeerIPv6 = '',
    [string]$Compare = '',
    [switch]$Fix,
    [switch]$Undo,
    [switch]$Force,
    [switch]$SkipGeo,
    [switch]$NoSave
)
$ScriptVersion = '0.2.1'
$ErrorActionPreference = 'SilentlyContinue'
$adapterName = 'Radmin VPN'
$rulePrefix = 'NetCheck-Radmin-'

# ================= 输出与日志 =================
$script:Log = New-Object System.Collections.ArrayList
function Emit {
    param([string]$Line, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    [void]$script:Log.Add($Line)
    Write-Host $Line -ForegroundColor $Color
}
function Section($t) {
    Emit ''
    Emit ('=' * 62) Cyan
    Emit ("  $t") Cyan
    Emit ('=' * 62) Cyan
}
function Ok($m)   { Emit ('  [OK]  ' + $m) Green }
function Warn($m) { Emit ('  [!]   ' + $m) Yellow }
function Bad($m)  { Emit ('  [X]   ' + $m) Red }
function Info($m) { Emit ('  [i]   ' + $m) DarkGray }

# ================= 纯函数(可单元测试) =================
function ConvertTo-StunMapped {
    param([byte[]]$Resp, [string]$Server = '', [byte[]]$Tid = $null)
    # 解析 STUN Binding 响应, 返回 MappedIP/MappedPort; 非法返回 $null
    if (-not $Resp -or $Resp.Length -lt 20) { return $null }
    $t = ([int]$Resp[0] -shl 8) -bor [int]$Resp[1]
    if ($t -ne 0x0101) { return $null }
    if (-not ($Resp[4] -eq 0x21 -and $Resp[5] -eq 0x12 -and $Resp[6] -eq 0xA4 -and $Resp[7] -eq 0x42)) { return $null }
    if ($Tid -and $Tid.Length -eq 12) {
        for ($k = 0; $k -lt 12; $k++) { if ($Resp[8 + $k] -ne $Tid[$k]) { return $null } }
    }
    $i = 20
    while ($i -lt ($Resp.Length - 3)) {
        $type = ([int]$Resp[$i] -shl 8) -bor [int]$Resp[$i + 1]
        $alen = ([int]$Resp[$i + 2] -shl 8) -bor [int]$Resp[$i + 3]
        if (($i + 4 + $alen) -gt $Resp.Length) { break }   # 属性声称长度超出报文实际长度 → 截断报文, 丢弃
        if (($type -eq 0x0001 -or $type -eq 0x0020) -and $alen -ge 8 -and $Resp[$i + 5] -eq 0x01) {
            $port = ([int]$Resp[$i + 6] -shl 8) -bor [int]$Resp[$i + 7]
            $b = New-Object byte[] 4
            for ($k = 0; $k -lt 4; $k++) { $b[$k] = $Resp[$i + 8 + $k] }
            if ($type -eq 0x0020) {
                $port = ($port -bxor 0x2112) -band 0xFFFF
                $magic = @(0x21, 0x12, 0xA4, 0x42)
                for ($k = 0; $k -lt 4; $k++) { $b[$k] = $b[$k] -bxor $magic[$k] }
            }
            return [pscustomobject]@{ Server = $Server; MappedIP = "$($b[0]).$($b[1]).$($b[2]).$($b[3])"; MappedPort = $port }
        }
        $i += 4 + $alen
        if ($alen % 4 -ne 0) { $i += 4 - ($alen % 4) }
    }
    return $null
}

function Get-PingStats {
    param([object[]]$Replies)
    # 兼容 PS5.1(ResponseTime) 与 PS7(Latency/Status), 按成功状态统计
    $ok = 0; $lats = @()
    foreach ($rp in $Replies) {
        if (-not $rp) { continue }
        $success = $true
        if ($rp.PSObject.Properties['Status']) { $success = ($rp.Status -eq 'Success') }
        $lat = $null
        if ($rp.PSObject.Properties['Latency'] -and $null -ne $rp.Latency) { $lat = $rp.Latency }
        elseif ($rp.PSObject.Properties['ResponseTime'] -and $null -ne $rp.ResponseTime) { $lat = $rp.ResponseTime }
        if ($success -and $null -ne $lat) { $ok++; $lats += [double]$lat }
    }
    $total = @($Replies).Count
    if ($ok -eq 0) { return [pscustomobject]@{ Ok = 0; Total = $total; Avg = $null; Min = $null; Max = $null; Loss = $total } }
    $m = $lats | Measure-Object -Average -Minimum -Maximum
    return [pscustomobject]@{ Ok = $ok; Total = $total; Avg = [math]::Round($m.Average, 1); Min = $m.Minimum; Max = $m.Maximum; Loss = $total - $ok }
}

function Get-LatencyVerdict {
    param($AvgMs)
    # 仅评价延迟, 丢包由 Get-LossVerdict 单独评价
    if ($null -eq $AvgMs -or "$AvgMs" -eq '') { return 'UNKNOWN' }
    $v = [double]$AvgMs
    if ($v -lt 150) { return 'GOOD' }
    if ($v -lt 300) { return 'FAIR' }
    return 'POOR'
}

function Get-LossVerdict {
    param([int]$LossCount, [int]$TotalCount)
    if ($TotalCount -le 0 -or $LossCount -le 0) { return 'NONE' }
    if ($LossCount -gt [math]::Floor($TotalCount * 0.2)) { return 'HEAVY' }
    return 'MILD'
}

function Merge-ChangeList {
    param([object[]]$Existing, [object[]]$New)
    # 合并改动记录: 同一(Kind+Target)只保留第一次记录, 保住最初修改前的状态
    $list = @($Existing)
    foreach ($n in $New) {
        $dup = $false
        foreach ($e in $list) { if ($e.Kind -eq $n.Kind -and "$($e.Target)" -eq "$($n.Target)") { $dup = $true; break } }
        if (-not $dup) { $list += $n }
    }
    return $list
}

function Expand-Changes {
    param($Items)
    # 防御性扁平化: 兼容旧版可能产生的嵌套结构, 保证每项都是单个改动对象
    $flat = @()
    foreach ($it in @($Items)) {
        if (-not $it) { continue }
        if ($it.PSObject.Properties['Kind']) { $flat += $it }
        else { $flat += @(Expand-Changes -Items $it) }
    }
    return $flat
}

function ConvertTo-CompareSource {
    param($Obj)
    # 兼容完整报告(数据在 facts 下)与分享报告(数据在顶层)
    if (-not $Obj) { return $null }
    if ($Obj.PSObject.Properties['facts']) { return $Obj.facts }
    return $Obj
}

function Get-Val {
    param($Src, [string]$Name)
    if (-not $Src -or -not $Src.PSObject.Properties[$Name]) { return '数据缺失' }
    return "$($Src.$Name)"
}

function Get-NatVerdict {
    param([object[]]$Results)
    $ok = @($Results | Where-Object { $_.Status -eq 'OK' })
    if ($ok.Count -lt 2) { return [pscustomobject]@{ Type = 'UNDETERMINED'; Reason = "仅有 $($ok.Count) 个服务器应答, 证据不足, 不做完整判定" } }
    $ips = @($ok | Select-Object -ExpandProperty MappedIP -Unique)
    $ports = @($ok | Select-Object -ExpandProperty MappedPort -Unique)
    if ($ips.Count -gt 1) { return [pscustomobject]@{ Type = 'MULTI_EXIT'; Reason = '不同出口IP(多线路/多层NAT), 直连行为不稳定' } }
    if ($ports.Count -eq 1) { return [pscustomobject]@{ Type = 'CONE_LIKE'; Reason = '同一本地端口映射到同一出口IP:端口(锥形行为, 打洞较容易)' } }
    return [pscustomobject]@{ Type = 'PORT_VARYING'; Reason = '同一出口IP但端口随目标变化(对称型行为, 打洞困难)' }
}

function Get-RelayVerdict {
    param([string]$LatencyVerdict, [bool]$HasForeignConn)
    if ($LatencyVerdict -eq 'POOR') {
        if ($HasForeignConn) { return 'RELAY_SUSPECTED' }
        return 'POOR_UNCONFIRMED'
    }
    return 'NONE'
}

function Mask-Ip {
    param([string]$Ip)
    if (-not $Ip) { return '' }
    if ($Ip -match ':') { $p = $Ip.Split(':'); return (($p[0..3]) -join ':') + '::x' }
    $o = $Ip.Split('.')
    if ($o.Count -eq 4) { return "$($o[0]).$($o[1]).x.x" }
    return 'x'
}

function Get-Recommendations {
    param($Facts)
    $rec = @()
    if ($Facts.LatencyVerdict -eq 'POOR' -and $Facts.RelayVerdict -eq 'RELAY_SUSPECTED') {
        $rec += '当前高延迟与境外中继连接并存: 请与朋友各自重启一次组网工具, 观察延迟是否回落(依据: 实测数据, 重启后可重新打洞)'
    }
    if ($Facts.LatencyVerdict -eq 'POOR' -and $Facts.RelayVerdict -eq 'POOR_UNCONFIRMED') {
        $rec += '延迟高但未抓到中继证据: 先保持双方网络/软件设置不变, 让朋友跑同版本工具后对照(依据: 缺少对方侧证据, 不宜直接换软件)'
    }
    if ($Facts.LocalV6 -and $Facts.V6ExtOk -and $Facts.PeerV6Ok -eq '') {
        $rec += '本机IPv6可用且外网连通, 但未检测朋友侧IPv6: 让朋友运行本工具并填写 -PeerIPv6 对照(依据: IPv6直连是成功率最高的路径, 需双方条件确认)'
    }
    if ($Facts.LocalV6 -and $Facts.V6ExtOk -and $Facts.PeerV6Ok -eq $true) {
        $rec += '双方IPv6条件齐备: 优先尝试 EasyTier 或 ZeroTier 走IPv6直连(依据: 本机与朋友IPv6均可达)'
    }
    if ($Facts.PeerV6Ok -eq $false) {
        $rec += '本机到朋友IPv6不通: 不宣称双方可IPv6直连, 先排查朋友侧IPv6或换IPv4方案(依据: 实测不通)'
    }
    if ($Facts.NatType -eq 'PORT_VARYING' -or $Facts.NatType -eq 'MULTI_EXIT') {
        $rec += 'NAT实测为对称行为/多出口: 直连打洞成功率低, 优先选择带中转的方案(如 EasyTier 公共节点或 UU局域网)(依据: STUN实测映射行为)'
    }
    if ($Facts.IsCgnat -or $Facts.IsMobileIsp) {
        $rec += '检测到 CGNAT/移动大内网迹象: 中转类方案优先级高于纯打洞方案(依据: 100.64段/运营商信息)'
    }
    if ($Facts.Tether) {
        $rec += '当前为手机热点/USB共享(双重NAT): 换宽带直连能提高任何方案的稳定性(依据: 网卡类型)'
    }
    if ($Facts.LossVerdict -eq 'MILD' -or $Facts.LossVerdict -eq 'HEAVY') {
        $rec += "存在丢包 $($Facts.LossCount)/$($Facts.TotalPings): 先排查无线干扰/代理劫持/网线, 丢包比高延迟更影响游戏手感(依据: 实测丢包)"
    }
    if ($rec.Count -eq 0) {
        $rec += '未发现明显风险项: 当前方案可继续使用, 若仍卡顿请与朋友对照报告(依据: 本机各项检测正常)'
    }
    $rec += '第三方方案说明(如 UU局域网/EasyTier 免费政策)以官方页面为准, 核实于 2026-09'
    return $rec
}

# ================= 主流程 =================
function Main {
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    $facts = @{
        Version = $ScriptVersion; Generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        LatencyVerdict = 'UNKNOWN'; LossVerdict = 'NONE'; RelayVerdict = 'NONE'; PeerIp = $PeerIP
        AvgMs = $null; MinMs = $null; MaxMs = $null; LossCount = 0; TotalPings = 0
        NatType = 'UNDETERMINED'; NatReason = ''; StunOk = 0; StunFail = 0; StunDetail = @()
        LocalV6 = $false; V6ExtOk = $false; PeerV6Ok = ''; V6Addrs = @()
        IsCgnat = $false; IsMobileIsp = $false; Tether = $false; UplinkDesc = ''; PublicIp = ''; IspInfo = ''
        HasForeignConn = $false; ForeignConns = @(); RadminInstalled = $false; PeerFound = $false
    }

    # ---- 蓝盾状态 ----
    $svc = Get-Service RvControlSvc -ErrorAction SilentlyContinue
    $facts.RadminInstalled = [bool]$svc
    $ad = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
    $ip4 = $null
    if ($ad) { $ip4 = Get-NetIPAddress -InterfaceAlias $adapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue }

    # ---- 同伴与延迟 ----
    $peers = @()
    if ($PeerIP) { $peers = @($PeerIP) }
    elseif ($ad) {
        $mine = if ($ip4) { $ip4.IPAddress } else { '' }
        $peers = @(Get-NetNeighbor -InterfaceIndex $ad.ifIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -like '26.*' -and $_.IPAddress -notin @('26.0.0.1', '26.255.255.255', $mine) } |
            Select-Object -ExpandProperty IPAddress -Unique | Select-Object -First 3)
    }
    $pingResults = @()
    foreach ($p in $peers) {
        $facts.PeerFound = $true
        $facts.PeerIp = $p
        $r = @(Test-Connection -ComputerName $p -Count $PingCount -ErrorAction SilentlyContinue)
        $facts.TotalPings = $PingCount
        $st = Get-PingStats -Replies $r
        $facts.AvgMs = $st.Avg; $facts.MinMs = $st.Min; $facts.MaxMs = $st.Max
        $facts.LossCount = $st.Loss
        $pingResults += [pscustomobject]@{ Peer = $p; Avg = $st.Avg; Min = $st.Min; Max = $st.Max; Loss = $st.Loss; Ok = $st.Ok }
    }

    # ---- 上网链路 ----
    $uplinkCfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
        Where-Object { $_.IPv4DefaultGateway -and $_.InterfaceAlias -notmatch 'Radmin|VPN|Teredo|Bluetooth|蓝牙|Mihomo|Meta' } |
        Select-Object -First 1
    $uplink = $null; $localIp = ''
    if ($uplinkCfg) {
        $uplink = Get-NetAdapter -InterfaceIndex $uplinkCfg.InterfaceIndex -ErrorAction SilentlyContinue
        if ($uplink) {
            $facts.UplinkDesc = "$($uplink.Name) $($uplink.InterfaceDescription)"
            if ($facts.UplinkDesc -match 'Remote NDIS|WWAN|USB|Mobile') { $facts.Tether = $true }
            $localIp = ($uplinkCfg.IPv4Address | Select-Object -First 1).IPAddress
        }
    }
    if ($localIp -match '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.') { $facts.IsCgnat = $true }

    # ---- 公网出口(两次尝试) ----
    $me = $null
    try { $me = Invoke-RestMethod -Uri 'http://ipinfo.io/json' -TimeoutSec 8 } catch { Start-Sleep -Seconds 2; try { $me = Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec 8 } catch {} }
    if ($me) {
        $facts.PublicIp = $me.ip
        $facts.IspInfo = "$($me.city)/$($me.region)/$($me.country) $($me.org)"
        if ($me.org -match 'Mobile|CMNET|移动') { $facts.IsMobileIsp = $true }
    }

    # ---- STUN (同一本地UDP端点) ----
    $stun = @()
    $sock = $null
    try { $sock = New-Object System.Net.Sockets.UdpClient(0); $sock.Client.ReceiveTimeout = 3000 } catch {}
    if ($sock) {
        foreach ($srv in @('stun.chat.bilibili.com', 'stun.miwifi.com', 'stun.l.google.com')) {
            $st = 'ERR'; $resp = $null
            try {
                $sock.Connect($srv, 3478)
                $req = New-Object byte[] 20
                $req[0] = 0; $req[1] = 1
                $req[4] = 0x21; $req[5] = 0x12; $req[6] = 0xA4; $req[7] = 0x42
                $rnd = New-Object byte[] 12
                (New-Object System.Random).NextBytes($rnd)
                for ($k = 0; $k -lt 12; $k++) { $req[8 + $k] = $rnd[$k] }
                [void]$sock.Send($req, 20)
                $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $resp = $sock.Receive([ref]$ep)
                $st = 'OK'
            } catch {
                $msg = "$($_.Exception.Message)"
                if ($msg -match 'timed out|超时') { $st = 'TIMEOUT' }
                elseif ($msg -match 'refused|拒绝|unreachable') { $st = 'UNREACHABLE' }
                else { $st = 'ERROR' }
            }
            if ($st -eq 'OK' -and $resp) {
                $m = ConvertTo-StunMapped -Resp $resp -Server $srv -Tid $req[8..19]
                if ($m) { $stun += [pscustomobject]@{ Server = $srv; Status = 'OK'; MappedIP = $m.MappedIP; MappedPort = $m.MappedPort }; $facts.StunOk++ }
                else { $stun += [pscustomobject]@{ Server = $srv; Status = 'BAD_DATA'; MappedIP = ''; MappedPort = 0 }; $facts.StunFail++ }
            } else {
                $stun += [pscustomobject]@{ Server = $srv; Status = $st; MappedIP = ''; MappedPort = 0 }
                $facts.StunFail++
            }
        }
        try { $sock.Close() } catch {}
    }
    $facts.StunDetail = $stun
    $natV = Get-NatVerdict -Results $stun
    $facts.NatType = $natV.Type; $facts.NatReason = $natV.Reason

    # ---- IPv6 三项 ----
    $v6 = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike 'fe80:*' -and $_.IPAddress -notlike '::1*' -and $_.IPAddress -notlike 'fd*' -and $_.InterfaceAlias -notmatch 'Teredo|Mihomo|Meta' })
    if ($v6.Count -gt 0) { $facts.LocalV6 = $true; $facts.V6Addrs = @($v6 | ForEach-Object { "$($_.IPAddress) [$($_.InterfaceAlias)]" }) }
    $pv6 = @(Test-Connection -ComputerName '2400:3200::1' -Count 2 -ErrorAction SilentlyContinue)
    if ($pv6.Count -gt 0) { $facts.V6ExtOk = $true }
    if ($PeerIPv6) {
        $pp = @(Test-Connection -ComputerName $PeerIPv6 -Count 3 -ErrorAction SilentlyContinue)
        if ($pp.Count -gt 0) { $facts.PeerV6Ok = $true }
        else { $facts.PeerV6Ok = $false }
    }

    # ---- 中继证据: Radmin 控制连接 + 归属 ----
    $foreign = @()
    foreach ($pn in @('RvControlSvc', 'RvRvpnGui')) {
        $pr = Get-Process $pn -ErrorAction SilentlyContinue
        if (-not $pr) { continue }
        Get-NetTCPConnection -OwningProcess $pr.Id -State Established -ErrorAction SilentlyContinue | ForEach-Object {
            $ip = $_.RemoteAddress
            if ($ip -and $ip -notin @('0.0.0.0', '::')) {
                $geo = ''
                if (-not $SkipGeo) {
                    try {
                        $u = "http://ipinfo.io/$ip/json"
                        if ($ip -match ':') { $u = "http://ipinfo.io/[$ip]/json" }
                        $j = Invoke-RestMethod -Uri $u -TimeoutSec 6
                        $geo = "$($j.city) $($j.country)"
                        if ($j.country -ne 'CN') { $facts.HasForeignConn = $true }
                    } catch {}
                }
                $foreign += [pscustomobject]@{ Ip = $ip; Port = $_.RemotePort; Geo = $geo }
            }
        }
    }
    $facts.ForeignConns = $foreign
    $facts.LatencyVerdict = Get-LatencyVerdict -AvgMs $facts.AvgMs
    $facts.LossVerdict = Get-LossVerdict -LossCount $facts.LossCount -TotalCount $facts.TotalPings
    $facts.RelayVerdict = Get-RelayVerdict -LatencyVerdict $facts.LatencyVerdict -HasForeignConn $facts.HasForeignConn
    $recs = Get-Recommendations -Facts $facts

    # ================= 输出: 摘要优先 =================
    $title = '与朋友的连接当前无法测试'
    if ($facts.TotalPings -gt 0 -and $facts.AvgMs) {
        if ($facts.LossVerdict -eq 'HEAVY') { $title = '与朋友的连接不稳定(丢包严重)' }
        elseif ($facts.LatencyVerdict -eq 'POOR') {
            $title = if ($facts.RelayVerdict -eq 'RELAY_SUSPECTED') { '与朋友的连接不稳定, 疑似经过中继' } else { '与朋友的连接不稳定(原因尚未确认)' }
        }
        elseif ($facts.LatencyVerdict -eq 'FAIR') { $title = '与朋友的连接一般' }
        elseif ($facts.LossVerdict -eq 'MILD') { $title = '与朋友的连接良好, 但存在丢包' }
        else { $title = '与朋友的连接良好' }
    }
    Section "本次检测: $title  (NetCheck v$ScriptVersion)"
    Emit '【已测到】'
    if ($facts.TotalPings -gt 0) {
        if ($facts.AvgMs) { Emit "  • 到朋友 $($facts.PeerIp) : $($facts.TotalPings) 次探测, 平均 $($facts.AvgMs)ms (最小 $($facts.MinMs)ms / 最大 $($facts.MaxMs)ms), 丢包 $($facts.LossCount)" }
        else { Emit "  • 到朋友 $($facts.PeerIp) : $($facts.TotalPings) 次探测全部超时/不通" }
        if ($facts.LossVerdict -ne 'NONE') { Emit "  • 丢包评价: $($facts.LossVerdict) (丢包比高延迟更影响游戏手感)" }
    } else { Emit '  • 未找到在线的朋友(可加 -PeerIP 手动指定)' }
    if ($facts.RadminInstalled) { Emit '  • 蓝盾(Radmin VPN)已安装, 服务正常' } else { Emit '  • 本机未安装蓝盾(Radmin VPN)' }
    if ($facts.UplinkDesc) { Emit "  • 上网链路: $($facts.UplinkDesc)" }
    if ($facts.PublicIp) { Emit "  • 公网出口: $($facts.PublicIp) ($($facts.IspInfo))" }
    if ($facts.LocalV6) { Emit "  • 本机有公网IPv6地址, 外网IPv6连通: $($facts.V6ExtOk)" }
    if ($facts.StunOk -ge 2) { Emit "  • NAT实测: $($facts.NatReason)" }
    elseif ($facts.StunOk -eq 1) { Emit '  • NAT探测: 仅1个STUN服务器应答, 不足以下结论' }
    if ($facts.HasForeignConn) { Emit '  • 蓝盾当前连接着境外服务器(可能为中继)' }
    Emit '【尚未确定】'
    if ($facts.RelayVerdict -eq 'POOR_UNCONFIRMED') { Emit '  • 当前高延迟是否经过中继(缺少连接层面的证据)' }
    if ($facts.NatType -eq 'UNDETERMINED' -and $facts.StunFail -gt 0) { Emit "  • NAT类型($($facts.StunFail) 个探测点失败: 超时/不可达/数据异常, 见明细)" }
    if ($facts.PeerV6Ok -eq '') { Emit '  • 朋友一侧的IPv6条件(需要对方的报告对照)' }
    if ($facts.RelayVerdict -ne 'NONE' -and $facts.RelayVerdict -ne 'RELAY_SUSPECTED' -and $facts.LatencyVerdict -eq 'POOR') { Emit '  • 延迟高的原因归属(本机/对方/运营商/中继)' }
    Emit '【建议先做】'
    $i = 0
    foreach ($r in $recs) { $i++; Emit "  $i. $r" }
    if ($Fix -or $Undo) { Emit '  ⚠ 本次以修复/撤销模式运行, 修改记录见报告末尾。' }
    else { Emit '  本次检测没有修改任何系统设置。' }

    # ================= 详细报告 =================
    Section '详细报告'
    Emit '--- 蓝盾状态 ---'
    if ($svc) { if ($svc.Status -eq 'Running') { Ok "服务 RvControlSvc: Running" } else { Bad "服务: $($svc.Status)" } }
    else { Info '未安装蓝盾(跳过相关检查)' }
    if ($ad) {
        if ($ad.Status -eq 'Up') { Ok "虚拟网卡 $adapterName : Up" } else { Warn "虚拟网卡: $($ad.Status)" }
        if ($ip4) { Ok "我的虚拟IP: $($ip4.IPAddress)" }
    }
    if ($peers.Count -eq 0) { Info '未发现同伴(对方不在线或未加入同一网络)' }

    Emit '--- 延迟明细 ---'
    if ($pingResults.Count -eq 0) { Info '无可用探测目标' }
    foreach ($pr in $pingResults) {
        if ($pr.Avg) { Emit "  $($pr.Peer) : 平均 $($pr.Avg)ms / 最小 $($pr.Min)ms / 最大 $($pr.Max)ms / 丢包 $($pr.Loss)/$PingCount" }
        else { Emit "  $($pr.Peer) : 全部超时/不通 (丢包 $($pr.Loss)/$PingCount)" }
    }
    $lvText = @{ GOOD = '良好(<150ms)'; FAIR = '一般(150~300ms)'; POOR = '高延迟(>300ms)'; UNKNOWN = '无有效探测数据' }[$facts.LatencyVerdict]
    $lossText = @{ NONE = '无丢包'; MILD = '轻微丢包'; HEAVY = '丢包严重' }[$facts.LossVerdict]
    Emit "  延迟判定: $lvText | 丢包判定: $lossText ($($facts.LossCount)/$($facts.TotalPings))"
    if ($facts.RelayVerdict -eq 'RELAY_SUSPECTED') { Bad '高延迟 + 存在境外控制/中继连接 → 疑似中继(证据如下, 非100%确认)' }
    elseif ($facts.RelayVerdict -eq 'POOR_UNCONFIRMED') { Warn '高延迟但未抓到中继连接证据 → 不认定已走中继' }
    if ($facts.HasForeignConn) {
        Emit '  境外/其他连接:'
        $facts.ForeignConns | ForEach-Object { Emit "    $($_.Ip):$($_.Port) [$($_.Geo)]" }
    }

    Emit '--- 上网链路与NAT ---'
    if ($facts.UplinkDesc) { Info "上网网卡: $($facts.UplinkDesc)" }
    if ($localIp) { Info "本地IP: $localIp"; if ($facts.IsCgnat) { Bad '本地IP在 100.64.0.0/10 → 运营商CGNAT迹象' } }
    if ($facts.PublicIp) { Info "公网出口: $($facts.PublicIp) ($($facts.IspInfo))" } else { Warn '公网出口查询失败(重试2次仍失败, 可能被代理/防火墙拦截)' }
    if ($facts.IsMobileIsp) { Warn '运营商: 移动 → 社区反馈组网成功率较低' }
    if ($facts.Tether) { Warn '手机热点/USB共享: 双重NAT, 打洞难' }

    Emit '--- STUN 探测明细 ---'
    if ($stun.Count -eq 0) { Warn '无法创建UDP套接字, 探测未执行' }
    foreach ($s in $stun) {
        $map = if ($s.Status -eq 'OK') { " → $($s.MappedIP):$($s.MappedPort)" } else { '' }
        $stText = switch ($s.Status) { 'OK' { '成功' } 'TIMEOUT' { '超时(服务器无响应或UDP被限制)' } 'UNREACHABLE' { '不可达(被拒绝/路由不通)' } 'BAD_DATA' { '响应数据异常(无法解析)' } default { '程序错误' } }
        if ($s.Status -eq 'OK') { Ok "$($s.Server) $stText$map" } else { Warn "$($s.Server) $stText" }
    }
    Emit "  NAT判定: $($facts.NatType) - $($facts.NatReason)"

    Emit '--- IPv6 三项检测 ---'
    if ($facts.LocalV6) { $facts.V6Addrs | ForEach-Object { Ok "本机IPv6地址: $_" } } else { Warn '本机无公网IPv6地址' }
    if ($facts.V6ExtOk) { Ok 'IPv6外网连通(2400:3200::1 可达)' } else { Warn 'IPv6外网连通失败(有地址≠能出去)' }
    if ($PeerIPv6) { if ($facts.PeerV6Ok) { Ok "到朋友IPv6($PeerIPv6) 连通" } else { Bad "到朋友IPv6($PeerIPv6) 不通 → 不宣称双方可IPv6直连" } }
    else { Info '未提供 -PeerIPv6, 与朋友的IPv6连通性未检测' }

    Emit '--- 防火墙放行(本机) ---'
    $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '^(Radmin VPN|NetCheck-Radmin)' })
    if ($rules.Count -gt 0) {
        foreach ($ru in $rules) {
            if ($ru.Enabled -and $ru.Direction -eq 'Inbound' -and $ru.Action -eq 'Allow') { Ok "$($ru.DisplayName) 已放行" } else { Warn "$($ru.DisplayName) 状态异常" }
        }
    } elseif ($svc) { Warn '没有 Radmin 放行规则(可用 -Fix 创建, 可撤销)' }

    # ================= 修复 / 撤销 =================
    if ($Fix) { Invoke-Fix }
    if ($Undo) { Invoke-Undo }

    # ================= 对照模式 =================
    if ($Compare) { Invoke-Compare }

    # ================= 报告保存 =================
    if (-not $NoSave) {
        $outDir = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP }
        try {
            $txtPath = Join-Path $outDir "NetCheck-Report-$ts.txt"
            $jsonPath = Join-Path $outDir "NetCheck-Report-$ts.json"
            $sharePath = Join-Path $outDir "NetCheck-Share-$ts.json"
            ($script:Log -join "`r`n") | Out-File -FilePath $txtPath -Encoding UTF8
            $jsonObj = [ordered]@{ tool = 'NetCheck'; version = $ScriptVersion; generated = $facts.Generated; facts = $facts; recommendations = $recs }
            $jsonObj | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
            $share = [ordered]@{
                tool = 'NetCheck'; version = $ScriptVersion; generated = $facts.Generated
                peerIp = Mask-Ip $facts.PeerIp; avgMs = $facts.AvgMs; minMs = $facts.MinMs; maxMs = $facts.MaxMs
                loss = $facts.LossCount; totalPings = $facts.TotalPings; latencyVerdict = $facts.LatencyVerdict; lossVerdict = $facts.LossVerdict; relayVerdict = $facts.RelayVerdict
                natType = $facts.NatType; natReason = $facts.NatReason; stunOk = $facts.StunOk; stunFail = $facts.StunFail
                localV6 = $facts.LocalV6; v6ExtOk = $facts.V6ExtOk; peerV6Ok = $facts.PeerV6Ok
                isCgnat = $facts.IsCgnat; isMobileIsp = $facts.IsMobileIsp; tether = $facts.Tether
                uplinkType = if ($facts.UplinkDesc -match 'Wi-Fi|Wireless|WLAN') { 'wifi' } elseif ($facts.UplinkDesc -match 'Remote NDIS|WWAN|USB|Mobile') { 'tether' } elseif ($facts.UplinkDesc) { 'wired/other' } else { 'unknown' }
                recommendations = $recs
            }
            $share | ConvertTo-Json -Depth 5 | Out-File -FilePath $sharePath -Encoding UTF8
            Emit "报告已保存: $txtPath"
            Emit "分析用JSON: $jsonPath"
            Emit "脱敏分享JSON: $sharePath"
        } catch { Warn "报告保存失败: $($_.Exception.Message)" }
    }
    Emit ''
}

# ================= 修复(可撤销) =================
function Invoke-Fix {
    Section '修复模式'
    $isAdmin = $false
    try { $id = [Security.Principal.WindowsIdentity]::GetCurrent(); $pr = New-Object Security.Principal.WindowsPrincipal($id); $isAdmin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
    if (-not $isAdmin) { Bad '需要管理员权限(请右键以管理员身份运行)'; return }
    Emit '计划执行的修改(仅限以下内容):'
    Emit '  1. 将蓝盾虚拟网卡设为"专用(Private)"(不改你的实际上网网卡)'
    Emit '  2. 新建防火墙入站放行规则: NetCheck-Radmin-VPN (RvRvpnGui.exe)'
    Emit '  3. 新建防火墙入站放行规则: NetCheck-Radmin-Svc (RvControlSvc.exe)'
    if (-not $Force) {
        $ans = Read-Host '确认执行? (Y=执行, 其他=取消)'
        if ($ans -ne 'Y') { Emit '已取消, 未做任何修改'; return }
    }
    $outDir = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP }
    $statePath = Join-Path $outDir 'NetCheck.state.json'
    $oldChanges = @()
    if (Test-Path $statePath) {
        try { $old = Get-Content -Raw -Encoding UTF8 $statePath | ConvertFrom-Json; $oldChanges = @($old.Changes) } catch { Warn '旧状态文件无法读取, 将重建记录' }
    }
    $newChanges = @()
    $allOk = $true
    $prof = Get-NetConnectionProfile -InterfaceAlias $adapterName -ErrorAction SilentlyContinue
    $prevCat = if ($prof) { "$($prof.NetworkCategory)" } else { 'UNKNOWN' }
    if ($prof) {
        Set-NetConnectionProfile -InterfaceAlias $adapterName -NetworkCategory Private -ErrorAction SilentlyContinue
        $after = Get-NetConnectionProfile -InterfaceAlias $adapterName -ErrorAction SilentlyContinue
        if ($after -and $after.NetworkCategory -eq 'Private') { Ok "虚拟网卡已设为专用(原为 $prevCat)"; $newChanges += [pscustomobject]@{ Kind = 'Profile'; Target = $adapterName; Previous = $prevCat } }
        else { Bad '虚拟网卡设置失败或未生效'; $allOk = $false }
    } else { Warn '未找到蓝盾网卡的网络配置文件, 跳过此步' }
    foreach ($item in @(
        @{ Name = "${rulePrefix}VPN"; Path = 'C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe' },
        @{ Name = "${rulePrefix}Svc"; Path = 'C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe' })) {
        if (Test-Path $item.Path) {
            $exists = Get-NetFirewallRule -DisplayName $item.Name -ErrorAction SilentlyContinue
            if (-not $exists) {
                New-NetFirewallRule -DisplayName $item.Name -Direction Inbound -Action Allow -Program $item.Path -Profile Any -ErrorAction SilentlyContinue | Out-Null
                $verify = Get-NetFirewallRule -DisplayName $item.Name -ErrorAction SilentlyContinue
                if ($verify -and $verify.Enabled) { Ok "规则已创建并生效: $($item.Name)"; $newChanges += [pscustomobject]@{ Kind = 'Rule'; Target = $item.Name; Previous = '' } }
                else { Bad "规则创建失败: $($item.Name)"; $allOk = $false }
            } else { Info "规则已存在: $($item.Name) (未重复创建)" }
        } else { Bad "找不到程序: $($item.Path)"; $allOk = $false }
    }
    $state = @{ AppliedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Changes = @(Merge-ChangeList -Existing $oldChanges -New $newChanges) }
    try { $state | ConvertTo-Json -Depth 5 | Out-File -FilePath $statePath -Encoding UTF8; Info "改动已记录: $statePath (历史 $($oldChanges.Count) 项 + 本次 $($newChanges.Count) 项)" } catch { Warn '状态文件写入失败(撤销功能会受限)' }
    if ($allOk) { Ok '修复完成(以上各项均已复核生效)' } else { Bad '部分操作失败, 请查看上方每项的实际结果(不会假报完成)' }
}

function Invoke-Undo {
    Section '撤销模式(仅撤销本工具做过的修改)'
    $outDir = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP }
    $statePath = Join-Path $outDir 'NetCheck.state.json'
    if (-not (Test-Path $statePath)) { Warn '没有本工具的状态文件 → 没有可撤销的本工具改动(不会动其他规则)'; return }
    try { $state = Get-Content -Raw -Encoding UTF8 $statePath | ConvertFrom-Json } catch { Bad "状态文件损坏: $($_.Exception.Message)"; return }
    $flat = @(Expand-Changes -Items $state.Changes)
    if ($flat.Count -eq 0) { Warn '状态文件里没有可撤销的改动'; Remove-Item $statePath -Force -ErrorAction SilentlyContinue; return }
    $allOk = $true
    foreach ($c in $flat) {
        $kind = "$($c.Kind)"; $target = "$($c.Target)"; $prev = "$($c.Previous)"
        if ($kind -eq 'Rule') {
            $ru = Get-NetFirewallRule -DisplayName $target -ErrorAction SilentlyContinue
            if ($ru) { $ru | Remove-NetFirewallRule -ErrorAction SilentlyContinue; $chk = Get-NetFirewallRule -DisplayName $target -ErrorAction SilentlyContinue; if (-not $chk) { Ok "已删除规则: $target" } else { Bad "规则删除失败: $target"; $allOk = $false } }
            else { Info "规则不存在(可能已手动删除): $target" }
        }
        elseif ($kind -eq 'Profile' -and $prev -ne 'UNKNOWN') {
            Set-NetConnectionProfile -InterfaceAlias $target -NetworkCategory $prev -ErrorAction SilentlyContinue
            $after = Get-NetConnectionProfile -InterfaceAlias $target -ErrorAction SilentlyContinue
            if ($after -and $after.NetworkCategory -eq $prev) { Ok "已恢复网卡类型: $target → $prev" } else { Bad "网卡类型恢复失败: $target"; $allOk = $false }
        }
    }
    if ($allOk) { Remove-Item $statePath -Force -ErrorAction SilentlyContinue; Ok '撤销完成, 状态文件已清除' } else { Bad '部分撤销失败, 请查看上方明细' }
}

function Invoke-Compare {
    Section '两端报告对照'
    if (-not (Test-Path $Compare)) { Bad "找不到对照文件: $Compare"; return }
    try { $o = Get-Content -Raw -Encoding UTF8 $Compare | ConvertFrom-Json } catch { Bad "对照文件解析失败: $($_.Exception.Message)"; return }
    if ($o.tool -ne 'NetCheck') { Warn '对照文件不是 NetCheck 报告(仅支持同工具JSON)' }
    $osrc = ConvertTo-CompareSource -Obj $o
    $oAvg = Get-Val $osrc 'avgMs'; if ($oAvg -ne '数据缺失') { $oAvg = "$oAvg ms" }
    $oLoss = Get-Val $osrc 'loss'; $oTot = Get-Val $osrc 'totalPings'
    $oLossStr = if ($oLoss -ne '数据缺失' -and $oTot -ne '数据缺失') { "$oLoss/$oTot" } else { '数据缺失' }
    Emit '  项目                 本机                       对方'
    $rows = @()
    $rows += [pscustomobject]@{ K = '工具版本'; A = $facts.Version; B = Get-Val $o 'version' }
    $rows += [pscustomobject]@{ K = '生成时间'; A = $facts.Generated; B = Get-Val $o 'generated' }
    $rows += [pscustomobject]@{ K = '到对方延迟(平均)'; A = if ($facts.AvgMs) { "$($facts.AvgMs) ms" } else { '不可达' }; B = $oAvg }
    $rows += [pscustomobject]@{ K = '丢包'; A = "$($facts.LossCount)/$($facts.TotalPings)"; B = $oLossStr }
    $rows += [pscustomobject]@{ K = '丢包判定'; A = $facts.LossVerdict; B = Get-Val $osrc 'lossVerdict' }
    $rows += [pscustomobject]@{ K = '本机IPv6地址'; A = "$($facts.LocalV6)"; B = Get-Val $osrc 'localV6' }
    $rows += [pscustomobject]@{ K = 'IPv6外网连通'; A = "$($facts.V6ExtOk)"; B = Get-Val $osrc 'v6ExtOk' }
    $rows += [pscustomobject]@{ K = 'NAT类型'; A = $facts.NatType; B = Get-Val $osrc 'natType' }
    $rows += [pscustomobject]@{ K = 'CGNAT迹象'; A = "$($facts.IsCgnat)"; B = Get-Val $osrc 'isCgnat' }
    $rows += [pscustomobject]@{ K = '移动运营商'; A = "$($facts.IsMobileIsp)"; B = Get-Val $osrc 'isMobileIsp' }
    $rows += [pscustomobject]@{ K = '手机热点/共享'; A = "$($facts.Tether)"; B = Get-Val $osrc 'tether' }
    $rows += [pscustomobject]@{ K = '中继判定'; A = $facts.RelayVerdict; B = Get-Val $osrc 'relayVerdict' }
    foreach ($rw in $rows) { Emit ("  {0,-20} {1,-26} {2}" -f $rw.K, $rw.A, $rw.B) }
    Emit '  对照提示:'
    $oVer = Get-Val $o 'version'
    if ($oVer -ne '数据缺失' -and $oVer -ne $facts.Version) { Warn '双方工具版本不一致, 请都升级到相同版本后再对照' }
    $oAvgN = Get-Val $osrc 'avgMs'
    if ($facts.AvgMs -and $oAvgN -ne '数据缺失' -and [math]::Abs([double]$facts.AvgMs - [double]$oAvgN) -gt 100) { Warn '双向延迟差异大 → 可能只有单方向异常(某一侧上行/打洞问题)' }
    $oV6 = Get-Val $osrc 'localV6'
    if ($oV6 -ne '数据缺失' -and $facts.LocalV6 -ne [bool]::Parse($oV6)) { Info '双方IPv6条件不一致 → IPv6直连可行性以两侧都满足为前提' }
    $oNat = Get-Val $osrc 'natType'
    if ($facts.NatType -eq 'PORT_VARYING' -or $oNat -eq 'PORT_VARYING') { Warn '至少一侧为对称型NAT行为 → 直连打洞成功率低, 考虑中转方案' }
}

if ($MyInvocation.InvocationName -ne '.') { Main }






