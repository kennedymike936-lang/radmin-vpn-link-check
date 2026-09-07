# Radmin VPN (蓝盾) 联机体检工具 + 组网方案推荐

一套帮你诊断"联机一格信号"问题的开源小工具：
检测蓝盾（Radmin VPN）链路质量，并进一步**体检你的整个网络环境（NAT/CGNAT/IPv6）**，自动推荐适合你的组网方案。

> 蓝盾 = Radmin VPN：Radmin 的图标是蓝色盾牌，中文社区习惯叫它"蓝盾"，常用于 Minecraft 等游戏的虚拟局域网联机。

## 为什么会有"一格信号"？

Radmin VPN 是 P2P 虚拟局域网：理想情况下双方**直连**（国内跨省通常 30~150ms）；
但如果 NAT 打洞失败（手机热点/USB 共享双重 NAT、运营商大内网、跨运营商、防火墙拦入站等），
Radmin 会自动把流量**甩到官方中继服务器**兜底——而中继节点常在**境外（如欧洲 OVH）**，
延迟飙到 500ms~2000ms+，游戏里就显示"一格信号"。

实测数据（湖南↔浙江）：

| 场景 | 延迟 |
|---|---|
| 蓝盾直连成功 | 平均 59ms ✅ |
| 打洞失败走欧洲中继 | 平均 465~1100ms，最大 2013ms ❌ |
| 双方 IPv6 直连（不经组网工具） | 145ms ✅ |
| 防火墙放行+双方重启后 | 从 512ms 拉回 66ms（会反复横跳） |

## 工具一：NetCheck（联机方案体检+推荐）【推荐】

`NetCheck.ps1` / `NetCheck.bat` —— 双击即用，输出 6 段报告：

1. **蓝盾现状**：服务/网卡/虚拟 IP + 到同伴的实测延迟
2. **上网链路与 NAT 环境**：识别手机共享/移动网卡、CGNAT（100.64.0.0/10）、运营商风险（移动宽带是组网重灾区）
3. **STUN NAT 类型探测**：向公共 STUN 服务器询问"你看到的我的出口"，判断锥形/对称型 NAT、多层 NAT/CGNAT
4. **IPv6 检测**：有无公网 IPv6 + 连通性（IPv6 是国内组网最稳的直连通路）
5. **防火墙放行检查**：蓝盾入站规则是否就位
6. **推荐方案排序**：根据检测结果自动排序（EasyTier / ZeroTier / 蓝盾 / UU局域网）

```powershell
# 普通体检(无需管理员): 双击 NetCheck.bat
# 修复蓝盾防火墙(需管理员):
pwsh -NoProfile -ExecutionPolicy Bypass -File NetCheck.ps1 -Fix
```

参数：`-PeerIP '26.x.x.x'`（手动指定朋友IP）、`-PingCount 10`、`-SkipGeo`

### 判定标准

| 平均延迟 | 判定 |
|---|---|
| < 150ms | 直连良好 ✅ |
| 150 ~ 300ms | 一般，可玩但可能略卡 |
| > 300ms | 疑似境外中继 ⚠️ |

### 方案选择速查

- 有可用 IPv6 → **EasyTier / ZeroTier**（走 IPv6 直连，成功率最高）
- 移动宽带 / CGNAT / 对称型 NAT → **EasyTier（公共节点/自建）或 UU局域网**（中转兜底）
- 电信联通锥形 NAT → **蓝盾 / ZeroTier** 都有机会直连
- 不想折腾 → **网易UU加速器「局域网联机」**，免费零配置

## 工具二：RadminCheck（蓝盾专用体检）

老版本工具，只针对蓝盾做链路体检（蓝盾状态/同伴发现/延迟/中继服务器定位/防火墙）。

```powershell
# 双击 RadminCheck.bat
pwsh -NoProfile -ExecutionPolicy Bypass -File RadminCheck.ps1 -Fix   # 修复模式
```

## 文档：组网方案横评

`net-solutions-comparison.md`：蓝盾 / ZeroTier / Tailscale / EasyTier / UU局域网 五方案对比、
选择流程图、实测数据、评论区常见问题解答（同步自 B 站专栏初稿）。

## 兼容性

- Windows 10/11，PowerShell 5.1 或 7+
- 体检为只读操作（无需管理员）；`-Fix` 模式需要管理员
- STUN/IP 归属查询为尽力而为：网络受限时自动跳过，不影响主要结论

## 免责声明

本工具仅做网络诊断与信息收集，不修改游戏文件，不涉及账号数据。
