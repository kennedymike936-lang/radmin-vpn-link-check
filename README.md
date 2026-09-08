# NetCheck — 联机体检工具 v0.2 (蓝盾/Radmin VPN 玩家向)

一套帮你诊断"联机一格信号"问题的开源小工具：检测蓝盾（Radmin VPN）链路 + 体检整个网络环境（NAT/CGNAT/IPv6），
输出**"现在怎样 → 依据是什么 → 下一步做什么"**的报告。默认只读，不修改系统设置。

> 蓝盾 = Radmin VPN：Radmin 图标是蓝色盾牌，中文社区习惯叫"蓝盾"，常用于 Minecraft 等游戏联机。

## 为什么会有"一格信号"？

Radmin 是 P2P 虚拟局域网：双方能直连时国内跨省通常 30~150ms；一旦 NAT 打洞失败（手机热点/USB 共享双重 NAT、
运营商大内网、跨运营商、防火墙拦入站、代理/TUN 劫持等），流量会被甩到官方中继服务器兜底——中继常在**境外（欧洲 OVH）**，
延迟 500~2000ms+，游戏里就是"一格信号"。

实测数据（湖南电信 ↔ 浙江移动）：直连成功 59ms ✅；打洞失败走欧洲中继 465~1100ms（最大 2013ms）❌；
双方 IPv6 直连 145ms ✅；防火墙放行+双方重启后从 512ms 拉回 66ms（但会反复横跳）。

## 快速开始

```powershell
# 普通体检(无需管理员): 双击 NetCheck.bat → 输出摘要式报告 + 自动保存三份文件
# 手动指定朋友IP / 朋友IPv6:
pwsh -File NetCheck.ps1 -PeerIP 26.x.x.x -PeerIPv6 2409:xxxx
# 两端报告对照(双方各跑一次后):
pwsh -File NetCheck.ps1 -Compare 朋友的NetCheck-Report-*.json
# 修复模式(需管理员; 先预览再执行; -Force 跳过确认):
pwsh -File NetCheck.ps1 -Fix
# 撤销本工具做过的修改:
pwsh -File NetCheck.ps1 -Undo
```

## 报告文件（自动保存）

| 文件 | 用途 |
|---|---|
| `NetCheck-Report-*.txt` | 便于阅读的完整报告 |
| `NetCheck-Report-*.json` | 便于分析的完整数据 |
| `NetCheck-Share-*.json` | **脱敏分享版**（隐藏完整 IP/设备名，保留判定与测量数据）→ 发朋友/评论区用这个 |

## 检测与判定原则（可靠性优先）

- **NAT 探测**：同一本地 UDP 端点访问多个 STUN 服务器，只报告实测映射行为；证据不足就明确说"未确定"，不猜测
- **中继判定**："高延迟"与"疑似中继"分开——高延迟 + 境外连接证据 = 疑似中继；无证据 = 原因未确认
- **IPv6 三项**：本机地址 / 外网连通 / 与朋友连通（-PeerIPv6），不做"双方可直连"的无据推断
- **失败分类**：超时 / 不可达 / 响应数据异常 / 程序错误，不统一甩锅"网络受限"
- **修复可撤销**：-Fix 先预览、只改蓝盾虚拟网卡、规则带 `NetCheck-Radmin-` 前缀并记录状态文件；-Undo 只撤销本工具的改动，逐项复核后才报告结果

## 兼容性

- Windows 10/11，PowerShell 5.1 / 7+
- 只读体检无需管理员；-Fix / -Undo 需管理员
- 测试：`pwsh -File tests\NetCheck.Tests.ps1`（纯函数单元测试，无需 Pester）

## 项目文件

| 文件 | 说明 |
|---|---|
| `NetCheck.ps1` / `NetCheck.bat` | 主工具（双击即用） |
| `RadminCheck.ps1` / `RadminCheck.bat` | v0.1 蓝盾专用体检（保留） |
| `net-solutions-comparison.md` | 五方案横评：蓝盾/ZeroTier/Tailscale/EasyTier/UU局域网 |
| `tests/NetCheck.Tests.ps1` | 单元测试 |
| `CHANGELOG.md` | 版本记录 |
| `FEEDBACK.md` | 反馈模板 + 案例记录（含 B 站社区案例） |
| `README_EN.md` | English intro |
| `LICENSE` | MIT |

## 反馈与社区

- 反馈模板与案例记录见 [FEEDBACK.md](FEEDBACK.md)
- 社区讨论帖：https://www.bilibili.com/opus/1244434707826868232
- 第三方方案（UU局域网/EasyTier 等）免费政策以官方页面为准，核实于 2026-09

## 免责声明

本工具仅做网络诊断与信息收集；`-Fix` 仅修改蓝盾虚拟网卡类型与带前缀的防火墙规则（可撤销）。不修改游戏文件、不涉及账号数据。
