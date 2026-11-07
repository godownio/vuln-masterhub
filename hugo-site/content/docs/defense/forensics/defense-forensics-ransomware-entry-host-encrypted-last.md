---
id: defense-forensics-ransomware-entry-host-encrypted-last
title: 勒索事件中入口跳板机常最后加密：用加密时间反推入口
type: scenario
domain: defense
path: defense/forensics
technique: entry-host-last-encrypted
tags:
- ransomware
- forensics
- incident-response
- lateral-movement
- timeline
- rdp
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-H
  verified_at: '2026-11-04T19:41:30+08:00'
  notes: 来源 93088；已对照原文核对；A 主机 05:29 先加密、B 入口跳板机 05:32 最后加密、B 主机 RDP 来源显示网关 192.168.1.254、出口 IP 测绘记录 2026-08-11 均一致；该规律原文自述为个案经验，卡中已保留 medium 与交叉验证要求。
url: /docs/defense/forensics/defense-forensics-ransomware-entry-host-encrypted-last/
draft: false
kb_aliases:
- 入口机最后加密
- 跳板机最后加密
- 加密顺序反推入口
- LockBit 入口定位
---

## 一句话结论

勒索团伙需要保留进出内网的通道，常见做法是先加密内网其他主机、最后才加密作为入口的跳板机；因此当多台主机被加密且日志被清时，“最后开始加密的那台”是入口机的高价值候选，可据此反查 RDP 登录、工具包和暴露面。

## 原理

- 攻击者通常通过一台对公网暴露或可远程登录的主机进入内网（RDP、VPN、映射端口、穿透工具）。
- 这台主机既是入口也是通道：过早加密会切断后续横向与回连能力，所以攻击者倾向先完成内网其他目标的加密，确认无更多价值后再加密入口机并离场。
- 因此多主机加密时间排序中，最后加密的主机往往与入口重合；它通常还保留完整工具包（扫描器、密码抓取、清日志脚本、加密器）和远程登录记录。
- 该规律不是绝对的：攻击者可能使用独立 C2、先加密入口、或多入口并行；只能作为候选假设，必须用其他证据交叉验证。

## 触发条件

- 同一事件中多台 Windows 主机被同一家族加密；
- 能获取各主机首批文件被加密的时间（文件 mtime、USN、备份快照、EDR 时间线）；
- 事件日志可能被清，但仍有 Amcache/Prefetch/EDR/文件时间等旁证；
- 攻击者使用入口跳板机横向，而非纯外部无落地攻击。

## 利用步骤

1. 收集各主机最早一批加密文件的修改时间，按时间排序；
2. 标出最后加密的主机，作为入口候选；
3. 在该主机查 RDP 4624 LogonType=10/3、来源 IP、登录用户与时间；
4. 检查桌面/临时目录是否有成套工具包（扫描器、netpass、清日志脚本、加密器）；
5. 用 Amcache/Prefetch 找工具首次执行时间，与加密时间对齐；
6. 查出口 IP 的资产测绘历史，确认 3389/445/Web 等端口是否曾暴露；
7. 若入口候选被证伪，回到时间线寻找其他跳板或多入口。

## PoC

```powershell
# 1) 各主机首批加密时间（示例：按 5 分钟窗口统计改名文件）
Get-ChildItem C:\ -Recurse -File -ErrorAction SilentlyContinue |
  Group-Object { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') } |
  Sort-Object Count -Descending | Select-Object -First 10

# 2) 入口候选上的 RDP 登录
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Properties[8].Value -in 3,10 } |
  Select-Object TimeCreated,
    @{n='User';e={$_.Properties[5].Value}},
    @{n='SourceIP';e={$_.Properties[18].Value}},
    @{n='LogonType';e={$_.Properties[8].Value}}

# 3) 工具执行痕迹（Amcache 需解析 hive 或使用取证工具）
```

```text
# 判读
最后加密主机 + 桌面成套工具 + RDP 登录 + 出口端口历史暴露
  -> 入口跳板机假设成立概率高
```

## 变体与关联

- 变体：攻击者先加密入口再横向（规律失效）；使用独立 C2 不依赖入口机；多入口/供应链投递；虚拟机快照或备份恢复改变 mtime。
- 关联：[[pentest-initial-access-exposed-rdp-nat-guest]]（入口方式）；[[defense-forensics-rdp-source-gateway-snat]]（入口登录来源被 NAT 改写）；[[defense-forensics-multisource-timeline-log-clear]]（日志被清后的时间线重建）；[[defense-incident-response-ransomware-pre-encryption-cleanup]]（加密前置行为）。
- 不确定点：该规律来自单起案例与常见勒索作战习惯，并非普适定律；confidence 定为 medium，必须与其他证据交叉验证。

## 检测与防御

- 检测：多主机加密时间序列；入口候选上的 RDP/远程登录与工具执行；出口 IP 的暴露面历史。
- 响应：优先保全最后加密主机的内存、磁盘、日志与工具包；不要急着重装，入口证据常在这台机器上。
- 防御：远程运维走 VPN/堡垒机并留痕；管理端口不暴露公网；网络分段，避免一台跳板机沦陷导致全网可加密；日志实时外发，弥补本机日志被清。
- 认知：加密顺序只是线索，不是结论；能证明的写死，不能证明的留白。
