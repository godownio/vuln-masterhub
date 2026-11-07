---
id: defense-forensics-rdp-source-gateway-snat
title: RDP 登录来源显示为路由器网关：DNAT 叠加 SNAT 掩盖真实来源
type: scenario
domain: defense
path: defense/forensics
technique: nat-source-address-artifact
aliases:
- RDP 来源网关
- 端口映射 SNAT
- 源地址转换取证
- 登录来源 192.168.1.254
tags:
- rdp
- nat
- snat
- port-forwarding
- forensics
- logon-type-10
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:20:26+08:00'
  notes: 已对照原文与9张图核对：DNAT 叠加 SNAT 使 RDP 来源显示为路由器内网地址 192.168.1.254、4624 LogonType=10 记录、路由器无连接日志导致真实公网源不可恢复均一致；RouterOS 配置未实测
---

## 一句话结论

当边界路由器把公网 3389 端口映射到内网主机，并对入站连接同时做源地址转换时，Windows 安全日志中的 RDP 登录来源会显示为路由器内网接口地址，而不是攻击者真实公网 IP；若不识别这一现象，溯源方向会被直接带偏。

## 原理

- **DNAT 只改目的地址**：路由器把 `公网IP:3389` 的目的地址改写为 `内网主机:3389`，使外部连接能够到达内网 RDP 服务。
- **SNAT/MASQUERADE 改源地址**：为保证回程流量仍经过路由器返回公网，许多设备（RouterOS 等尤其常见）在端口映射时同时把源地址改写为路由器自身的内网接口地址（如 192.168.1.254）。因此内网主机看到的 TCP 对端就是网关。
- **日志记录的是 TCP 对端**：Windows 4624 事件中的 `IpAddress` 来自网络层连接信息，于是 LogonType=10（RemoteInteractive）的登录来源显示为网关地址；同一来源上的多台主机可能都出现“来自网关”的登录。
- **证据随会话消失**：家用/企业路由器通常不保存 NAT 连接日志，转换表随会话老化或设备重启销毁，真实公网源地址因此不可恢复。攻击者未必理解该原理，但配置客观上替其完成了来源隐藏。

## 触发条件

- 边界设备存在端口映射（DNAT）到内网主机的 RDP；
- 设备对映射流量执行 SNAT/MASQUERADE，或使用“回环/hairpin NAT”配置；
- 目标主机直接记录网络对端地址，未部署能记录原始来源的代理/堡垒机；
- 边界设备未开启连接日志、NetFlow 或日志外发。

## 利用步骤

（此卡描述的是取证判读与攻击者视角的客观效果，不提供攻击操作。）

1. 在受害主机筛选 4624 事件，关注 `LogonType=10` 且 `IpAddress` 为内网网关地址的记录；
2. 确认该地址是否是路由器/防火墙接口，而非真实终端；
3. 检查边界设备的 NAT 规则与 SNAT 策略，判断来源是否被改写；
4. 尝试从边界设备、上游运营商、其他同网段主机补齐同一时间窗的连接记录；
5. 若真实来源已丢失，转向资产测绘历史、暴露面变更记录和其他主机日志建立时间线，而不是继续在网关地址上追查。

## PoC

```powershell
# 提取 RDP 交互式登录事件（4624, LogonType=10）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Properties[8].Value -eq 10 } |
  Select-Object TimeCreated,
    @{n='User';e={$_.Properties[5].Value}},
    @{n='SourceIP';e={$_.Properties[18].Value}},
    @{n='LogonType';e={$_.Properties[8].Value}}
```

```text
# RouterOS 侧核对是否存在 3389 映射及 src-nat/masquerade 规则
/ip firewall nat print
```

```text
# 判读要点
4624 LogonType=10, IpAddress=192.168.1.254  -> 可能是网关 SNAT，而非攻击者终端
```

## 变体与关联

- 变体：反向代理/CDN 使 Web 日志只看到代理 IP；负载均衡器未传 `X-Forwarded-For`；云 NAT 网关、VPN 集中器同样改写源地址。
- 关联：[[pentest-initial-access-exposed-rdp-nat-guest]]（同一映射既暴露入口又掩盖来源）；[[defense-incident-response-ransomware-pre-encryption-cleanup]]（入口得手后的清理与加密行为）。

## 检测与防御

- **配置侧**：梳理全部 DNAT 规则及其 SNAT 行为，记录映射的创建人、目的、有效期；对必须保留的映射启用连接日志。
- **日志侧**：边界设备日志、NetFlow/sFlow 外发到独立日志平台；Windows 4624/4625 实时转发，避免本机日志被清。
- **取证侧**：看到“内网网关作为 RDP 来源”时先怀疑 NAT，而不是直接认定网关被入侵；用多主机同源登录、NAT 规则时间、资产测绘历史交叉验证。
- **架构侧**：远程运维改用堡垒机/VPN，由堡垒机记录真实用户与来源，减少对边界 NAT 日志的依赖。
- **注意**：本卡不声称能恢复已被 NAT 覆盖的真实公网 IP；多数情况下只能证明“来源被改写”，不能还原攻击者地址。
