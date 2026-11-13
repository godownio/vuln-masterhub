---
id: defense-detection-kimsuky-powershell-backdoor-fixed-header-heartbeat
title: Kimsuky PowerShell 后门流量检测：42 字节首包固定前缀 01042400000020000000 + 单字节 00 心跳 + 4 字节长度帧
type: scenario
domain: defense
path: defense/detection
technique: kimsuky-powershell-backdoor-fixed-header-heartbeat-detection
aliases:
- Kimsuky 后门流量特征
- PowerShell 后门首包 42 字节
- 19228259350740992
- 单字节 00 心跳
- raw TCP RC4 后门检测
- V-Manager 流量
tags:
- kimsuky
- apt
- detection
- network-traffic
- ids
- suricata
- wireshark
- powershell
- backdoor
- heartbeat
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483-fix
  verified_at: '2026-11-10T21:09:47+08:00'
  notes: V483 指出 Wireshark 过滤 tcp[0:10] 取的是 TCP 头而非载荷。已改为 tcp.len == 42 && tcp.payload[0:10] == 01:04:24:00:00:00:20:00:00:00。Suricata 规则与其余特征核对不变。
---

## 一句话结论

Kimsuky 的 PowerShell socket 后门上线首包固定为 42 字节，前 10 字节恒为 `01 04 24 00 00 00 20 00 00 00`（opcode 0x0401、载荷长度 0x24、uniqueId 长度 0x20），后跟 32 字节 MD5 十六进制串；连接维持期间每约 1 秒发送单字节 `00` 心跳，指令帧为 4 字节长度 + RC4 载荷。这三个明文特征可用于 IDS/Suricata 规则、Wireshark 过滤与流量研判。

## 原理

- **首包固定前缀**：协议版本/登录 opcode 固定为 0x0401，载荷长度恒为 0x24（2 字节 opcode + 4 字节 uniqueId 长度 + 32 字节 uniqueId=36=0x24），uniqueId 长度恒为 0x20；因此首包总长 42 字节且前 10 字节完全固定，即使后续载荷被 RC4 加密也不影响该特征。
- **心跳单字节**：后门接收循环用 `GetTickCount` 判断距上次发送超过约 1000ms 就发送 1 字节 `0x00`；没有长度头、没有 opcode，是区别于正常应用流量的强特征。
- **长度帧**：指令交互数据为 `4 字节载荷长度 + 载荷`，长度值可直接用于识别“短长度 + 后续密文”的 C2 交互；RC4 加密后的载荷无魔数，但长度字段与心跳/首包组合足以区分。
- **检测组合**：单看 42 字节首包或单字节 00 都可能误报（例如其他二进制协议），但“同一五元组上 42 字节固定头首包 + 周期性单字节 00 + 后续 4 字节长度帧”的组合置信度很高；再结合进程侧 PowerShell 外联、`Invoke-Expression`/base64 行为可进一步确认。
- **局限性**：样本可修改默认端口、uniqueId 长度或心跳间隔；流量加密后无法直接看指令内容，需结合 uniqueId=MD5(MAC+IP) 的密钥派生离线解密。

## 触发条件

- 网络流量可见（边界/主机 IDS、pcap、全流量）。
- 后门与 C2 的通信未被 TLS/隧道封装（该样本为裸 TCP）。
- 已知/可猜测默认端口 8888 或对全部 TCP 做特征匹配。
- 有 PowerShell 进程网络行为遥测可做关联。

## 利用步骤

1. 在流量中筛选 TCP 首包长度为 42 字节、前 10 字节为 `01 04 24 00 00 00 20 00 00 00` 的会话。
2. 提取首包中的 32 字节 uniqueId（MD5 十六进制串），记录五元组与时间。
3. 观察同一会话是否出现周期性单字节 `00` 心跳与 `4 字节长度 + 密文` 的指令帧。
4. 用 uniqueId 派生 `_r`/`_s` 两个 RC4 流，离线解密后续载荷，确认指令（磁盘/目录/执行/下载等）。
5. 关联主机侧 PowerShell 进程、命令行、脚本块日志与文件外传（POST `show.php`）告警，完成定性。
6. 封禁 C2、提取 IOC，并用解密结果评估数据外传范围。

## PoC

Wireshark 过滤：

```text
tcp.len == 42 && tcp.payload[0:10] == 01:04:24:00:00:00:20:00:00:00
```

Suricata 规则骨架（方向为后门→C2，端口按实际修改）：

```text
alert tcp any any -> any 8888 (msg:"Kimsuky PowerShell backdoor first packet"; \
  content:"|01 04 24 00 00 00 20 00 00 00|"; depth:10; dsize:42; \
  flow:to_server,established; sid:1000010; rev:1;)
```

心跳/帧组合可用同一流上的 `dsize:1; content:"|00|";` 与长度字段做关联告警。

## 变体与关联

- 变体：样本若改端口/心跳间隔，首包固定前缀仍可能保留；可放宽为“42 字节首包 + 固定 10 字节头”，再人工确认。
- 变体：同类 raw TCP RC4 后门（如 CyberGate/DinodasRAT）有各自长度帧/心跳特征，检测思路可复用。
- 关联：协议结构与密钥派生见 [[pentest-c2-kimsuky-powershell-backdoor-rc4-c2-protocol-reimplementation]]；其他 RAT 心跳检测案例见 [[defense-detection-asyncrat-ping-heartbeat-replay-verify]]。
- 边界：加密流量无法仅凭特征读指令；若攻击者加 TLS/域名前置，需 JA3/证书与主机侧行为配合。

## 检测与防御

- 检测：按上述首包/心跳/长度帧规则布控边界与主机 IDS；对 PowerShell 外联 8888 等非常规端口告警。
- 防御：限制 PowerShell 脚本执行与出站连接，启用脚本块日志/AMSI；封禁已知 C2 与 IOC。
- 处置：隔离主机、提取内存与脚本样本、用 uniqueId 解密历史流量评估影响。
