---
id: defense-forensics-mssql-tds-xpcmdshell-traffic-replay
title: MSSQL 1433 TDS 流量复盘：从 SQL batch 还原 xp_cmdshell 建号、加管理员与开 RDP 命令
type: scenario
domain: defense
path: defense/forensics
technique: mssql-tds-xpcmdshell-traffic-replay
tags:
- forensics
- traffic-analysis
- mssql
- tds
- xp-cmdshell
- rdp
- incident-response
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-07T23:22:38+08:00'
  notes: 已对照原文核对：tcp.port==1433过滤TDS、Pre-Login/TLS/SQL batch、Query字段明文的SERVERPROPERTY与sys.databases查询、xp_cmdshell的reg add fDenyTSConnections/net user/net localgroup命令、响应命令成功完成、3389 T.125 attachUserConfirm rt-successful均与img29-41一致；sa口令cisp-pte@sa来自web.config.bak泄露。未复跑原文pcap。
url: /docs/defense/forensics/defense-forensics-mssql-tds-xpcmdshell-traffic-replay/
draft: false
kb_aliases:
- TDS 流量分析
- 1433 流量排查
- SQL batch 解码
- xp_cmdshell 流量
- MSSQL 入侵溯源
- TDS Query Packet
---

## 一句话结论

拿到包含数据库阶段的 pcap 后，用 `tcp.port == 1433` 过滤并在 Wireshark 中按 TDS 协议解析，可以看到 `Pre-Login → TLS 握手 → SQL batch` 的登录过程；每个 SQL batch 的 `Query` 字段就是明文 SQL，能直接读出攻击者执行的 `SELECT SERVERPROPERTY`、`sys.databases` 以及 `EXEC master..xp_cmdshell 'net user ...'`、`net localgroup administrators ...`、`reg add ... fDenyTSConnections ...` 等命令，TDS 响应还会回显“命令成功完成。”等输出；再结合 `tcp.port == 3389` 的 T.125 `attachUserConfirm result: rt-successful` 可确认随后的 RDP 登录。

## 原理

- TDS（Tabular Data Stream）是 SQL Server 客户端与服务器之间的应用层协议，承载 Pre-Login/Login7 登录、TLS/SSPI 认证、SQL batch/RPC 调用与结果集。Wireshark 内置 TDS dissector，能识别包类型并把查询文本显示在 `Query` 字段。
- SQL Server 登录阶段先发 `TDS Pre-Login`，服务器返回 `97 Response`，随后进入 TLS 握手（Client Hello、Server Hello、Certificate、Key Exchange、Application Data），认证完成后客户端以 `SQL batch` 发送查询。
- `xp_cmdshell` 是 SQL Server 的扩展存储过程，以 SQL Server 服务账户创建 `cmd.exe` 子进程执行命令，调用形如 `EXEC master..xp_cmdshell '<cmd>'`。该语句经 TDS SQL batch 传输，在未强制加密的链路上是明文。
- 典型后续命令：`net user <name> <password> /add` 建本地用户、`net localgroup administrators <name> /add` 加入管理员组、`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f` 开启远程桌面；三者组合完成“数据库命令执行 → 本地管理员 → RDP 入口”。
- 流量取证的价值：无需数据库日志、ERRORLOG 或账号口令，仅凭 pcap 就能离线还原攻击者执行的 SQL 语句、执行顺序与部分返回输出，并与 HTTP webshell 阶段和 RDP 阶段对齐时间线。
- 前提是 TDS 未被强制加密；若服务器要求加密或 TLS 会话可解密，则需要相应密钥才能看到 SQL batch 明文。

## 触发条件

- 抓包点覆盖攻击者到 SQL Server 的 1433 流量；链路未强制 TLS，或已具备 TLS 解密条件。
- 使用 Wireshark/tshark，TDS dissector 默认启用即可。
- 已确认或怀疑数据库凭据泄露/复用，需要还原攻击者在数据库侧的动作与命令。

## 利用步骤

1. 用 `tcp.port == 1433` 过滤；先看到 TCP 三次握手、`TDS Pre-Login`、`97 Response`，再到 TLS 握手与 `TDS SQL batch`。
2. 逐个展开 `TDS Query Packet`/`SQL batch`，读取 `Query` 字段；按时间顺序记录每条 SQL。
3. 识别信息收集查询：`SELECT SERVERPROPERTY('ProductLevel') AS ProductLevel, SERVERPROPERTY('Edition') AS Edition, ...`；`SELECT d.name db_name, d.database_id, d.state, ... FROM sys.databases d`。
4. 识别命令执行：`use master; exec master..xp_cmdshell "net user ... /add"`、`... "net localgroup administrators ... /add"`、`... "reg add ... fDenyTSConnections ... /d 0 /f"`。
5. 查看对应 TDS 响应包中的 Token/结果字段，例如中文“命令成功完成。”、错误消息，确认命令是否成功。
6. 与 HTTP 阶段关联：webshell 读取 `web.config` 等配置得到的数据库账号，与 1433 登录时间、来源 IP 对应；确认登录使用的是 sa 或其他 sysadmin 账号。
7. 过滤 `tcp.port == 3389`，找到 RDP 协商与 `T.125 DomainMCSPDU attachUserRequest/attachUserConfirm`，`result: rt-successful` 表示认证成功；把 3389 登录时间与新建账号、开 RDP 命令时间对齐。
8. 输出时间线：webshell 命令执行 → 配置文件读取凭据 → 1433 登录与查询 → 建号/加组/开 RDP → 3389 登录 → 后续持久化。

## PoC

```text
# Wireshark 显示过滤器
tcp.port == 1433
tds
tcp.port == 3389
```

```bash
# tshark 列出 TDS 帧，再在 Wireshark 中展开 Query 字段读取明文 SQL
tshark -r web.pcap -Y "tds" -T fields -e frame.number -e _ws.col.Info

# 只看 1433 会话
tshark -r web.pcap -Y "tcp.port == 1433" -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info
```

说明：`Query` 文本在 Wireshark 包详情 `TDS Query Packet → Packet data stream headers/Query` 中显示；tshark 的 TDS 字段名随版本略有差异，以 GUI 或 `-V` 输出为准。未执行任何原文命令。

## 变体与关联

- 变体：SQL Server 强制加密时 TDS 外层为 TLS，需要会话密钥或服务器私钥解密；命名管道/Shared Memory 连接不经过 1433。
- 变体：通过 `sp_executesql` 等 RPC 调用执行时，Wireshark 显示为 TDS RPC 而不是 SQL batch，需要展开 RPC 参数查看语句。
- 变体：Azure SQL/托管实例的网关与端口不同；会话复用与连接池会让多条命令出现在同一 TDS 连接中。
- 关联：[[pentest-privilege-escalation-mssql-sysadmin-reuse-xpcmdshell]]、[[pentest-lateral-movement-windows-registry-enable-rdp-disable-nla]]、[[defense-detection-sqlps-lolbin-powershell]]、[[defense-forensics-rdp-pfx-tls-decrypt-scancode-replay]]、[[defense-incident-response-pcap-web-intrusion-attacker-timeline]]。

## 检测与防御

- 检测：1433 出现非预期来源；TDS 会话中出现 `xp_cmdshell` 关键字（IDS/NDR/流量规则）；SQL Server 侧 `sp_configure 'xp_cmdshell'` 变更与扩展存储过程调用；Windows 4688 中 `sqlservr.exe` 派生 `cmd.exe`；4720/4732 新增用户/加入管理员组；`fDenyTSConnections` 注册表变更与 3389 监听。
- 防御：禁用 `xp_cmdshell` 并用策略锁定；最小化 sysadmin 成员，禁用或强口令化 sa；应用配置文件加密存放，避免 Web 目录中的 `web.config` 明文口令；数据库端口只对必要主机开放；SQL Server 以低权限专用账户运行；RDP 仅经 VPN/跳板并强制 NLA。
- 取证：原始 pcap 只读保存并计算哈希；把 TDS 查询导出为文本时间线，与 HTTP、RDP 及主机日志交叉验证。
