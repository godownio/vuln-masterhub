---
id: defense-forensics-remote-control-log-peer-ip-role
title: 远控软件本地日志取证：按创建时间选日志、用角色特征标签从向日葵/ToDesk/TeamViewer 日志提取对端真实 IP 并判断主控/被控角色
type: scenario
domain: defense
path: defense/forensics
technique: remote-control-log-forensics-peer-ip-role
tags:
- windows
- forensics
- remote-control
- sunlogin
- todesk
- teamviewer
- log-analysis
- ip-attribution
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V563
  verified_at: '2026-11-12T07:50:43+08:00'
  notes: 已对照原文与11张截图逐张核对：图01/02 安装目录与log文件夹定位、图03 向日葵V12.6.0.49095完整版、图04 三个日志文件（shell.20220828-122150.log / sunlogin_service.20220828-122135.log / sunlogin_service_watch.*，仅第二个含连接信息）、图05 属性创建时间2022-08-28 12:21:35、图06 主控端搜被控真实IP命中8项、图07/08 被控端搜主控IP的[udpwrapper]/[udp]命中、图09 角色标签维恩图（[P2PHelper]/[P2PStream]仅主控，[P2PAccepter]/[service]仅被控，[udpwrapper]/[udp]双端）、图10/11 微步情报39.x=住宅用户=真实IP、183.248.x=数据中心=非真实IP，均与卡一致；ToDesk/TeamViewer特征表逐行对照原文表格一致（文章未给两者的日志截图，卡已标注实测范围）。修正一处表述：原文被控端[udp]为OnConnectRequest/OnConnectAck，仅主控端为OnConnectRes，卡片原句‘[udp] OnConnectRes两端都会出现’已改为按端区分的精确描述。dedup：仅本卡自身exact命中；最近候选pentest-lateral-movement-sunlogin-cnvd-2022-10270-rce为攻击向未授权RCE、defense-forensics-windows-evtx-psreadline-rmm-chain-reconstruction主线为4624/4688+PSReadLine还原wmiexec链，均非同链；dup-scan.json无涉本卡pair。文中版本V12.6.0.49095为测试环境而非受影响版本，未设affected_versions。未验证点：ToDesk/TeamViewer部分为原文特征表转述，无独立样本复核。
url: /docs/defense/forensics/defense-forensics-remote-control-log-peer-ip-role/
draft: false
kb_aliases:
- 向日葵日志取证
- Sunlogin 日志分析
- ToDesk 日志取证
- TeamViewer 日志取证
- 远控连接日志
- 主控端/被控端识别
- 远控对端 IP 提取
---

# 一句话结论

向日葵、ToDesk、TeamViewer 等远控软件会在本地安装目录留下连接日志；向日葵日志用角色专属标签区分两端——主控端出现 `[P2PHelper]`/`[P2PStream]`，被控端出现 `[P2PAccepter]`/`[service]`，双端都有 `[udpwrapper]`/`[udp]`——结合日志文件创建时间与 IP 情报（住宅宽带 vs 数据中心），即可从单台主机提取对端真实公网 IP 并判断本机在本次远控中是主控端还是被控端。

# 原理

- **远控软件为排障记录 P2P 打洞细节**：日志会打印本端/对端的 local IP:port 与 public IP:port。向日葵主控端日志形如 `[P2PHelper] receive peer local ip ... public ip <peer_public>:port`、`[P2PStream] EstablishP2P local ip <self_public>:port/... ==> peer ip <peer_public>:port/...`；被控端日志形如 `[P2PAccepter] receive P2P request (public <peer_public>:port local ...)`、`[service][UdpAcceptor] new acceptor <peer_public>:port-->0.0.0.0:port`。`[udpwrapper]`（如 `P2PHolePunch`）与 `[udp]` 系列连接日志两端都会出现（主控端形如 `OnConnectRes`，被控端形如 `OnConnectRequest`/`OnConnectAck`）。因此哪些标签出现在日志里，就说明本机在连接中的角色，标签里的 public/peer IP 就是对端地址。
- **为什么用创建时间**：文件浏览、编辑会更新"修改时间"，日志写入也会不断刷新 mtime；只有"创建时间"能稳定对应日志开始记录的时刻，用来把日志文件与案发时间段对齐。
- **为什么要做 IP 情报甄别**：P2P 打洞日志中的 public IP 可能是对端真实出口 IP，也可能是厂商中继/云主机地址。文章示例中 `39.x.x.x` 被情报平台标记为"住宅用户"（真实 IP），而 `183.248.x.x` 被标记为"数据中心"（并非真实 IP）；对家宽/企业专线需结合 IP 侧情报综合研判，对服务器用户可能因实验时间过短而没有有效记录。
- **ToDesk 与 TeamViewer 的落点**：ToDesk 日志在安装目录 `\todesk\Logs`，`client_年_月_日.log`/`session_年_月_日.log` 中 `LocalIpport`、`RemotePort tcp begin connect` 可查本地/对端 IP，`token login center` 含本机注册手机号；查询 IP 时需先排除 `127.0.0.1` 等本地地址。TeamViewer 日志在 `%AppData%\TeamViewer\TeamViewer15_Logfile.log`，连接特征为 `punch received`，日志不保留手机号。
- **取证价值**：远控软件日志是判断"谁控制了谁、从哪个 IP 接入、绑定哪个手机号"的直接端点证据，可与网络流量、账号登录记录交叉验证。

# 触发条件

- 取证/侦察场景中能接触目标主机文件系统（现场、磁盘镜像或远程采集），且远控软件已安装并产生过连接日志、日志未被清理。
- 知道或能推断案发时间段，用于挑选对应日志文件；日志级别/版本需保留 Info 级 P2P 记录（文章实测向日葵完整版与简约版日志无区别，均有记录）。
- 具备 IP 情报/资产测绘平台，用于区分真实出口 IP 与中继/数据中心地址。
- 合法授权前提下进行（日志含手机号、IP 等个人信息）。

# 利用步骤

1. 定位安装目录：有桌面图标时右键→"打开文件所在位置"；无图标时任务栏搜索应用名→"打开文件位置"。向日葵默认 `C:\Program Files\Oray\SunLogin\SunloginClient\log`，ToDesk 为 `\todesk\Logs`，TeamViewer 为 `C:\Users\<用户>\AppData\Roaming\TeamViewer`。
2. 选对日志文件：向日葵为 `sunlogin_service.<YYYYMMDD>-<HHMMSS>.log`（同目录 `shell.*.log`、`sunlogin_service_watch.*.log` 通常不含连接信息）；ToDesk 为 `client_年_月_日.log` 与 `session_年_月_日.log`；TeamViewer 为 `TeamViewer15_Logfile.log`。
3. 看文件属性中的**创建时间**，把日志与案发时间段对齐（多份日志时尤其重要）。
4. 提取对端 IP 与角色：
   - 向日葵主控端：搜 `[P2PHelper]`、`[P2PStream]`，读取 `public ip`/`peer ip`；被控端：搜 `[P2PAccepter]`、`[service]`；两端都搜 `[udpwrapper]`、`[udp]` 交叉验证。
   - ToDesk：搜 `LocalIpport`、`RemotePort tcp begin connect`、`token login center`（手机号），排除 `127.0.0.1` 等本地 IP。
   - TeamViewer：搜 `punch received` 定位对端连接记录。
5. 对提取到的 IP 做情报查询，标注住宅/企业专线/数据中心；数据中心地址多为中继，不作为对端真实 IP。
6. 结合日志中本机注册手机号/账号、登录时间与网络侧记录，形成"主机—角色—对端 IP—账号"的证据链。

# PoC

```powershell
# 向日葵：按角色标签检索所有服务日志中的对端/本端公网 IP（只读，不改动证据）
$log = "C:\Program Files\Oray\SunLogin\SunloginClient\log\sunlogin_service.*.log"
Select-String -Path $log -Pattern '\[P2PHelper\]|\[P2PStream\]|\[P2PAccepter\]|\[service\]|\[udpwrapper\]|\[udp\]'

# ToDesk：查本地/对端 IP 与注册手机号
Select-String -Path "\todesk\Logs\client_*.log","\todesk\Logs\session_*.log" -Pattern 'LocalIpport|RemotePort tcp begin connect|token login center'

# TeamViewer：连接特征
Select-String -Path "$env:APPDATA\TeamViewer\TeamViewer15_Logfile.log" -Pattern 'punch received'
```

```text
文章实测（向日葵 V12.6.0.49095，两台 Win10，仅正常连接未传文件）：
主控端日志搜被控机真实 IP 得到 8 项命中；被控端日志搜主控机真实 IP 得到 5 项命中；
[P2PHelper]/[P2PStream] 仅主控端出现，[P2PAccepter]/[service] 仅被控端出现，[udpwrapper]/[udp] 双端出现。
```

# 变体与关联

- 同类产品：Splashtop、Parsec、Microsoft 远程桌面、AnyDesk、NoMachine、GotoHTTP 等同样会在本地留下连接日志，路径与关键字需按产品分别定位；文章仅实测向日葵/ToDesk/TeamViewer。
- 关联（攻击面）：`pentest-lateral-movement-sunlogin-cnvd-2022-10270-rce`、`pentest-initial-access-sunlogin-cnvd-2022-03672-verify-haras-rce`、`pentest-lateral-movement-todesk-upgrade-password-inheritance` 描述了利用远控软件本身的入侵/横向手法；本卡用于事发后从端点日志反向定位控制端 IP 与角色。
- 关联（取证思路）：与常规"从网络流量/登录日志还原攻击链"的取证卡互补；远控软件日志缺失时可退回流量侧（P2P/UDP 打洞流量）与账号侧证据。
- 边界：日志可能被清理/覆盖（文章实验均在 5 分钟内完成，日志量小）；重装系统或升级可能改变路径与格式；中继模式下日志中的 IP 不是对端真实 IP，必须做情报甄别。

# 检测与防御

- 证据保全：第一时间对日志目录做镜像或只读导出并计算哈希，记录文件创建时间；避免直接打开写入。
- 日志留存与集中：将远控软件日志、Windows 事件日志、网络流量集中采集，防止攻击者删除本地日志；对远控软件安装/运行做资产盘点与告警。
- 研判：把日志中的对端 IP 与防火墙/NAT/代理日志、账号登录日志交叉验证；对住宅 IP 与数据中心 IP 分别标注，避免把中继地址误判为攻击者真实地址。
- 合规：日志包含手机号、IP 等个人信息，取证需在授权范围内进行并做好脱敏与访问控制。
