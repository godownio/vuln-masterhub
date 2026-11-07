---
id: defense-forensics-java-rat-plugin-loader-neutrino-tunnel
title: Java 远控插件加载与内网穿透：PluginUtil 下载 JAR + neutrino proxy 隧道 + PscpService 远程文件/DB/PowerShell
type: scenario
domain: defense
path: defense/forensics
technique: java-rat-plugin-loader-neutrino-tunnel
aliases:
- MSRSCI 插件加载
- PluginUtil
- ProxyManager
- neutrino proxy
- 内网穿透
- PscpService
- CmdChannelHandler
- Java RAT 能力分析
tags:
- forensics
- java
- malware
- rat
- plugin-loader
- intranet-tunnel
- proxy
- powershell
- c2
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:12:01+08:00'
  notes: 已对照原文与截图核对：PluginUtil 下载/加载插件、清理时保留 version.txt 与 agent.mv.db、clearData 清空 xx_001/xx_002/process_log、LauncherController 调 ProxyManager.add(ip,licenseKey)、neutrino/proxy 包结构与开源中微子代理一致、PscpService 提供 DB/文件/PowerShell 接口均一致。未验证点：未动态验证隧道建立与远控指令执行。
---

## 一句话结论

MSRSCI.jar 的远控能力集中在三块：`PluginUtil` 从配置 URL 下载/加载 `proxy-agent.jar`、`lib-agent.jar` 等插件并在清理时保留 `version.txt`/`agent.mv.db`；`ProxyManager.add(ip, licenseKey)` 通过 `neutrino/proxy`（与开源 neutrino proxy 代码一致）建立长期连接/内网穿透隧道；`PscpService`/`CmdChannelHandler` 提供远程数据库查询修改、文件浏览/删除/解压/上传/下载、PowerShell 执行与任务下发。

## 原理

- **插件加载**：`org/dromara/agent/launcher/util/PluginUtil` 负责加载插件 JAR，并从配置的 URL 下载指定 JAR；配置中的 `jarLibs` 列出 `proxy-agent.jar`、`lib-agent.jar`、`xjar-pscp.exe`。清理逻辑会删除插件文件，但保留 `version.txt` 与 `agent.mv.db`，并可清空 `xx_001`、`xx_002`、`process_log` 表，抹除运行痕迹与插件数据。
- **内网穿透**：`ProxyManager.add(ip, licenseKey)` 建立长期连接或隧道；`org/dromara/agent/launcher/core` 下的 `ProxyConnector`、`TcpProxyChannelHandler`、`UdpProxyChannelHandler`、`RealServerChannelHandler` 等类实现代理连接与转发；`neutrino/proxy/core` 的包结构与 GitHub 开源项目 neutrino proxy 一致，说明该远控直接集成了开源内网穿透组件。
- **远程控制接口**：`PscpService` 是核心接口类，具备远程数据库查询/修改、远程文件操作（浏览、删除、解压、上传、下载、查询）、远程 PowerShell 执行；`CmdChannelHandler` 负责控制消息、心跳、任务下发、连接状态，远控端指令从这里进入并分发。
- **配置与插件协同**：`version.txt`/`agent.mv.db` 中的 `servers`、`upgradeUrl`、`jarLibs` 决定 C2/升级地址与要下载的插件；`PluginUtil` 按这些配置拉取并加载插件，形成“配置下发 → 插件下载 → 功能扩展”的模块化远控。
- **能力面**：远程文件/数据库/PowerShell + 内网代理隧道，意味着攻击者不仅能控制单机，还能以受控终端为跳板访问内网；这与在线考试/监考场景结合，可能被用于篡改试卷、窃取考生数据、横向移动。
- 根因是“远控框架把插件下载、代理隧道、命令执行做成可配置模块”，分析时必须同时看 JAR、配置、插件和网络行为，不能只看单一 class。

## 触发条件

- 拿到完整样本目录（JAR、plugins、配置、日志、插件 JAR/exe）。
- 能反编译/解密 JAR（见 XJar 卡），并读取 `PluginUtil`、`ProxyManager`、`PscpService`、`CmdChannelHandler` 等类。
- 有网络/主机侧行为数据（C2 连接、插件下载、文件操作、PowerShell 执行）用于印证。
- 授权 malware 分析/取证环境。

## 利用步骤

1. 反编译/解密 JAR，定位 `PluginUtil`：确认插件加载路径、下载 URL 来源、清理逻辑与保留文件。
2. 查看 `version.txt`/`agent.mv.db` 中的 `jarLibs`、`upgradeUrl`、`servers`，列出插件与 C2。
3. 分析 `ProxyManager.add(ip, licenseKey)` 与 `core` 下的 `ProxyConnector`/`TcpProxyChannelHandler`/`UdpProxyChannelHandler`，确认代理协议、连接方向、是否支持 TCP/UDP 转发。
4. 将 `neutrino/proxy/core` 与开源 neutrino proxy 对比，确认内网穿透能力与版本。
5. 分析 `PscpService`/`CmdChannelHandler`，列出远程命令/文件/DB/PowerShell 接口与参数（VO 类可给出字段）。
6. 检查 `plugins` 目录下的 `proxy-agent.jar`、`lib-agent.jar`、`xjar-pscp.exe` 是否被篡改/替换，提取插件自身配置与 C2。
7. 结合日志/网络流量，还原“配置下发 → 插件下载 → 隧道建立 → 远程操作”的完整时间线。

## PoC

静态分析关注点（伪代码/类名）：

```text
PluginUtil.loadPlugin(...) / downloadJar(url) / deletePlugin(keep version.txt, agent.mv.db)
ProxyManager.add(ip, licenseKey) -> ProxyConnector -> TcpProxyChannelHandler / UdpProxyChannelHandler
PscpService: queryDatabase/updateDatabase, fileList/fileDelete/fileUnzip/fileUpload/fileDownload, powershell
CmdChannelHandler: control message / heartbeat / task dispatch
neutrino/proxy/core: ChannelAttribute, ProxyMessageDecoder/Encoder, dispatcher, type matchers
```

IOC 关注：

```text
plugins/version.txt
plugins/data/agent.mv.db
C:\ClientManager_PSC
proxy-agent.jar / lib-agent.jar / xjar-pscp.exe
:9010/version/update
H2 user LAUNCHER
```

## 变体与关联

- **插件变体**：JAR 插件、EXE 插件、脚本插件；下载源可能是 C2/升级 URL、对象存储、GitHub。
- **隧道变体**：neutrino proxy、frp、ngrok、reGeorg、自定义 TCP/UDP 转发；确认协议与端口。
- **控制变体**：CmdChannelHandler 自定义协议、WebSocket、HTTP 长轮询、心跳保活；PscpService 远程 DB/文件/PowerShell。
- **关联**：[[code-analysis-reverse-unpacking-xjar-encrypted-class-heap-key]]（先解 XJar）；[[defense-forensics-java-rat-encrypted-config-h2-db]]（配置/DB 中的 C2 与插件列表）；[[defense-forensics-c2-server-sqlite-conf-artifacts]]（C2 服务端取证）。
- **边界**：插件被删除/加密、C2 下线、隧道使用私有协议时，需要结合网络流量与内存取证；仅用于授权分析。

## 检测与防御

- **检测**：`plugins` 目录出现/下载 JAR/EXE；进程加载未知 JAR；外连 `:9010/version/update` 或异常长连接；H2 `agent.mv.db` 被创建/访问；PowerShell/文件/DB 远程操作；内网出现来自受控终端的代理流量。
- **防御**：阻断 C2/升级 URL；禁止 Java 进程从非白名单目录加载 JAR；监控插件目录与 H2 文件；限制 PowerShell 与内网代理；对考试/监考终端做完整性校验。
- **取证**：保留插件、配置、DB、日志与网络流量；对比开源 neutrino proxy 代码确认能力；输出 IOC 与时间线。
- **合规**：仅用于授权 malware 分析与取证。
