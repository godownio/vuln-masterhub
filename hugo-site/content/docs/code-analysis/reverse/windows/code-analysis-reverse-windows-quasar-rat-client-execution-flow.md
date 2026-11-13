---
id: code-analysis-reverse-windows-quasar-rat-client-execution-flow
title: Quasar RAT 1.4.1 客户端执行流程逆向：NETReactor 去混淆、启动自检、双次 TLS 连接与 DoShellExecute 指令循环
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: quasar-rat-client-execution-flow
tags:
- quasar-rat
- dotnet
- malware-analysis
- reverse
- netreactor
- dnspy
- tls
- c2
- imessage
- execution-flow
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502
  verified_at: '2026-11-11T02:38:18+08:00'
  notes: 已通读全文并逐张读取44张本地图（其中正文第42张为外链未本地化，已用图43/44与 Quasar v1.4.1 官方源码交叉核对）。核对一致：Main 设 Tls12+Application.Run(GForm0)（图10）、Rfc2898DeriveBytes(masterKey,salt,50000) 派生 32/64 字节（图12/15）、AES-256-CBC+HMAC-SHA256（图14）、证书公钥 VerifyHash(SHA256) 自检（图20）、Mutex CreatedNew 否则 Exit(2)（图21）、删 Zone.Identifier（图22）、安装/启动项（图23）、托盘图标（图24）、QuasarClient+MessageHandler 注册（图25/26）、心跳常量 0x61A8/HEADER_SIZE 4（图29）、队列取址与 SslStream/AuthenticateAsClient 不校验证书（图31/32）、双次连接与 ClientIdentification 字段（图33-38）、dir 指令 protobuf 字节与 DoShellExecute 处理（图40/41/43/44）。另抓 Quasar v1.4.1 源码确认帧格式为 4 字节长度头+protobuf，DoShellExecute 首次建 Shell、exit Dispose 的描述准确。证书有效期 9999（UTC，界面本地显示10000/1/1）无误。frontmatter 无 sources/source_url；Quasar 为开源RAT非组件版本，未设版本区间。PoC 为断点/过滤速查，未执行样本。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-quasar-rat-client-execution-flow/
draft: false
kb_aliases:
- Quasar RAT 客户端分析
- Quasar 执行流程
- NETReactorSlayer 去混淆
- QuasarClient 通信初始化
- DoShellExecute 指令
- 双次 TLS 连接
- Quasar 启动自检
---

## 一句话结论

Quasar RAT 1.4.1 客户端是 .NET Reactor 混淆的 WinForms 程序，`de4dot`/NETReactorSlayer 去混淆后用 dnSpy 即可还原完整执行链：入口设 TLS1.2 并进入主窗体；初始化阶段完成 PBKDF2 派生密钥、AES+Base64 配置字符串解码、证书公钥签名自检（失败退出）、互斥体单实例、删除自身 `Zone.Identifier`、按配置自安装与托盘图标；随后创建 QuasarClient 与消息处理器集合、以 25 秒 Keep-Alive 心跳启动连接线程，先后做两次 TCP+TLS1.2 连接（第一次只握手后断开，第二次发送 `ClientIdentification` 上线信息），之后在异步读回调里按 4 字节头 + Protobuf 消息分发，`DoShellExecute` 命令交给 Shell 执行并逐行回传结果。

## 原理

- **去混淆与入口定位**：样本带 .NET Reactor 混淆（类名 `Class0`、`GClass65` 等，字符串加密）。用 NETReactorSlayer（或 de4dot）还原后，dnSpy 中入口 `Main` 可见 `ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12`、异常处理注册、`EnableVisualStyles`、`Application.Run(new GForm0())`——典型 WinForms 主窗体，GForm0 即后续初始化逻辑所在。
- **密钥与字符串解码**：初始化时用样本内置的 masterKey（本例为 40 位十六进制串）与固定盐做 `Rfc2898DeriveBytes(masterKey, salt, 50000)`，`GetBytes(32)`/`GetBytes(64)` 分别得到 AES key 与 HMAC key；配置字符串以 Base64+AES-256-CBC 存储，`method_2 = UTF8.GetString(method_3(Convert.FromBase64String(input)))`，`method_3` 先校验 32 字节 HMAC-SHA256 再取 16 字节 IV 解密。C2 地址、安装目录、文件名、互斥体名、启动项名、客户端标签、证书等都在这一步还原（加密细节另见关联卡）。
- **启动自检**：`smethod_2` 用样本内置 X509 证书的 RSA 公钥对一段内置数据做 `VerifyHash(..., CryptoConfig.MapNameToOID("SHA256"), Convert.FromBase64String(signature))`，校验失败返回 false，调用方随即退出。作用类似证书/公钥固定，防止被替换证书的假 C2 或篡改样本；证书默认 CN 为 `Quasar Server CA`、有效期到 9999 年，是家族默认特征。
- **单实例与 MOTW 清理**：`new Mutex/GClass1(uniqueId)` 若 `CreatedNew == false` 则 `Environment.Exit(2)`，保证只有一个实例；`Class3.DeleteFile(Application.ExecutablePath + ":Zone.Identifier")` 删除自身 NTFS 备用数据流，去掉“文件来自 Internet”标记，避免 SmartScreen/MOTW 相关策略干扰。
- **安装与驻留**：按配置决定是否把自身复制到 `%AppData%\<SubDir>\<Client.exe>` 并设置开机启动（启动项名可配置，本例 `Quasar Client Startup`）；随后初始化托盘图标（`Quasar Client\nNo connection`），用于显示连接状态并维持进程。
- **通信初始化**：创建 `QuasarClient`（构造函数接收 hosts 管理器与服务端证书）并订阅其连接状态事件；再创建消息处理器集合，把 GClass32–GClass44 等处理器通过 `MessageHandler.Register` 注册，覆盖 Shell、文件、注册表、进程、屏幕等指令。心跳参数在 GClass2 中定义：`BUFFER_SIZE 0x4000`、`HEADER_SIZE 4`、`KEEP_ALIVE_INTERVAL/TIME 0x61A8`（25 秒）、`MAX_MESSAGE_SIZE 0x500000`。
- **连接循环与双连接**：连接线程从 hosts 队列取目标（支持多 C2 轮换），`method_4` 先断开旧连接，创建 Socket 并设置 TCP Keep-Alive 为 25 秒，`Connect` 后用 `SslStream(networkStream, true, false, RemoteCertificateValidationCallback)` 包装，`AuthenticateAsClient(ip, null, SslProtocols.Tls12, false)`——**不校验证书**（回调放行）；成功则 `BeginRead` 异步接收。抓包可见第一次连接只完成 TCP 三次握手与 TLS 握手即 FIN 断开，第二次连接重新握手后才发送 `ClientIdentification`（Version、OS、AccountType、Country/CountryCode、ImageIndex、HardwareId、Username、PCName、Tag、EncryptionKey、Signature 等），心跳维持 25 秒。
- **指令循环与 DoShellExecute**：异步 `EndRead` 得到字节数 num，拷贝到 `byte[] array` 后交给消息处理器。以 `dir` 为例，内存中可见长度头后紧跟 Protobuf 编码的指令（字段含消息类型与命令文本）。`Execute` 先判断消息是否 `DoShellExecute`，是则取 `message.Command`：首次命令创建 Shell 实例，后续复用；`exit` 时 Dispose；其余交给 Shell 的 `ExecuteCommand`。执行输出封装为多条 `DoShellExecuteResponse`（IsError/Output 行）经同一 TLS 流回传，服务端逐行展示，随后恢复等待下一次读取。
- **为什么这样设计**：TLS+Protobuf 让流量内容不可见；双连接把“探测/握手”和“带身份上线”分开，降低被简单协议识别概率；消息处理器注册表让指令分发与通信解耦，便于二次开发加入新功能；客户端内置证书公钥校验则提高防守方中间人/伪造 C2 的门槛。

## 触发条件

- 拿到带 .NET Reactor 混淆的 Quasar 客户端样本（PE/.NET，常见于钓鱼附件、二次打包载荷）。
- 分析环境具备 dnSpy/de4dot/NETReactorSlayer 与网络抓包工具；样本可在隔离环境运行以观察连接行为。
- 样本未被强壳/原生混淆破坏 .NET 元数据；masterKey、salt、证书等仍内嵌。

## 利用步骤

> 以下为分析/取证步骤（复现样本行为需隔离环境）。

1. 用 NETReactorSlayer 或 de4dot 去混淆，dnSpy 打开还原后的程序集，定位入口 `Main` 与主窗体 `GForm0`。
2. 在 `Main`、初始化 `smethod_0`（配置解码入口）、`Class28` 构造函数（PBKDF2）、`method_3`（AES 解密）下断点，导出 masterKey/salt 与全部配置字符串（C2、安装路径、互斥体、启动项、证书、标签）。
3. 在 `smethod_2`（证书公钥 VerifyHash）下断，确认证书与签名来源；在互斥体创建与 `DeleteFile(":Zone.Identifier")` 处下断，确认单实例与 MOTW 清理行为。
4. 在连接函数 `method_4` 下断：记录 hosts 队列地址、端口、`AuthenticateAsClient` 参数与证书校验回调返回值，确认 TLS1.2 且不验证服务端证书。
5. 抓包对照两次 TCP+TLS 连接：第一次握手后断开，第二次握手后发送 `ClientIdentification`；按 4 字节头 + Protobuf 解析消息，确认心跳周期 25 秒与上线字段。
6. 在异步读回调 `EndRead`、`MessageHandler.Execute`、Shell `ExecuteCommand` 下断，下发 `dir` 观察内存中长度头后的 Protobuf 指令与返回的 `DoShellExecuteResponse` 行。
7. 汇总 IOC：C2、证书指纹/公钥、互斥体、安装路径与启动项名、客户端标签与 HardwareId，用于同源样本与主机排查。

## PoC

无 PoC（分析类场景，不提供可执行利用代码）。可复用的断点/过滤速查：

```text
dnSpy 断点：Main → smethod_0 → Class28::.ctor → method_3 → smethod_2 → method_4 → EndRead → Execute → ExecuteCommand
抓包过滤：tcp.port == <C2端口>；tls.handshake.type == 1/2/11；按 4 字节头切分应用层消息
关键常量：KEEP_ALIVE 0x61A8(25s)、HEADER_SIZE 4、MAX_MESSAGE_SIZE 0x500000、BUFFER_SIZE 0x4000
```

## 变体与关联

- 关联：配置解密算法（PBKDF2/HMAC/AES 布局与离线还原脚本）见 [[code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt]]；本卡聚焦执行流程与通信时序，密码学细节以该卡为准。
- 关联：Quasar RAT TLS 流量识别（默认证书 CN/hex、固定套件、25 秒心跳、ACK/SYN 比例）见 [[defense-detection-quasar-rat-tls-traffic-fingerprint]]；本卡从客户端代码侧解释这些特征的来源。
- 关联：同类 .NET RAT 分析（AsyncRAT 字符串解密/互斥体/TLS C2）见 [[code-analysis-reverse-windows-asyncrat-string-decrypt-mutex-tls-c2]]，可对比两者初始化与消息分发差异。
- 变体：二次开发版本可能改 salt/迭代次数/类名、把配置放入资源或改为服务端下发；C2 地址可换域名、端口可自定义；心跳与缓冲区参数可调。
- 边界：样本被强混淆到无法反编译或配置运行时从 C2 拉取时，需动态调试/内存 dump；线程与消息注册表的具体类名随版本变化。

## 检测与防御

- 主机：`%AppData%` 下随机子目录出现可执行文件与 `Logs` 目录；启动项名可配置（默认 `Quasar Client Startup`）；进程创建互斥体、删除自身 `Zone.Identifier`、托盘图标文本 `Quasar Client`；.NET 进程发起 TLS1.2 长连接并周期性发送小包。
- 网络：默认证书 `CN=Quasar Server CA`、有效期至 9999 年、固定 hex 特征；TLS 1.2 固定套件与 25 秒心跳；上行远大于下行。使用既有 ET/Suricata 规则与 JA3/JA3S 组合检测。
- 防御：启用 .NET 程序集审计与 AMSI/ETW；限制 `%AppData%` 可执行文件启动与自启动项；出站白名单；对无签名 .NET 进程的 TLS 外联做告警。
- 响应：隔离主机、提取样本与内存、按配置解密结果封禁 C2、清理安装目录/启动项/互斥体，排查同源投递与横向。
