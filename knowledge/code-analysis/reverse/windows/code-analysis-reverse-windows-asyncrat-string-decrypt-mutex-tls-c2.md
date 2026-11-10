---
id: code-analysis-reverse-windows-asyncrat-string-decrypt-mutex-tls-c2
title: AsyncRAT 注入体分析：Base64+自定义解密配置字符串、AsyncMutex 互斥体、忽略证书校验的 TLS C2 与 Chrome Profile 枚举
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: asyncrat-string-decrypt-mutex-tls-c2-analysis
aliases:
- AsyncRAT 分析
- AsyncClient123
- AsyncMutex_alosh
- AsyncRAT 字符串解密
- SslStream 忽略证书校验
- Chrome User Data 枚举
- AsyncRAT 配置提取
tags:
- code-analysis
- reverse
- windows
- dotnet
- dnspy
- asyncrat
- malware-analysis
- config-extraction
- mutex
- tls
- chrome
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V424
  verified_at: '2026-11-09T17:23:28+08:00'
  notes: 已对照原文与图21/22/23/24/25/26/27/28/29核对：AsyncClient123 混淆程序集，解密方法 DSHlwdM?uqonI(string) 返回 Encoding.UTF8.GetString(this.HhvGciICHlBij(Convert.FromBase64String(...)))（已按图23 修正卡内原方法名拼写）；断点得到互斥体 AsyncMutex_alosh，Handles 中可见 \Sessions\2\BaseNamedObjects\AsyncMutex_alosh（图24/25）；SslStream 的 RemoteCertificateValidationCallback 恒 true，Locals host=johngo.dnsgeek.com port=7707 → 142.202.240.40:7707（图28），aspnet_compiler.exe 的 TCP 连接与图19/29 一致；Chrome User Data 枚举 length==32 且 switch(fileName[22]) 与图27 一致；反调试/环境检查（Admin/Performance/Pastebin/Antivirus 字符串、dnSpy 版本弹窗）与图26 一致。未验证点：具体自定义字节变换算法与 Chrome 数据收集用途原文未展开（卡内已写疑似）；未复跑样本。dedup 候选（RedLine/Quasar/XWorm 等配置解密卡）均不同链；dup-scan.json(11-08) 早于建卡(11-09) 无本卡 pair；无 sources/source_url、无原文 URL/文章 ID/长段摘录（保留原文 C2 IOC），path code-analysis/reverse/windows 合法；非组件类无受影响版本。颗粒度：单一分析定位链（解密函数→互斥体→TLS C2→Chrome 目录），未混入独立攻击动作。
---

## 一句话结论

对被注入 `aspnet_compiler.exe` 的 AsyncRAT（样本代号 `AsyncClient123`）载荷，可在 dnSpy 中定位形如 `Encoding.UTF8.GetString(this.<custom>(Convert.FromBase64String(s)))` 的字符串解密函数，在 `GetString` 返回处下断点即可批量还原配置字符串（例如互斥体 `AsyncMutex_alosh`）；再结合 `SslStream` 构造（证书校验回调恒返回 true）与进程网络连接可定位 C2（配置中为域名:7707，解析到 `142.202.240.40:7707`）。载荷同时枚举 Chrome `User Data` 下 32 字符随机命名的 Profile 目录，疑似做浏览器数据收集。

## 原理

- **配置字符串解密定位**：AsyncRAT 把配置字段以 Base64 保存，运行时先 `Convert.FromBase64String` 再经自定义字节变换，最后 `Encoding.UTF8.GetString` 得到明文。dnSpy 反编译中可见 `return Encoding.UTF8.GetString(this.HhvGciICHlBij(Convert.FromBase64String(input)));` 形式的单行方法，是下断点的最佳位置：在 `GetString` 返回处断下，调用栈上游的配置初始化会把 Mutex、Host、Port、Version、Install Name 等字符串依次解出。
- **互斥体定位**：RAT 启动时创建命名互斥体防止多实例，样本解出的名字为 `AsyncMutex_alosh`；Process Hacker/Process Explorer 的 Handles 视图可看到 `\Sessions\<会话>\BaseNamedObjects\AsyncMutex_alosh`。互斥体名既是家族/变体识别特征，也可用于在内存中定位正在运行的注入体（即使宿主进程名是 `aspnet_compiler.exe`）。
- **TLS C2 连接**：C2 通信使用 `new SslStream(new NetworkStream(tcp), false, new RemoteCertificateValidationCallback(...))`，回调直接返回 true（接受任意服务器证书），因此中间人/沙箱代理可截获流量；端点通过 `RemoteEndPoint.ToString().Split(':')[0]` 等形式取得。调试器 Locals 中可见 host=`johngo.dnsgeek.com`、port=`7707`，实际连接为 `142.202.240.40:7707`；`SslProtocols.Tls` 用于包装流。
- **Chrome Profile 枚举**：样本遍历 `...\Google\Chrome\User Data` 下的目录，只处理长度为 32 字符的 Profile 目录名，并按第 23 个字符（`fileName[22]`）分支——这是 Chrome 新版随机 Profile 目录（如 32 字符）的常见识别方式，推测用于定位浏览器凭据/Cookie/历史数据，属 AsyncRAT 变体的数据收集能力。
- **反分析检查**：原文提到样本会检测虚拟化/分析环境与调试器存在，截图中出现对 “Admin”“Performance”“Pastebin”“Antivirus”等字符串的检查与布尔标志；具体判定逻辑原文未展开，属家族常见反沙箱/反调试组合。
- **为什么按“分析”成卡**：AsyncRAT 是开源 RAT，样本通常只做类名/字符串混淆；掌握“解密函数 → 互斥体 → TLS 连接 → 浏览器数据目录”这条定位链，可以在不完整脱壳的情况下从内存/调试器快速提取 C2 与家族信息，用于阻断与同源聚类。

## 触发条件

- 样本为 .NET 程序集且可被 dnSpy/de4dot 反编译（本例 AsyncRAT 仅字符串与类名混淆，未强壳）。
- 能在隔离环境中运行样本并附加调试器（或从内存 dump 出注入体程序集）。
- 配置字符串在启动阶段解密；若样本被配置为延迟/按需解密，需要在相应调用点下断。

## 利用步骤

1. 从注入宿主 `aspnet_compiler.exe` 进程 dump 内存或取得原始 `AsyncClient123` 程序集，dnSpy 打开，定位入口点与配置初始化代码。
2. 搜索 `Convert.FromBase64String`、`Encoding.UTF8.GetString`，找到返回 UTF-8 字符串的解密方法（本例 `DSHlwdM?uqonI(string)` → `HhvGciICHlBij(byte[])` → `GetString`）。
3. 在 `GetString` 返回处下断点并继续，记录返回的字符串：先出现互斥体名 `AsyncMutex_alosh`，随后是 Host/Port、版本、安装名等配置项。
4. 用 Process Hacker 打开注入进程的 Handles，确认 `\Sessions\<n>\BaseNamedObjects\AsyncMutex_alosh`，作为运行中确认与主机排查点。
5. 在 `SslStream` 构造与连接处下断，读取 host/port 与远端 IP（本例 `johngo.dnsgeek.com:7707` → `142.202.240.40:7707`）；注意证书校验回调恒 true。
6. 观察文件/注册表访问，确认 Chrome `User Data` 下 32 字符 Profile 目录的枚举行为，评估数据收集范围。

## PoC

无通用 PoC（需样本与调试器配合）。定位用的函数形态与断点位置（按反编译截图重写）：

```csharp
// 反编译中可见的解密方法形态
public string Decrypt(string input) {
    return Encoding.UTF8.GetString(this.CustomTransform(Convert.FromBase64String(input)));
}
// 断点：Encoding.UTF8.GetString 返回处；记录每次返回值即可得到配置字符串
```

```text
# 观察到的关键值（原文截图）：
互斥体：AsyncMutex_alosh
C2：johngo.dnsgeek.com:7707（解析为 142.202.240.40:7707，TLS）
互斥体句柄：\Sessions\2\BaseNamedObjects\AsyncMutex_alosh
```

说明：本卡未执行样本；`CustomTransform` 的具体算法原文未展开，实际分析时在调试器中读返回值即可，无需逆出算法。

## 变体与关联

- [[code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt]]：另一个开源 .NET RAT 的配置离线解密；AsyncRAT 的配置用 Base64+自定义变换而非 PBKDF2+AES/HMAC，本例通过动态断点取明文。
- [[code-analysis-reverse-windows-xworm-v5-aes-config-plugin-rat-capabilities]]：同类 .NET RAT 家族分析（配置解密 + 能力清单）。
- [[pentest-c2-managed-runpe-reflection-newpe2-aspnet-compiler]]：本载荷被注入 `aspnet_compiler.exe` 的托管 RunPE 链。
- [[pentest-initial-access-wsf-remote-script-bits-zip-loader-chain]]、[[code-analysis-reverse-obfuscation-txt-fragment-keyword-reflection-assembly]]：本载荷的投递与前置混淆。
- 变体：AsyncRAT 二次开发常改互斥体前缀（如 `AsyncMutex_` 后随机串）、字符串加密算法、C2 端口与 TLS 开关；互斥体与解密函数形态仍是稳定定位点。
- 边界：强混淆/加壳、配置从 C2 下发或延迟解密时，静态断点可能取不到全部配置；证书校验回调为 true 使流量可被代理解密，便于取证。

## 检测与防御

- 检测：合法 .NET 进程（尤其 `aspnet_compiler.exe`）中出现 `AsyncMutex_*` 命名互斥体；进程内存含 AsyncRAT 特征字符串/程序集元数据；对外 TLS 连接使用非常用端口（如 7707）且证书不受信。
- 检测：进程访问 `\Google\Chrome\User Data` 下多个 32 字符 Profile 目录（浏览器凭据/Cookie 收集行为）；`aspnet_compiler.exe` 由 `powershell.exe` 创建且无编译参数。
- 防御/响应：内存扫描与 ETW .NET 程序集加载监控；对 `aspnet_compiler.exe` 异常子进程与网络行为告警；发现互斥体后终止宿主进程、dump 内存提取配置；用 C2 域名/IP 与互斥体做全网排查与同源聚类。
