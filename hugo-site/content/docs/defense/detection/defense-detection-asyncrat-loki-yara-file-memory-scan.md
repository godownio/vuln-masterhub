---
id: defense-detection-asyncrat-loki-yara-file-memory-scan
title: AsyncRAT 终端与内存双扫描：RAT_AsyncRAT.yara 经 Loki 扫文件，内存独有字符串自建 yara 扫进程
type: scenario
domain: defense
path: defense/detection
technique: asyncrat-loki-yara-file-and-memory-scan
tags:
- asyncrat
- rat
- yara
- loki
- detection
- memory-scan
- ir
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V568
  verified_at: '2026-11-12T09:11:54+08:00'
  notes: 已对照原文12948及全部27张图逐张核对：RAT_AsyncRAT.yara规则全文(MZ+schtasks/START/DEL+三System.*导入+HWID/pastebin/antivm条件,图11)、Loki的score分级(图12)、signature-base/yara放置(图13/17)、AsyncClient.exe与混淆版均SCORE70命中(图14)、AsyncRAT2内存规则This is a ping!/savePlugin/sendPlugin fullword wide(图16)、Loki内存命中vmtoolsd.exe PID1220/ProcessHacker 3760/AsyncClient 3320(图17)均与卡片一致；未本机运行Loki；卡片PoC输出示例中'SUBS CORE'为'SUBSCORE'笔误(不影响使用)；dedup候选均非同链(通用yara内存狩猎卡为方法层，本卡为AsyncRAT具体规则+Loki双扫描)，无需删除。原文未声明受影响版本，未设versions。
url: /docs/defense/detection/defense-detection-asyncrat-loki-yara-file-memory-scan/
draft: false
kb_aliases:
- AsyncRAT Yara 检测
- RAT_AsyncRAT.yara
- Loki 扫描 AsyncRAT
- 内存字符串 yara 扫进程
- This is a ping 内存规则
- 无文件木马内存检测
---

## 一句话结论

终端侧可用 `RAT_AsyncRAT.yara`（MZ 头 + `schtasks /create /f /sc onlogon /rl highest`、`START`、`DEL` 命令串 + `System.Drawing.Imaging`/`System.Net.Sockets`/`System.Security.Cryptography` 导入 + HWID/pastebin/antivm 等特征）经 Loki 加载扫描文件，不同生成选项与混淆的 AsyncRATClient 均命中；无文件场景则用进程内存中的独有字符串（`This is a ping!`、`savePlugin`、`sendPlugin`）自建 yara，经 Loki 对进程内存扫描命中注入的 AsyncRAT 模块。

## 原理

- **静态 yara 规则**：RAT_AsyncRAT.yara 以 `$magic = "MZ"` at 0（PE 头）为前置，要求命令串（计划任务自启动 `schtasks /create /f /sc onlogon /rl highest`、启动与删除命令 `START`/`DEL`）、.NET 导入（`System.Drawing.Imaging`、`System.Net.Sockets`、`System.Security.Cryptography`）与可疑串（HWID、pastebin、Antivirus、Win32_ComputerSystem、antivm 等）的组合条件成立，因此对功能完整的 AsyncRAT 客户端家族命中率高。
- **生成选项不影响核心特征**：在 AsyncRAT 控制端勾选不同功能（反病毒分析等）生成的客户端，功能实现仍依赖上述 API 与命令串，所以规则持续命中；这与"改字符串即可免杀"的简单特征不同，检测方应优先选择功能实现相关的特征。
- **Loki 的加载方式**：Loki 从 `signature-base/yara` 目录加载 yara 规则，`loki.exe --onlyrelevant --noprocscan` 扫描目录文件，输出 `[WARNING] SCORE: 70` 与命中的字符串；也支持 Yara 扫进程内存。
- **内存检测互补**：无文件注入（PowerShell 反射加载到合法进程）时磁盘无样本，但运行时内存保留 `This is a ping!`（心跳）、`savePlugin`/`sendPlugin`（插件交互）等独有字符串，可自建内存 yara 规则扫描进程内存，Loki 按 PID 命中注入模块。
- **为什么需要双扫描**：静态文件规则对落地样本有效但抗不过无文件；内存规则能抓运行时但依赖进程存活与权限（System 权限可打开更多受保护进程）。

## 触发条件

- Windows 终端，具备 yara/Loki 工具（或自建扫描器）；
- 样本落地（静态扫描）或进程已加载 AsyncRAT 模块（内存扫描）；
- 内存扫描需足够权限打开目标进程（System/管理员）。

## 利用步骤

1. 准备 yara 规则：下载/编写 `RAT_AsyncRAT.yara`，放入 `loki/signature-base/yara/` 目录（文件规则）；另写内存规则（如 `AsyncRAT2`，strings 含 `This is a ping!`、`savePlugin`、`sendPlugin`）。
2. 静态扫描：`loki.exe -p <目录> --onlyrelevant --noprocscan > result.txt`，查看 `[WARNING] Yara Rule MATCH: AsyncRAT`、SCORE 与命中串。
3. 内存扫描：对可疑进程（或全进程）用 yara/Loki 扫描内存，确认 `Name/PID/PATH` 与命中规则；必要时以 System 权限运行以覆盖更多进程。
4. 命中后固定证据：记录文件哈希（MD5/SHA1/SHA256）、进程路径、命中规则与字符串。
5. 继续内存取证与配置提取（见关联卡）。

## PoC

```text
rule AsyncRAT2 : RAT
{
    meta:
        description = "AsyncRAT v0.5.8"
        date = "2024-01-31"
    strings:
        $suspicious01 = "This is a ping!" fullword wide
        $suspicious03 = "savePlugin" fullword wide
        $suspicious04 = "sendPlugin" fullword wide
    condition:
        any of them
}
```

```bat
loki.exe -p C:\Users\admin\Desktop\test\ --onlyrelevant --noprocscan >1.txt
:: 输出示例
:: [WARNING] FILE: ...\AsyncClient.exe SCORE: 70 TYPE: EXE
:: REASON_1: Yara Rule MATCH: AsyncRAT SUBS CORE: 70
:: MATCHES: Str1: MZ Str2: /c schtasks /create /f /sc onlogon /rl highest /tn " ...
```

```text
# 内存扫描命中示例（Loki 输出）
[ALERT] Yara Rule MATCH: AsyncRAT2 PID: 1220 NAME: vmtoolsd.exe ...
[ALERT] Yara Rule MATCH: AsyncRAT2 PID: 3320 NAME: AsyncClient.exe PATH: ...\AsyncClient.exe
```

## 变体与关联

- 变体：内存规则可加 `This is a ping!` 的宽字符/大小写变体、`Packet`/`Pong` 组合；不同版本字符串略有差异（高低版本心跳包不通用），规则应分版本。
- 关联：通用 Yara 内存狩猎方法 [[defense-detection-yara-memory-hunt-feature-authoring-batch-scan]]；AsyncRAT 心跳报文/协议特征 [[defense-detection-asyncrat-ping-heartbeat-replay-verify]]；默认 TLS 证书测绘 [[defense-detection-asyncrat-default-tls-cert-c2-mapping]]；命中后的内存配置提取 [[defense-forensics-asyncrat-memory-config-extract]]。
- 边界：Loki 0.x 的 yara 版本较老，复杂规则可能不兼容；内存扫描对短命进程/重启后失效。

## 检测与防御

- 检测：对终端定期跑双扫描（文件 + 内存）；监控 `schtasks /create /f /sc onlogon`、PowerShell 反射加载；将 AsyncRAT 家族字符串与 C2 配置加入 IOC 库。
- 防御：EDR/ASR 拦截计划任务自启动与反射加载；限制 PowerShell 与 .NET 程序集动态加载；内存扫描以 System 权限定期执行并留存证据。
