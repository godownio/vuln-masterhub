---
id: defense-forensics-asyncrat-memory-config-extract
title: AsyncRAT 内存取证：按配置结构特征（长度前缀+0x00000080+0x2C Key）定位提取配置，MegaDumper+dnspy 提模块
type: scenario
domain: defense
path: defense/forensics
technique: asyncrat-memory-config-structure-locate-extract
aliases:
- AsyncRAT 内存配置提取
- AsyncRAT 配置特征定位
- 00000080 2c000000 内存扫描
- MegaDumper dump .NET 内存马
- dnspy 提取 AsyncRAT Settings
- 无文件 AsyncRAT 取证
tags:
- asyncrat
- rat
- memory-forensics
- config-extraction
- megadumper
- dnspy
- yara
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V568
  verified_at: '2026-11-12T09:11:53+08:00'
  notes: 已对照原文12948及全部27张图逐张核对：配置结构(前4字节长度/前12字节0x00000080/Key 0x2C)、Go正则00000080.{8}2c000000与输出偏移0x4c41bc、Process Hacker dump、dbghelp MiniDump模板(图24)、0x4C40A0偏移处配置字段顺序(图26)、MegaDumper进程列表.NET dump菜单(图19)、Dumps/Stub.exe(图20)、dnspy Settings明文字段Anti/Aes256/Pastebin/BDOS/Hwid/Delay/Group(图21)均与卡片一致；未本机复现dump提取；dedup 20候选中无同链(均为其他RAT配置解密/dump定位类，sink不同)，无需删除。原文未声明受影响版本，未设versions。
---

## 一句话结论

AsyncRAT 以无文件方式注入合法进程时，可在进程内存/dump 中按配置结构特征定位配置：配置字符串前 4 字节为其长度、前 12 字节处固定为 `00 00 00 80`、Key 字符串长度固定 0x2C；用 hex 正则 `00000080.{8}2c000000` 扫描 dump 即可定位配置区并交解密脚本；也可先用 MegaDumper dump .NET 模块、再用 dnspy 直接读 Settings 字符串。

## 原理

- **内存中的配置结构**：AsyncRAT 客户端配置（`Settings` 类：Anti、Aes256、Pastebin、BDOS、Hwid、Delay、Group 等字符串）在进程内存里连续存放。观测到配置字符串前 4 字节存放该串长度、前 12 字节处有固定 4 字节标记 `0x00 0x00 0x00 0x80`；配置里的 Key（AES 密钥串）长度固定为 0x2C 字节。
- **为什么能定位**：这套"长度前缀 + 固定标记 + 固定长度 Key"形成了稳定指纹，与字符串内容无关，混淆/改变配置值不会破坏结构；因此适合在任意内存 dump 上做模式搜索。
- **两条提取路径**：
  1. 内存直接定位：Process Hacker 等工具 dump 进程内存 → 按上面特征写脚本扫描 → 找到 Key 串偏移 → 按反编译代码中字段顺序读取后续配置串 → 用 AsyncRAT 配置解密脚本解密。
  2. 模块 dump：用 MegaDumper 对注入进程（如 `aspnet_compiler.exe`）做 `.NET dump`，可直接还原 .NET 程序集为 `Stub.exe` 等文件；dnspy 打开即看到 `Settings` 类的明文字符串（配置），无需内存扫描。
- **适用场景**：AsyncRAT 常以 PowerShell 反射加载（`[Assembly]::Load` + `Invoke`）方式注入合法进程，磁盘无 PE 落地，传统文件扫描失效，必须内存取证。

## 触发条件

- 已在终端/内存中发现可疑进程（如合法进程被注入、无文件 PowerShell 加载痕迹）；
- 能获取进程内存（Process Hacker/任务管理器 dump、或全内存镜像）；
- 目标为 AsyncRAT 系（或其变体，配置结构同源）；
- 有可用的配置解密脚本（PBKDF2/AES 等，见相关卡）。

## 利用步骤

1. 用 Process Hacker 选中可疑进程，右键 `.NET dump`（或 dump 整个进程内存），得到 `.dmp` 文件。
2. 用脚本把 dump 转 hex，按正则 `00000080.{8}2c000000` 查找所有候选偏移。
3. 在命中偏移处查看：Key 串（base64，长度 0x2C）与其后按代码顺序排列的配置字段（Anti/Aes256/Pastebin/BDOS/Hwid/Delay/Group 等）。
4. 按 AsyncRAT 配置解密流程（PBKDF2 派生密钥 + AES/HMAC）解密各字段，得到 C2 地址、端口、密钥、互斥体等 IOC。
5. 若内存扫描困难，改用 MegaDumper：在进程列表选中目标 → `.NET dump` → 输出目录得到 `Stub.exe` 等模块 → dnspy 打开反编译，直接读取 `Settings` 字符串。

## PoC

```go
// 在 dump 中按配置结构特征定位（Go 示例，hex 字符串上做正则）
data := hex.EncodeToString(rawDump)
re := regexp.MustCompile("00000080.{8}2c000000")
for _, m := range re.FindAllStringIndex(data, -1) {
    start, end := m[0]/2, m[1]/2
    cfg := data[end*2 : end*2+0x2c*2*2] // 从命中点后读取 0x2C 字节 Key 及后续配置
    b, _ := hex.DecodeString(cfg)
    fmt.Printf("offset=0x%x %s\n", start, string(b))
}
```

```text
# 运行输出示例（节选）
起始索引: 0x4c41bc, 结束索引: 0x4c41c8
V c y M m R j R E V 0 a H Z W S W t 1 R T N D O D R D Q X Z T b D B X b k 9 k W H I =  ← 0x2C 的 base64 Key
```

## 变体与关联

- 变体：不同 AsyncRAT 变体（VenomRAT/DcRAT）配置布局基本同源，但 salt/密钥派生不同，定位后可套用对应解密脚本，见 [[code-analysis-reverse-windows-asyncrat-family-config-pbkdf2-salt-decrypt]]。
- 关联：内存扫描规则可用 Yara（见 [[defense-detection-asyncrat-loki-yara-file-memory-scan]] 与通用 Yara 内存狩猎卡）；内存镜像定位注入进程可配合 Volatility netscan/malfind。
- 关联：配置解密后得到 C2/密钥，可继续做流量解密与样本溯源（见 AsyncRAT 通信/心跳相关卡）。

## 检测与防御

- 检测：无文件 PowerShell 加载（`[Assembly]::Load`、`Invoke`、Base64 大段载荷）、合法进程（aspnet_compiler.exe 等）出现异常 .NET 模块/内存区域；对内存中的配置特征串做定期扫描；MegaDumper/dnspy 类取证记录留档。
- 防御：启用 PowerShell 日志与 AMSI、限制反射加载；EDR 监控进程内存中的 .NET 程序集加载；对 AsyncRAT 家族 IOC（配置中的 C2、互斥体）做阻断。
