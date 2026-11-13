---
id: code-analysis-reverse-windows-silverfox-edge-xml-loader-mz-strip-jpg-shellcode
title: 银狐 edge.xml 加载器逆向：MZ 签名被破坏的 PE 伪装 xml，参数触发生成 CreateThread 线程并读取 edge.jpg shellcode 内存执行
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: silverfox-edge-xml-mz-strip-loader-jpg-shellcode
tags:
- reverse-engineering
- windows
- pe
- mz-strip
- shellcode
- silverfox
- loader
- scheduled-task
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V669
  verified_at: '2026-11-13T10:09:58+08:00'
  notes: 已对照原文与20张截图核对：edge.xml WinHex 首部 4D 1A 50 00（MZ 4D 5A 被破坏、DOS stub 仍在）、sub_10001000 中 CommandLineToArgvW/GetFullPathNameW/GetModuleHandle+GetProcAddress(CreateThread) 及 CreateThread(0,0,sub_10001000,...)、任务计划创建代码、CreateFileW→GetFileSize→LocalAlloc→ReadFile→sub_100019A0→sub_10002630 链与 sub_10002360(VirtualAlloc,...) 调用均属实。原文确实未给 edge.jpg 的提取/解密与 shellcode 协议，卡内已在边界与 PoC 说明中如实标注，confidence medium 合理。修正 exe/edge.xml 角色混淆表述（原文分析对象为 edge.xml，任务拉起的是随机 exe，二者衔接原文未展开）。未复跑样本
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-silverfox-edge-xml-loader-mz-strip-jpg-shellcode/
draft: false
kb_aliases:
- 银狐 edge.xml
- edge.jpg shellcode
- MZ 头去除
- MZ 签名破坏
- PE 伪装 xml
- CreateThread 加载器
- 图片 shellcode 内存执行
---

## 一句话结论

银狐变种把主加载器命名为 `edge.xml` 并破坏 PE 的 MZ 签名（示例首字节为 `4D 1A` 而非 `4D 5A`），使静态工具/安全软件不把它当 PE；修复头后可见它必须带参数运行（同目录计划任务以 `-d` 拉起随机名 exe），内部用 `CommandLineToArgvW`/`GetFullPathName` 处理参数、`GetModuleHandle("kernel32.dll")+GetProcAddress("CreateThread")` 创建线程，再打开文件读取内容（原文为 `edge.jpg`）经转换后交给带 `VirtualAlloc`/`LoadLibrary` 指针的执行函数，把 shellcode 装入内存运行，实现远控；计划任务负责持久化。

## 原理

- **MZ 签名破坏规避静态识别**：PE 文件以 `4D 5A`（MZ）开头，示例 `edge.xml` 在 WinHex 中为 `4D 1A 50 00 ...`，但 DOS stub 字符串 “This program cannot be run in DOS mode.” 仍在；把扩展名改为 `.xml` 且破坏签名后，按扩展名/PE 魔数匹配的检测与解析器都不会加载它，直到恢复 `0x5A` 才能用 IDA 等工具分析。
- **参数触发 + 线程执行**：反编译可见 `CommandLineToArgvW` 解析命令行（带引号时去引号）、`GetFullPathNameW` 取路径，名字为 `kernel32.dll`/`CreateThread` 的字符串用于 `GetModuleHandle`/`GetProcAddress`，随后 `CreateThread(0, 0, sub_10001000, arg, 0, 0)`；没有参数（如用户直接双击）不会走完整流程，同目录计划任务以 `-d` 参数拉起随机名 exe，保证执行环境正确，也增加沙箱误判。
- **读取图片内 shellcode**：代码用 `CreateFileW` 打开文件、`GetFileSize` + `LocalAlloc` + `ReadFile` 读入内存，随后 `sub_100019A0(buf, &size)` 做数据变换、`sub_10002630(buf, size)` 进入执行准备；`sub_10002630` 调用 `sub_10002360(Src, size, VirtualAlloc, ..., LoadLibrary, ..., ...)`，把 `VirtualAlloc`/`LoadLibrary` 等 API 指针传入，典型的 shellcode 内存加载/反射执行框架。
- **文件组合的分工**：`edge.xml` 是 PE 加载器（扩展名伪装 xml、MZ 被破坏），计划任务启动的随机名 exe 带 `-d` 参数，同名 `.dat` 为配套数据，`edge.jpg` 承载 shellcode/加密载荷（exe 与 xml 的具体加载衔接原文未展开）；把可执行代码藏在图片里可绕过按扩展名和文件类型的检测，且不落盘第二阶段 PE。
- **持久化**：计划任务在每次登录/开机时执行 `cmd /c cd <随机目录> && start <随机>.exe -d`，因此样本文件被删除后仍可能被任务重新拉起；分析时需同时记录任务命令行。
- **边界**：原文只展示关键反编译片段与文件结构，未给出 `edge.jpg` 的完整提取/解密脚本与 shellcode 协议；`sub_100019A0` 的变换算法与线程函数细节未公开，卡内按可见行为描述，confidence medium。

## 触发条件

- 主机出现 `edge.xml`（实为破坏 MZ 的 PE）+ `edge.jpg` + 随机名 exe/dat 的目录组合，且存在带 `-d` 参数的随机 exe 计划任务。
- 样本已被捕获，分析环境可对文件做十六进制编辑与 IDA 反编译。
- 需要还原加载器行为/提取 shellcode 时。

## 利用步骤

（以下为逆向分析步骤）

1. 用 file/WinHex 检查 `edge.xml`：PE 魔数异常但 DOS stub 存在；记录原始字节（示例 `4D 1A`）。
2. 复制样本，备份原始文件；把偏移 0x01 的 `0x1A` 改回 `0x5A`（恢复 `4D 5A`），保存为 `.exe`，确认 PE 工具可识别（必要时再校正校验和/其他被改字段）。
3. IDA 载入修复后的样本，查看导入表与字符串（`CommandLineToArgvW`、`kernel32.dll`、`CreateThread`），定位 main/线程函数 `sub_10001000`。
4. 分析命令行处理：确认必须参数（`-d`）与路径拼接逻辑（`GetFullPathNameW`）。
5. 跟踪文件读取链：`CreateFileW → GetFileSize → LocalAlloc → ReadFile → sub_100019A0 → sub_10002630`，确认读取的是 `edge.jpg` 及数据变换方式。
6. 分析 `sub_10002630/sub_10002360`：识别传入的 `VirtualAlloc`、`LoadLibrary` 等 API 指针与 shellcode 执行方式；用调试器在分配/执行点下断，dump 内存中的 shellcode。
7. 结合计划任务命令行（`-d`）与文件时间线，还原完整执行链并输出 IOC/YARA。

## PoC

```text
# 修复被破坏的 MZ 签名（示意）
原字节: 4D 1A 50 00 03 00 00 00 ...
修复后: 4D 5A 50 00 03 00 00 00 ...
# 偏移 0x01: 0x1A -> 0x5A，保存为 edge.exe 后用 IDA 打开
```

```c
// 关键反编译片段（按原文截图整理）
v4 = CommandLineToArgvW(CommandLine, &numArgs);      // 解析参数
if (*v4 == 34) { ... }                                // 去引号
GetFullPathNameW(v5, 0, 0, 0);
ModuleName = "kernel32.dll";
ProcName   = "CreateThread";
h = GetModuleHandleW(ModuleName);
pCreateThread = GetProcAddress(h, ProcName);
((... )pCreateThread)(0, 0, sub_10001000, arg, 0, 0); // 参数触发的线程执行

// 读取文件并执行（另一函数）
hFile = CreateFileW(path, 0x80000000, 1, 0, 3, 0x80, 0);
size  = GetFileSize(hFile, &sizeHigh);
buf   = LocalAlloc(0x40, size);
ReadFile(hFile, buf, size, &read, 0);
sub_100019A0(buf, &size);
sub_10002630(transformed, size);                      // 进入 shellcode 内存加载
```

说明：代码按原文截图重写为最小示意，未执行；`edge.jpg` 的 shellcode 提取与解密细节原文未给出。

## 变体与关联

- [[defense-incident-response-silverfox-edge-xml-jpg-random-task-cleanup]]：该变种在主机上的文件布局、计划任务与清理流程，与本卡互为处置/分析两侧。
- [[code-analysis-reverse-windows-corrupted-pe-driver-xor-ioctl-backtrack]]：同样需要修复 MZ 头并还原后续 XOR 变换的损坏 PE 分析，但对象是驱动/CTF 样本，机制不同。
- [[code-analysis-reverse-windows-pe-header-layout-locate]]：PE 头布局基础，可用于校验修复后的 e_lfanew/节表。
- [[code-analysis-reverse-obfuscation-silverfox-const-func-global-dce-bcf]] 等银狐混淆卡：同家族样本的控制流/字符串混淆分析。
- 变体：MZ 可能被替换为其他字节而非删除；加载器扩展名可换 `.jpg`/`.dat`/`.tmp`；shellcode 可能加密/压缩后再由 `sub_100019A0` 变换；参数可换其他开关。
- 边界：修复头后若仍有校验和/入口点被改动可能无法直接加载；运行时 dump 是提取 shellcode 的可靠兜底。

## 检测与防御

- 检测：非 PE 扩展名文件（xml/jpg/dat）中出现 `4D 5A` 或 `4D` 开头 + DOS stub 字符串 “This program cannot be run in DOS mode.”；PE 头 `e_magic` 不等于 0x5A4D 但具备 DOS stub/PE 结构。
- 检测：随机目录 exe 由计划任务带 `-d` 参数启动；进程读取同目录图片后出现可执行内存分配（VirtualAlloc RWX）与线程创建。
- 检测：YARA 规则匹配被破坏 MZ 的 PE（`uint16(0) == 0x1A4D` 或 `uint8(0)==0x4D && uint8(1)!=0x5A` 且含 DOS stub），并扫描 `edge.xml`/`edge.jpg` 组合。
- 防御：应用白名单限制 Public/Temp 目录执行；EDR 监控计划任务命令行与图片文件读取后的内存执行；对 IM 投递的 RAR/伪文档样本做沙箱与 PE 头异常检测。
- 响应：删除 loader 与任务，内存中 shellcode 用 EDR/内存扫描清理；按关联的应急处置卡完成主机清理与溯源。
