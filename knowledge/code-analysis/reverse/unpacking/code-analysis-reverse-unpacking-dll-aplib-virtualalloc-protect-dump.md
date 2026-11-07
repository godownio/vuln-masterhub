---
id: code-analysis-reverse-unpacking-dll-aplib-virtualalloc-protect-dump
title: 32 位 DLL 样本手动脱壳：rundll32 导出加载 + VirtualAlloc/VirtualProtect 断点定位 aPLib 载荷并修复 PE
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: dll-aplib-virtualalloc-protect-dump
aliases:
- DLL 手动脱壳
- rundll32 调试 DLL
- VirtualAlloc 断点 dump
- VirtualProtect 断点
- aPLib M8Z
- 内存 dump 修复 PE
- Hancitor 脱壳
tags:
- reverse
- unpacking
- dll
- x32dbg
- virtualalloc
- virtualprotect
- aplib
- memory-dump
- pe-repair
- malware-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:41:38+08:00'
  notes: '已对照原文与21张图逐张核对：样本为 PE32 DLL（SHA256 8ff43b6d...，微步标 Hancitor），.data 原始 A00/虚拟 14264、.text/.reloc 熵 6.7；x32dbg 经 rundll32 导出序号 #1(Callrun) 加载，VirtualAlloc 返回/VirtualProtect 入口断点，第三次分配后转储区以 4D 38 5A("M8Z") 开头，010 Editor 搜到 4D 5A MZ 并截断前缀得到含 WININET 导入的 PE，与卡一致。未验证点：未本机复跑样本；原文用“搜 MZ 截断”处理 M8Z 转储，卡补充“M8Z 需 aPLib 解压或壳完成后 dump”的严格说明，实际该样本转储中确有内嵌 MZ/PE；无产品版本，未设 affected_versions；frontmatter 无 sources/source_url。'
---

## 一句话结论

对 32 位加壳 DLL，可用 `rundll32.exe <dll>,#<导出序号>` 以调试器启动，在 `VirtualAlloc` 返回点和 `VirtualProtect` 入口下断，借 `EAX` 返回的新内存地址找到解密后的载荷；若内存以 `M8Z` 开头说明是 aPLib 压缩数据，dump 后在十六进制编辑器中从 `MZ`/`PE` 头处截断前缀即可得到可静态分析的 PE。

## 原理

- 加壳 DLL 的入口先执行壳代码，真实载荷在运行时才被解密/解压到新内存；静态查看区段会看到 `.data` 等节 `原始大小` 远小于 `虚拟大小`，或 DIE 显示 `.text`/`.reloc` 高熵（原文约 6.7），提示存在压缩或加密壳。
- 壳必须先申请可写内存再写入明文：`VirtualAlloc` 的返回值（x86 的 `EAX`）就是新缓冲区地址。在函数**返回点**下断，可以直接拿到该地址，随后在内存窗口观察解密后的数据。
- 解密完成后，壳通常调用 `VirtualProtect` 把该区域改为 `PAGE_EXECUTE_READ`/`PAGE_EXECUTE_READWRITE` 再跳转执行。在 `VirtualProtect` **入口**下断，能卡在“载荷已解密、尚未执行”的窗口期。
- `ResumeThread` 常用于进程镂空（Process Hollowing）：先挂起合法进程、掏空并写入载荷，再恢复线程。对这类样本在 `ResumeThread` 下断可截获注入后的最终内存。
- 原文 dump 出的缓冲区以 ASCII `M8Z` 开头，这是 aPLib 压缩数据的特征；aPLib 解压后才是 PE。若直接 dump 到的是 `MZ` 开头的镜像，只需按 PE 头截断；若为 `M8Z`，需先按 aPLib 解压，或在壳完成解压后再 dump。
- dump 文件前面常带有壳的堆块头/对齐填充。用十六进制编辑器搜索 `MZ` 与 `PE\0\0`，删除第一个 `MZ` 之前的全部字节，即可恢复标准 PE；导入表中出现 `WININET.dll` 等网络 API，说明拿到的是具备实际功能的二阶段载荷。

## 触发条件

- 样本是 32 位 DLL（PE32），导出表存在自定义主函数（如 `Callrun`），可用导出序号或函数名经 `rundll32` 加载。
- 区段原始大小/虚拟大小明显不一致，或熵值显示压缩/加密节。
- 允许本地动态调试；样本无强反调试，或已绕过。
- 壳使用 `VirtualAlloc` + `VirtualProtect` 的常规内存展开方式；若是其他壳（如直接 `MapViewOfFile`、手工映射），需换用对应断点。

## 利用步骤

1. 用 PE-bear/PEStudio 查看区段：记录原始大小、虚拟大小、熵；用 DIE 确认疑似加壳。
2. 查看导出表，确认入口导出（原文为序号 1 的 `Callrun`）。
3. 在 x32dbg 中“文件 → 更改命令行”，以 `"C:\Windows\SysWOW64\rundll32.exe" <样本路径>,#1` 启动并重新加载调试会话；在系统断点/入口断点/TLS 回调处暂停。
4. 在 `VirtualAlloc`、`VirtualProtect`、`ResumeThread` 下断（`VirtualAlloc` 断在返回指令，`VirtualProtect` 断在函数入口）。
5. 多次 F9；每次 `VirtualAlloc` 返回时记录 `EAX`，在内存窗口跟踪该区域。原文第三次分配后命中 `VirtualProtect`，对应缓冲区开头出现 `M8Z`。
6. 右键内存区域 → “将内存转储到文件”，保存 dump。
7. 在 010 Editor 中搜索 `MZ`/`PE` 头，删除 `MZ` 之前的壳数据；若 dump 是 `M8Z`，先识别 aPLib 并解压，再重复截断。
8. 用 PE-bear 检查导入表与节表，确认可被 IDA 正常加载；随后分析主循环、网络 API 与配置解密逻辑。

## PoC

x32dbg 断点设置（命令行）：

```text
"<x32dbg路径>\x32dbg.exe" "C:\Windows\SysWOW64\rundll32.exe" "C:\samples\sample.dll",#1
```

```text
bp VirtualAlloc
bp VirtualProtect
bp ResumeThread
```

观察与 dump：

```text
# VirtualAlloc 返回时
EAX = 0x024D0000        ; 新分配缓冲区
# 在内存窗口转到 EAX，观察写入内容
# 命中 VirtualProtect 后，该区域开头为:
4D 38 5A ...            ; "M8Z"，aPLib 压缩数据
# 右键 → 将内存转储到文件 → dump.bin
# 010 Editor 搜索 4D 5A ("MZ")，删除之前的字节，另存为 unpacked.exe
```

## 变体与关联

- 变体：dump 出 `MZ` 镜像时可直接用 Scylla/ImpRec 修复 IAT，而不必手工截断；dump 出 `M8Z` 时需先 aPLib 解压。
- 变体：64 位样本改用 x64dbg，断点 API 相同；`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` 组合对应远程注入，需在目标进程内 dump。
- 变体：壳把载荷映射为映像而非明文块（`NtMapViewOfSection`、手工 PE 映射），需在跳转到 OEP 前用内存断点或硬件断点拦截。
- 关联：[[code-analysis-reverse-unpacking-upx-manual]]（UPX 的 OEP 定位与 IAT 修复）；[[code-analysis-reverse-unpacking-pe-loader-lcg-chacha20]]（二阶段 PE 解密与 `MZ` 校验）；[[code-analysis-reverse-obfuscation-cryptapi-sha1-rc4-config-decrypt]]（同一 Hancitor 样本的配置解密）。
- 关联：`ResumeThread` 断点也适用于进程镂空类样本，与内存 dump 思路一致。

## 检测与防御

- 检测（分析侧）：区段原始/虚拟大小差异、节熵 > 6.5、入口在非典型节、导入表极少但运行时解析 API，均可作为加壳线索。
- 检测（防御侧）：监控进程对自身或他人内存的 `VirtualAlloc`+`VirtualProtect` 组合、`WriteProcessMemory`+`ResumeThread` 组合；对 `rundll32` 加载非系统目录 DLL 且带导出序号的行为告警。
- 防御：加壳不是安全边界，敏感逻辑不应仅依赖壳；启用 CFG/ACG/CIG 等缓解，配合 EDR 的内存扫描与行为链检测。
- 响应：对可疑 DLL 在隔离环境完成 dump 与静态分析，提取 C2 配置与持久化行为后再清理。
