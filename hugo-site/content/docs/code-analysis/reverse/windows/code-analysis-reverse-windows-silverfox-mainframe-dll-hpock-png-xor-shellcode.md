---
id: code-analysis-reverse-windows-silverfox-mainframe-dll-hpock-png-xor-shellcode
title: 银狐 mainframe.dll 侧加载：hpock.png 周期 XOR 解密 → NtProtectVirtualMemory 执行 Shellcode → RtlDecompressBuffer 展开载荷
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: silverfox-mainframe-dll-hpock-png-xor-shellcode
tags:
- windows
- malware-analysis
- silverfox
- dll-sideload
- png
- xor
- shellcode
- rtldecompress
- c2
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V423
  verified_at: '2026-11-09T16:54:40+08:00'
  notes: 已对照原文与32张图核对：YourPhone.exe PathFileExistsW+LoadLibraryW(mainframe.dll)(图11)、mainframe.dll(154KB,2024-04-17) GetModuleFileNameA+hpock.png+fopen/fread、44字节头/20字节周期XOR(i==44重置,v8>=20回绕)(图12-13)、NtProtectVirtualMemory(-1,&base,&size,0x40)(图15)、shellcode LoadLibraryA/GetProcAddress/RtlDecompressBuffer(图16)、解压PE导出fuckyou(图18)均一致。小瑕疵：图10 DIE为mainframe.dll(2024-04-17)，卡内将YourPhone.exe的2024-03-21文件时间写作'编译'，宜按文件时间理解；'宿主签名掩护'为推测原文未证实。未验证点：PoC未执行、头部/密钥算法未完全还原。无sources/文章ID/长段摘录，路径合法；dedup候选(qqmusic-ak-txt/two-stage/sogou等)非同链；dup-scan(11-08 19:10)早于建卡无涉及pair。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-silverfox-mainframe-dll-hpock-png-xor-shellcode/
draft: false
kb_aliases:
- YourPhone.exe mainframe.dll
- hpock.png 载荷
- 银狐侧加载
- NtProtectVirtualMemory 执行
- RtlDecompressBuffer 解压载荷
- fuckyou 导出
---

## 一句话结论

银狐样本二把白程序 `YourPhone.exe` 与恶意 `mainframe.dll`、伪装图片 `hpock.png` 放在同一目录：`YourPhone.exe` 用 `PathFileExistsW` 检查后 `LoadLibraryW("mainframe.dll")` 完成侧加载；`mainframe.dll` 读取同目录 `hpock.png`，按文件头参数与 20 字节周期密钥做 XOR 解密得到 Shellcode，动态解析 `NtProtectVirtualMemory` 把内存改为可执行并跳转；Shellcode 再用 `RtlDecompressBuffer` 解压内嵌载荷，最终模块导出 `fuckyou`。

## 原理

- **白加黑侧加载**：`YourPhone.exe` 是正常宿主，运行前判断同目录是否存在 `mainframe.dll`，存在则 `LoadLibraryW` 加载；Windows 加载器优先从 EXE 所在目录解析 DLL，因此同目录恶意 `mainframe.dll` 被拉起，宿主签名/文件名提供掩护。
- **PNG 作为加密容器**：`mainframe.dll` 由 `GetModuleFileNameA` 取得自身目录，拼出 `hpock.png` 并用 `fopen/fread` 整文件读入内存。文件名叫 PNG，但内容不是给图片解析器用的正常图片，而是“头部 + XOR 密文”的载荷容器；文件头前 44 字节被解析为参数（长度/密钥相关），密文从头部之后开始。
- **周期 XOR 解密**：反编译中可见按字节循环 `Buffer[i] ^= v2[v8++]`，密钥数组 `v2` 长度为 20，`v8 >= 20` 时回绕；偏移 44 处重置密钥索引（前 44 字节为头部）。因此解密是按 20 字节周期、带固定偏移的异或，密钥/头部参数来自文件本身而非独立配置。
- **动态解析 NtProtectVirtualMemory**：DLL 在栈上拼 `"NtProtectVirtualMemory"` 字符串，通过自写的模块/导出解析函数（`sub_10001010`/`sub_10001080` 一类）取得函数地址，随后以 `(-1, &base, &size, 0x40, &old)` 调用——`-1` 表示当前进程，`0x40` 为 `PAGE_EXECUTE_READWRITE`。使用 ntdll 原生 API 而非 `VirtualProtect`，可以避开对 kernel32 导入/API hook 的检测。
- **跳转执行与解压**：改保护后直接 `return ((int(*)(void))v7)()` 跳到解密出的缓冲区。Shellcode 通过 PEB/导出表自举 `LoadLibraryA`/`GetProcAddress`，调用 `RtlDecompressBuffer` 解压紧随其后的压缩载荷（x64dbg 中可见 `RtlDecompressBuffer` 解析与调用），再把解压结果作为下一阶段执行。
- **载荷导出 `fuckyou`**：解压后的 PE 导出表包含 `fuckyou`（ordinal 1）与 `DllEntryPoint`；导出名具有挑衅性，也作为家族/变种识别特征。核心远控能力与前序银狐变种一致，文章未展开完整功能。

## 触发条件

- 受害者运行 `YourPhone.exe`（或同类白宿主），且同目录存在 `mainframe.dll` 与 `hpock.png`。
- 目录可写/可读，进程允许分配可执行内存与调用 `NtProtectVirtualMemory`（未开启严格 ACG/CIG/内核代码完整性保护）。
- 分析侧：需要三件套样本与隔离环境；PNG 头部/密钥算法未完全在文中给出，需动态调试 dump。

## 利用步骤

1. 收集同目录文件：`YourPhone.exe`（258KB，2024-03-21 编译）、`mainframe.dll`（154KB，2024-04-17 编译，MSVC 14.37）、`hpock.png`（108KB），另有 `libcrypto-3.dll`/`libcurl.dll`/`librdkafka*.dll`/`libssl-3.dll`/`zlib1.dll`/`zstd.dll` 等依赖。
2. 静态分析 `YourPhone.exe`：定位 `PathFileExistsW` + `LoadLibraryW("mainframe.dll")` 的加载分支。
3. 分析 `mainframe.dll`：定位 `GetModuleFileNameA` + `"hpock.png"` 拼接、`fopen/fread` 读取、44 字节头部解析与 20 字节周期 XOR 循环。
4. x64dbg 在 `NtProtectVirtualMemory` 解析/调用处下断，观察 `0x40` 保护与跳转；在跳转目标 dump 解密后的 Shellcode。
5. 跟随 Shellcode 到 `RtlDecompressBuffer`，dump 解压后的 PE；用 PE 工具确认导出 `fuckyou`。
6. 提取 C2/配置（若后续阶段解密未还原则记录边界），把文件哈希、导出名与 20 字节密钥特征作为 IOC。

## PoC

```c
// 解密逻辑骨架（按反编译整理，非逐字原文）
BYTE *buf = read_file("hpock.png");
BYTE key[20] = { /* 由文件头/样本决定 */ };
int k = 0;
for (int i = 0; i < size; i++) {
    if (i == 44) k = 0;              // 44 字节头部之后重置
    buf[i] ^= key[k++];
    if (k >= 20) k = 0;
}
// 之后：解析 NtProtectVirtualMemory → (-1, &buf, &size, 0x40, &old) → jmp buf
```

```text
内存观察点：
  mainframe!NtProtectVirtualMemory 调用前：EAX/栈中出现 "hpock.png" 路径
  Shellcode 中：LoadLibraryA/GetProcAddress/RtlDecompressBuffer
  解压后 PE 导出：fuckyou (ordinal 1)、DllEntryPoint
```

## 变体与关联

- `hpock.png` 可换成其他图片/数据文件名；头部 44 字节与 20 字节密钥可按样本变化，需按反编译函数重新提取。
- 同类银狐变种也用 `RtlDecompressBuffer` 解压内嵌载荷（QQMusic/AK.txt、Inno/PNG 尾部 zlib 等），区别在于容器与解密算法。
- 关联：[[pentest-c2-silverfox-qqmusic-ak-txt-xor-decompress-upx-dll-loader]]（AK.txt 解密 + RtlDecompressBuffer + UPX DLL）、[[pentest-c2-silverfox-inno-dlclr-vmprotect-png-zlib-chain]]（PNG 尾部 zlib 容器）、[[code-analysis-reverse-windows-silverfox-cef-helper-dll-sideload-inflation]]（libcef 白加黑）、[[code-analysis-reverse-windows-silverfox-upx-http-txt-downloader-gh0st-memory]]（同篇下载器链）。
- 边界：头部/密钥算法未完全还原时无法离线解密；若 EDR 拦截 `NtProtectVirtualMemory` 或 ACG/CIG 启用，执行阶段失败。

## 检测与防御

- **主机**：监控同目录出现白宿主 + `mainframe.dll` + 图片文件的组合；`LoadLibraryW` 加载非系统目录 DLL；进程调用 `NtProtectVirtualMemory` 将匿名内存改为 RWX；内存中出现 `JeffcEn`/`fuckyou` 导出与 `RtlDecompressBuffer` 调用。
- **文件**：`hpock.png` 等“图片”文件头与内容熵异常（头部结构不符、尾部高熵）；对 `mainframe.dll` 做签名/哈希比对。
- **终端**：启用 ACG/CIG/CFG 与内核代码完整性；限制普通用户目录 DLL 侧加载；EDR 规则覆盖 `PathFileExists` + `LoadLibrary` + `NtProtectVirtualMemory` 链。
- **取证**：保留 `hpock.png`、`mainframe.dll`、`YourPhone.exe` 与进程内存；按 20 字节 XOR/头部参数离线还原 Shellcode，关联同源 C2。
