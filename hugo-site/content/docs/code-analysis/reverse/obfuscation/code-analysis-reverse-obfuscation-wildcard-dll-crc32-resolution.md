---
id: code-analysis-reverse-obfuscation-wildcard-dll-crc32-resolution
title: 不存 DLL 名字的动态解析：枚举 System32\*.dll 对每个文件名算 CRC32 匹配常量后 LoadLibraryW
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: wildcard-dll-enumeration-crc32-name-match
tags:
- windows
- malware-analysis
- latrodectus
- api-resolution
- crc32
- loadlibrary
- obfuscation
- win32
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:34:39+08:00'
  notes: 已对照图05核对：GetSystemDirectory + '*.dll' + FindFirstFileW/FindNextFileW 枚举、CountLengthWideStr(cFileName) 及 CRC32(cFileName, 2*n) 比较、命中 LoadLibraryW，与原文一致；PoC 原为 FindFirstFileA 且称实际混用 A/W，已按原图改为 FindFirstFileW/FindNextFileW 并修正说明；与 Dridex PEB 导出表 CRC32 hash 卡实现/触发不同，非重复；原文无版本；未复跑
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-wildcard-dll-crc32-resolution/
draft: false
kb_aliases:
- System32 通配枚举 DLL
- FindFirstFileW *.dll CRC32
- DLL 名哈希解析
- 无字符串 LoadLibrary
- 运行时库名模糊解析
---

## 一句话结论

样本不保存 `user32.dll`、`wininet.dll` 这类库名，而是 `GetSystemDirectory` 后拼出 `*.dll`，用 `FindFirstFileW`/`FindNextFileW` 枚举 System32 下所有 DLL，对每个文件名按宽字符字节数（字符数 ×2）计算 CRC32 与内嵌常量比较，命中后用 `LoadLibraryW` 加载该文件并返回模块句柄；这样静态字符串里看不到任何库名，且换系统目录/库集合也能自动适配。

## 原理

- **动机**：导入表和字符串都是静态检测与分析的高价值线索。把库名从字符串中移除，分析者只能看到一堆 CRC32 常量，增加定位成本。
- **实现**：`GetSystemDirectory()` 得到 `C:\Windows\System32`，用解密出的格式串 `*.dll` 拼成搜索路径；`FindFirstFileW`/`FindNextFileW` 遍历目录项，对每个 `cFileName` 求宽字符串长度 `n`，调用 `CRC32(cFileName, 2*n)`（按 UTF-16LE 字节计算），与目标常量比较；命中即 `LoadLibraryW(cFileName)`（相对当前目录/系统目录解析）并返回句柄，未命中则返回 0/错误。
- **与 API hash 的关系**：同一家族的 `kernel32.dll`/`ntdll.dll` 及函数名走 PEB + 导出表遍历 + CRC32；普通库则用本卡的目录枚举法——因为不需要遍历模块导出，只要能定位文件名即可加载，再 `GetProcAddress`。
- **为什么可行**：`CRC32` 只是 32 位弱校验，但库名集合固定且碰撞概率极低；遍历一次 System32 只有几百个 DLL，性能可接受。宽字符按 2 倍长度计算是为了覆盖 UTF-16 的每个字节。
- **可移植性**：路径来自 `GetSystemDirectory`，不硬编码盘符；库名列表以 CRC32 常量形式存在，换 Windows 版本也能匹配到同名文件。

## 触发条件

- Windows 用户态进程，能读 System32 目录并 `LoadLibraryW`。
- 样本中存在对 `*.dll` 的 `FindFirstFileW` 调用，且对文件名做 CRC32/哈希后再 `LoadLibraryW`。
- 需要还原样本使用了哪些系统库时，需要复现 CRC32 并反查字典（System32 的 DLL 名列表即可作为字典）。

## 利用步骤

1. 在 IDA 中定位 `FindFirstFileW`/`FindNextFileW` 调用，观察 `GetSystemDirectory` 与 `*.dll` 字符串的来源（常由字符串解密得到）。
2. 找到对 `cFileName` 计算哈希的函数调用，确认哈希算法（本例为 CRC32，输入长度为 `2 * wcslen`）。
3. 从调用点提取比较常量（寄存器/栈上的立即数）。
4. 用本地 System32 的 DLL 文件名列表逐个计算 `crc32(name.encode('utf-16le'))`，建立「常量→DLL 名」映射，批量反查。
5. 同理可反查后续 `GetProcAddress` 的 API hash 常量（若使用同一 CRC32 算法）。

## PoC

```python
import os, zlib

target = 0x????????  # 从样本比较指令中提取
sysdir = r"C:\Windows\System32"
for name in os.listdir(sysdir):
    if name.lower().endswith(".dll"):
        h = zlib.crc32(name.encode("utf-16le")) & 0xFFFFFFFF
        if h == target:
            print("matched DLL:", name)
```

样本侧逻辑等价于：

```c
GetSystemDirectoryW(dir, MAX_PATH);
wsprintfW(pattern, L"%s\\*.dll", dir);
h = FindFirstFileW(pattern, &fd);
do {
    if (crc32((BYTE *)fd.cFileName, 2 * (DWORD)wcslen(fd.cFileName)) == target)
        return LoadLibraryW(fd.cFileName);
} while (FindNextFileW(h, &fd));
```

（原文样本用 `FindFirstFileW`/`FindNextFileW` 枚举；CRC32 输入是宽字符文件名的 UTF-16LE 字节序列，所以长度取字符数 ×2。）

## 变体与关联

- 关联：本技巧出自 [[code-analysis-reverse-windows-latrodectus-loader-behavior-c2]]；该家族对 kernel32/ntdll 的导出走 PEB + CRC32。
- 关联：CRC32 API hash 的通用还原（带固定 XOR 的 Dridex 版本）见 [[code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key]]。
- 变体：可换成其他哈希（FNV-1a、djb2、ror13）或直接比较 DLL 导出表特征；也可能只枚举固定前缀（如 `win*.dll`）缩小范围。
- 变体：有的样本在内存中维护“已解析模块表”，避免重复枚举；分析时注意第二次调用直接返回缓存句柄的分支。

## 检测与防御

- 分析侧信号：非安装/更新程序调用 `FindFirstFileW("*.dll")` 并伴随 CRC32/哈希循环；随后 `LoadLibraryW` 的路径来自枚举结果而非字符串。
- 检测：监控进程对 System32 的批量目录枚举（相对少见）、从非常规模块发起的 `LoadLibraryW` 系统 DLL 加载、以及紧接着的 `GetProcAddress` 批量解析。
- 防御：该技巧不改变最终行为，行为检测（计划任务、rundll32 加载 AppData DLL、外联）仍是主要抓手；字符串/导入表清理只提高静态分析成本。
