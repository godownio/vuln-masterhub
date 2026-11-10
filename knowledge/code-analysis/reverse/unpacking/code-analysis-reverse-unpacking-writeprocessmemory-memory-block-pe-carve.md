---
id: code-analysis-reverse-unpacking-writeprocessmemory-memory-block-pe-carve
title: WriteProcessMemory 断点抓进程替换最终载荷 + 内存块 PE 雕刻：DOS Stub 串回退 0x4E 定位 PE 头、末节算大小、SHA256 去重与尾部 16 字节零校验
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: writeprocessmemory-breakpoint-memory-block-pe-carve
aliases:
- WriteProcessMemory 断点抓载荷
- 进程替换最终载荷提取
- 内存块 PE 雕刻
- DOS Stub 定位 PE 头
- This program cannot be run in DOS mode
- 0x4E 回退
- 内存 dump 批量还原 PE
- AgentTesla 载荷提取
tags:
- reverse
- unpacking
- windows
- memory-dump
- pe-carving
- writeprocessmemory
- process-hollowing
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V306
  verified_at: '2026-11-08T12:07:59+08:00'
  notes: 已对照原文与 img01-06 核对：WriteProcessMemory 断点 lpBuffer=0x040182B0、保存 032E0000 内存块、DOS Stub 串-0x4E、最后一节 Size+Offset 算大小、SHA256 去重+末尾 16 字节全 0、候选偏移 0x94d0/0xc03cc0/0xc81ae0/0xcff900/0xd3bb20 及 InternalName bfb5da9f-...exe/Tyrone.dll 均与图和原文代码一致；卡内 Python 为按文章逻辑重写、未对样本实跑
---

## 一句话结论

对采用进程替换（hollowing）的木马，在 `WriteProcessMemory` 下断点即可在写入前拿到最终载荷指针 `lpBuffer`；直接保存整块内存后，用 DOS Stub 字符串 `This program cannot be run in DOS mode` 的出现位置减去 0x4E 得到候选 PE 头偏移，再按最后节的 `PointerToRawData + SizeOfRawData` 算出文件大小、用“末尾 16 字节全 0”过滤伪 PE 头、用 SHA256 去重，就能从大块内存中批量还原出可直接反编译/分析的最终 PE。

## 原理

- **为什么断 WriteProcessMemory**：进程替换类加载器会先创建挂起进程/分配内存，再调用 `WriteProcessMemory` 把解密后的最终 PE 写进目标进程，随后改入口/恢复线程。此时 `lpBuffer` 指向待写入的 PE 数据，是“写之前”的明文载荷，绕过了解密算法复现与密钥获取；比在内存中盲目搜索 PE、或动态调试多阶段解密更稳定。
- **为什么直接保存整块内存**：`lpBuffer` 往往位于一块较大的私有内存中间（分配基址如 0x032E0000，载荷在 `lpBuffer=0x040182B0`），同一内存块还可能混有其他 PE/数据。OllyDbg/调试器对 `lpBuffer` 直接“保存数据到文件”只能从指针处导出，长度需要手工判断；更方便的是从内存块基址保存整块 `.mem`，再离线雕刻。文章样本把 0x032E0000 起的整块内存保存为 `032E0000.mem`。
- **为什么用 DOS Stub 串回退 0x4E**：标准 PE 的 DOS 头为 0x40 字节，DOS Stub 从 0x40 开始；链接器写入的提示串 `This program cannot be run in DOS mode` 在 Stub 内偏移固定为 0x0E，因此该串在 PE 文件中的偏移是 0x40 + 0x0E = 0x4E。在未知内存块中搜到该串，减去 0x4E 就是候选 PE 起始；再校验 `MZ`/`e_lfanew`/`PE\0\0` 可排除大部分误报。该串不是 PE 规范强制内容（Stub 可被改写），但对未刻意擦除 Stub 的样本命中率很高；若样本改了 Stub，可改用 `MZ` + `e_lfanew` 指向的 `PE\0\0` 双特征扫描。
- **为什么用最后节算大小**：PE 文件在磁盘上的大小并不等于 `SizeOfImage`（内存镜像大小）；对完整 dump 的 PE，文件末尾通常等于最后一个节的 `PointerToRawData + SizeOfRawData`（节按文件对齐）。用 Go `debug/pe` 或自写结构解析取最后节即可得到候选长度；若 PE 头部之后其实不是真载荷（只有头是正常的），长度会异常，需要过滤。
- **两个过滤条件**：① 候选载荷末尾 16 字节全 0（节对齐填充常见形态）；② 对候选整体算 SHA256，只保留首次出现的 hash，避免同一载荷在内存块中重复出现（多份映射/拷贝）。文章样本用这两个条件把 0x94d0、0xc03cc0、0xc81ae0、0xcff900、0xd3bb20 等多个候选筛成有效 PE（如 InternalName 为 GUID 形式 `.exe` 的最终载荷、以及 `Tyrone.dll` 等阶段 DLL）。
- **局限**：若加载器不用 `WriteProcessMemory`（如 `NtMapViewOfSection` 映射、`CreateRemoteThread`+`VirtualAllocEx` 写、或直接在自身进程解密执行），需要改断对应 API；若载荷被分片写入/边写边解密，单次 `lpBuffer` 可能只是片段；若 Stub 被改或节表被破坏，则需改用更鲁棒的 PE 扫描/重建。

## 触发条件

- 样本采用进程替换/ hollowing 或类似“分配内存 + WriteProcessMemory 写入最终 PE + 改入口”的加载方式，且加载器在写入时未加密（明文 PE 在 `lpBuffer`）。
- 能在调试器中运行样本（OllyDbg/x64dbg）并对其 API 下断；样本反调试不过强，或可在隔离环境绕过。
- 已获得可写出的内存块（从 `lpBuffer` 所在分配基址或整段进程内存保存），并能在离线环境解析 PE。
- 目标是批量 triage：需要快速从大量样本中提取最终载荷，而不是精确复现每一层解密算法/密钥。

## 利用步骤

1. 调试器加载样本，`Ctrl+N`/符号栏找到 `WriteProcessMemory`，下 `BPX WriteProcessMemory`；F9 运行到断点。
2. 断下后查看调用栈与参数：`hProcess`、`lpBaseAddress`、`lpBuffer`、`nSize`。用 Process Hacker/任务管理器确认目标进程（样本可能创建了同名/伪装进程），记录 `lpBuffer` 与所属内存分配基址。
3. 在内存窗口跳到分配基址（如 0x032E0000），右键“保存数据到文件”，保存整块 `.mem`；若只想取载荷，也可从 `lpBuffer` 起按 `nSize`/PE 结构保存。
4. 离线扫描 `.mem`：搜索 `This program cannot be run in DOS mode`，对每个命中位置 `pos` 取候选起点 `pos-0x4E`；校验 `MZ`、`e_lfanew`、`PE\0\0`。
5. 解析候选 PE：读节数/可选头大小，遍历节表，取最后一节的 `PointerToRawData + SizeOfRawData` 作为候选长度；截取候选。
6. 过滤：候选末尾 16 字节必须全 0；对候选算 SHA256，跳过已出现过的 hash；对保留的候选写出为独立文件（文件名可带内存偏移）。
7. 用 PE 工具（PEview/DIE/dnSpy）确认类型与 InternalName；对 .NET 载荷继续反编译提取配置（可衔接批量 ilspycmd + 正则配置抽取流程）。

## PoC

无漏洞利用 PoC；以下为按文章逻辑重写的内存块 PE 雕刻脚本（未对样本实跑）。

```python
import hashlib, re, struct, sys
from pathlib import Path

STUB = b"This program cannot be run in DOS mode"

def pe_size(d, off):
    if d[off:off+2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", d, off + 0x3C)[0]
    nt = off + e_lfanew
    if d[nt:nt+4] != b"PE\0\0":
        return None
    nsec, size_opt = struct.unpack_from("<H", d, nt + 6)[0], struct.unpack_from("<H", d, nt + 20)[0]
    sec = nt + 24 + size_opt
    end = 0
    for i in range(nsec):
        o = sec + i * 40
        raw_size, raw_ptr = struct.unpack_from("<II", d, o + 0x10)
        end = max(end, raw_ptr + raw_size)
    return end or None

def carve(mem_path, out_dir):
    d = Path(mem_path).read_bytes()
    out = Path(out_dir); out.mkdir(exist_ok=True)
    seen = set()
    for m in re.finditer(re.escape(STUB), d):
        off = m.start() - 0x4E
        if off < 0:
            continue
        size = pe_size(d, off)
        if not size or off + size > len(d):
            continue
        cand = d[off:off+size]
        if cand[-16:] != b"\0" * 16:          # 末尾 16 字节全 0
            continue
        h = hashlib.sha256(cand).hexdigest()
        if h in seen:                          # 载荷去重
            continue
        seen.add(h)
        (out / f"{Path(mem_path).stem}_off_0x{off:x}.bin").write_bytes(cand)
        print(f"PE off=0x{off:x} size=0x{size:x} sha256={h}")

if __name__ == "__main__":
    carve(sys.argv[1], "output")
```

## 变体与关联

- 变体：若找不到 DOS Stub 串（Stub 被改/擦除），改为全内存扫描 `MZ`，对每个 `MZ` 校验 `e_lfanew` 在合理范围且 `PE\0\0` 命中；或按 `SizeOfImage`/节表重建。
- 变体：加载器使用 `NtWriteVirtualMemory`、`NtMapViewOfSection`、`RtlMoveMemory` 或直接在自身进程解密时，断点应换成对应 API/内存写入点；也可在 `VirtualAllocEx`/`VirtualProtect` 返回后 dump。
- 变体：候选 PE 只有头部正常、后续不是真实载荷（内存中残留的其他模块头）时，可增加节内容熵、入口点是否落在可执行节、导入表是否可解析等校验。
- 关联：[[code-analysis-reverse-unpacking-dll-aplib-virtualalloc-protect-dump]]（VirtualAlloc/VirtualProtect 断点 dump 并修复 PE）、[[code-analysis-reverse-unpacking-speakeasy-memory-dump-base64-pe]]（仿真 dump 内存定位内嵌 PE）、[[code-analysis-reverse-windows-pe-header-layout-locate]]（PE 头/节表定位基础）、[[code-analysis-reverse-windows-pe-import-reloc-parser]]（PE 结构解析）。

## 检测与防御

- 检测：EDR 可监控跨进程 `WriteProcessMemory` 写 PE 头（目标内存出现 `MZ`/`PE` 特征）、随后改线程上下文/入口的行为；内存扫描可检测私有可执行内存中的 PE 头与 DOS Stub；对已知加载器可匹配其进程替换调用序列。
- 防御：启用 ETW/内核回调（PsSetCreateProcessNotifyRoutineEx、ObRegisterCallbacks）与内存扫描；对调试器/API 断点做反调试；加载器侧可擦除 DOS Stub/PE 头、分片写入以对抗此类雕刻。
- 说明：本文针对恶意样本的动态提取/分析技术，severity 记为 low；仅在授权样本分析环境使用。
