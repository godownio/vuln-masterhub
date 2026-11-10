---
id: code-analysis-reverse-windows-pe-header-layout-locate
title: PE 头布局定位链：e_magic/e_lfanew 找 NT 头，SizeOfOptionalHeader/NumberOfSections 定位节表并取入口与节区
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-header-layout-parsing
tags:
- reverse
- windows
- pe
- pe-header
- section-table
- parser
- malware-analysis
- triage
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T12:22:55+08:00'
  notes: 已对照原文与图01-11核对：MZ/0x5A4D、e_lfanew=0x100、PE 签名 0x4550、FileHeader Machine=14Ch/NumberOfSections=6/SizeOfOptionalHeader=0xE0、OptionalHeader Magic=10Bh/EP=1000h/ImageBase=400000h/SizeOfHeaders=400h、节表起始与 40 字节结构、入口=ImageBase+EP 均一致；解析器输出与截图吻合。卡中 PoC 未实跑。PE 基础解析卡，非漏洞链
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-pe-header-layout-locate/
draft: false
kb_aliases:
- PE 头结构
- IMAGE_DOS_HEADER
- e_lfanew
- IMAGE_NT_HEADERS
- IMAGE_FILE_HEADER
- IMAGE_OPTIONAL_HEADER
- IMAGE_SECTION_HEADER
- COFF 文件头
- 入口点 ImageBase+AddressOfEntryPoint
- 节表定位
---

## 一句话结论

PE 文件的头区是一条固定偏移链：文件偏移 0x00 的 `IMAGE_DOS_HEADER` 用 0x3C 处的 `e_lfanew` 指向 `IMAGE_NT_HEADERS`（4 字节 `PE\0\0` 签名 + `IMAGE_FILE_HEADER` + `IMAGE_OPTIONAL_HEADER`），节表紧跟在可选头之后；用 `IMAGE_FILE_HEADER.SizeOfOptionalHeader` 和 `NumberOfSections` 就能从任意 PE32/PE32+ 文件精确切出全部 `IMAGE_SECTION_HEADER`（每个 40 字节），并用 `ImageBase + AddressOfEntryPoint` 得到真正的代码入口。

## 原理

- **DOS 头是固定起点**：PE 文件最前面是 64 字节的 `IMAGE_DOS_HEADER`，`e_magic`（偏移 0x00，小端存储为 `4D 5A`，即 ASCII `MZ`）是文件签名；`e_lfanew`（偏移 0x3C，DWORD）保存 NT 头相对文件起始的偏移。DOS 头之后到 NT 头之间是可选的 DOS Stub（链接器写入的 16 位 DOS 程序，常打印 “This program cannot be run in DOS mode”），其内容和长度不固定，所以 NT 头位置不能写死，必须由 `e_lfanew` 决定。
- **NT 头签名与文件头**：`IMAGE_NT_HEADERS` 偏移 0 是 4 字节签名 `0x00004550`（字节序列 `50 45 00 00`，即 `PE\0\0`）；偏移 0x04 起是 20 字节的 `IMAGE_FILE_HEADER`：`Machine`（x86 为 0x14C，x64 为 0x8664）、`NumberOfSections`（节表项数）、`TimeDateStamp`、`PointerToSymbolTable`、`NumberOfSymbols`、`SizeOfOptionalHeader`（可选头字节数）、`Characteristics`（文件属性位，如可执行、DLL）。32 位与 64 位 PE 的 `IMAGE_FILE_HEADER` 布局相同。
- **可选头区分 PE32/PE32+**：`IMAGE_OPTIONAL_HEADER` 以 `Magic` 开头，0x10B 表示 PE32（结构大小 0xE0=224 字节），0x20B 表示 PE32+（0xF0=240 字节）。关键成员：`AddressOfEntryPoint`（相对 ImageBase 的 RVA，PE32 偏移 0x10）、`ImageBase`（PE32 偏移 0x1C 为 4 字节，PE32+ 偏移 0x18 为 8 字节）、`SectionAlignment`/`FileAlignment`（内存/文件对齐粒度）、`SizeOfImage`、`SizeOfHeaders`、`NumberOfRvaAndSizes`、`DataDirectory[16]`（PE32 偏移 0x60，PE32+ 偏移 0x70）。可选头在 32/64 位下字段宽度不同，解析必须按 `Magic` 分支。
- **节表的位置与结构**：节表起始偏移 = `e_lfanew + 4(签名) + 20(FileHeader) + SizeOfOptionalHeader`；共有 `NumberOfSections` 个 40 字节的 `IMAGE_SECTION_HEADER`。每项：`Name[8]`、`VirtualSize`（0x08，内存中大小）、`VirtualAddress`（0x0C，内存 RVA）、`SizeOfRawData`（0x10，磁盘中大小）、`PointerToRawData`（0x14，磁盘偏移）、`Characteristics`（0x24，可读/可写/可执行等属性位）。
- **入口点换算**：文件被加载时优先装入 `ImageBase`，代码首地址 = `ImageBase + AddressOfEntryPoint`；静态分析时把入口 RVA 换算成文件偏移：在节表中找到 `VirtualAddress <= RVA < VirtualAddress + max(VirtualSize, SizeOfRawData)` 的节，文件偏移 = `RVA - VirtualAddress + PointerToRawData`。这一步是后续解析导入表、重定位表、资源等所有目录的前提。

## 触发条件

- 需要在不依赖 `pefile`/IDA 的场合快速确认一个 Windows PE 文件（EXE/SYS/DLL）的架构、入口 RVA、节区布局与文件偏移映射，例如恶意样本 triage、脱壳后核对 dump、构造/修改 PE 前的字段定位。
- 拿到完整磁盘 PE 文件或已按镜像布局还原的内存 dump；样本未加壳或已脱壳（加壳样本的 NT 头/节表可能被压缩或篡改，直接按此链解析会得到异常节）。
- 明确目标位数：读取 `Magic`（0x10B/0x20B）决定 `IMAGE_OPTIONAL_HEADER` 的字段偏移与 `DataDirectory` 位置。

## 利用步骤

1. 读文件偏移 0x00 的 WORD，校验等于 `0x5A4D`（`MZ`）。
2. 读 0x3C 的 DWORD 得 `e_lfanew`，跳到该偏移校验 4 字节等于 `PE\0\0`（`0x00004550`）。
3. 读紧随其后的 `IMAGE_FILE_HEADER`：取 `Machine`、`NumberOfSections`、`SizeOfOptionalHeader`。
4. 读 `IMAGE_OPTIONAL_HEADER` 开头的 WORD 得 `Magic`，按 0x10B/0x20B 选择字段偏移；取 `AddressOfEntryPoint`、`ImageBase`、`SizeOfHeaders`、`Subsystem`、`DataDirectory`。
5. 以 `e_lfanew + 24 + SizeOfOptionalHeader` 为起点，循环 `NumberOfSections` 次、每次前进 40 字节，读取每个节的名字、`VirtualSize`、`VirtualAddress`、`SizeOfRawData`、`PointerToRawData`、`Characteristics`。
6. 计算入口的虚拟地址 `ImageBase + AddressOfEntryPoint`，并按第 5 步节表把入口 RVA 换算为文件偏移，用于后续静态定位；异常值（节数过大、节表越界、入口不在任何节内）提示样本被篡改/加壳，需要换动态 dump 或先脱壳。

## PoC

无漏洞利用 PoC；以下为按文章字段布局重写的最小解析脚本（未实跑），输出 DOS/NT/可选头关键字段与全部节表。

```python
import struct

def parse_pe(path):
    d = open(path, "rb").read()
    assert d[:2] == b"MZ", "not MZ"
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    assert d[e_lfanew:e_lfanew+4] == b"PE\0\0", "not PE"
    fh = e_lfanew + 4
    machine, nsec, _, _, _, size_opt, chars = struct.unpack_from("<HHIIIHH", d, fh)
    opt = fh + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    is64 = magic == 0x20B
    ep     = struct.unpack_from("<I", d, opt + 0x10)[0]
    image_base = struct.unpack_from("<Q" if is64 else "<I", d, opt + (0x18 if is64 else 0x1C))[0]
    size_hdr   = struct.unpack_from("<I", d, opt + 0x3C)[0]
    subsystem  = struct.unpack_from("<H", d, opt + 0x44)[0]
    dd_off     = opt + (0x70 if is64 else 0x60)
    dd = [struct.unpack_from("<II", d, dd_off + i*8) for i in range(16)]
    sec_off = opt + size_opt
    secs = []
    for i in range(nsec):
        o = sec_off + i*40
        name = d[o:o+8].rstrip(b"\0").decode("latin1")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", d, o+8)
        secs.append((name, vsize, va, rsize, rptr))
    print(f"arch={'x64' if is64 else 'x86'} machine=0x{machine:X} nsec={nsec} "
          f"entry_va=0x{image_base+ep:X} size_headers=0x{size_hdr:X} subsystem={subsystem}")
    for s in secs:
        print("section", s)
    return image_base, ep, dd, secs

def rva_to_off(rva, secs):
    for name, vsize, va, rsize, rptr in secs:
        if va <= rva < va + max(vsize, rsize):
            return rva - va + rptr
    raise ValueError(hex(rva))

# parse_pe("CRACKME.EXE")
```

## 变体与关联

- 变体：PE32+ 的 `ImageBase` 为 8 字节、`DataDirectory` 在可选头 0x70，沿用 PE32 偏移会把 `ImageBase` 高 4 字节读进 `SectionAlignment`，导致入口换算错误。
- 变体：加壳/损坏样本的 `NumberOfSections`、`SizeOfOptionalHeader` 可能被改大或指向文件尾，解析前应对节表起点+40*节数做文件边界校验；异常 PE 常作为反分析/规避手段。
- 变体：DOS Stub 可被链接器或人工任意修改/挪用（例如把 DOS 头当作可执行指令或承载数据），因此只能信 `e_lfanew`，不能假设 Stub 固定长度或内容。
- 关联：[[code-analysis-reverse-windows-pe-import-reloc-parser]]（在本链基础上继续解析导入表/重定位表）；[[code-analysis-reverse-windows-pe-text-code-cave-call-rel32-patch]]（用节表定位 `.text` 代码洞）；[[code-analysis-reverse-windows-pe-tls-callback-pre-oep]]（用可选头/目录定位 TLS 回调）；[[code-analysis-reverse-windows-mz-no-embedded-pe-xor-shellcode]]（MZ/PE 特征定位内嵌 PE）。

## 检测与防御

- 检测：静态分析侧，PE 头字段异常（`e_lfanew` 越界、签名缺失、节数/可选头大小与文件长度不符、节表重叠、入口 RVA 不在任何节内、节名为空/畸形）常是加壳、篡改或恶意构造的迹象，可作为样本 triage 的规则；对同一文件分别按磁盘/内存镜像解析并对比，可发现内存中改写 PE 头的规避手法。
- 防御：自写 PE 解析器必须做边界与循环上限校验（`e_lfanew` 在文件内、`NumberOfSections` 合理、`SizeOfOptionalHeader` 不超过剩余文件、按 `Magic` 分支读取字段），避免解析恶意 PE 时越界读/崩溃；分析不可信样本应在隔离环境进行。
- 说明：本文是 PE 格式基础解析技术，不是漏洞利用链，severity 记为 low。
