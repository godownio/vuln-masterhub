---
id: code-analysis-reverse-windows-pe-import-reloc-parser
title: PE 导入表与基址重定位解析：ILT/IAT/绑定导入与 .reloc 块遍历
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-import-reloc-parsing
tags:
- reverse
- windows
- pe
- import-table
- iat
- ilt
- base-relocation
- parser
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T09:52:52+08:00'
  notes: 已对照原文与3张图核对：导入目录表 IMAGE_IMPORT_DESCRIPTOR 字段、ILT/IAT 与绑定导入语义、ILT 32/64 位项最高位名称/序号标志、IMAGE_IMPORT_BY_NAME、IMAGE_BASE_RELOCATION 4KB 页/8字节头/项数=(SizeOfBlock-8)/2/高4位类型低12位偏移、RVA→文件偏移算法均与文章一致；图01导入表(MSVCP140/VCRUNTIME/api-ms-win-*/KERNEL32，ILT≠IAT)、图02重定位(0x5000 size 0x7C 项数 0x3A；0x9000 size 0x28 项数 0x10)、图03 Parser 输出均吻合。卡片 Python PoC 为作者按文章结构重写，未实跑；已核对结构体偏移与字段宽度无明显错误。原文 C++ Rich Header 判断有 'if (tmpchar[1] = 0x61 ...)' 赋值笔误，卡片未沿用。未验证点：PoC 未在本机样本运行；frontmatter 无 sources/source_url；本文为解析技术教程非漏洞，无 affected_versions 合理。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-pe-import-reloc-parser/
draft: false
kb_aliases:
- PE 导入表解析
- IMAGE_IMPORT_DESCRIPTOR
- ILT IAT 区别
- 基址重定位表解析
- IMAGE_BASE_RELOCATION
- 手写 PE Parser
- RVA 转文件偏移
---

## 一句话结论

PE 的导入信息由 `DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]` 指向的 `IMAGE_IMPORT_DESCRIPTOR` 数组描述，每项给出 DLL 名、ILT（`OriginalFirstThunk`）和 IAT（`FirstThunk`），ILT 项最高位区分“按名称”还是“按序号”导入；基址重定位由 `DataDirectory[BASERELOC]` 指向的 `IMAGE_BASE_RELOCATION` 块数组描述，每块对应一个 4KB 页，16 位项的高 4 位是类型、低 12 位是页内偏移；按 RVA→文件偏移换算即可手写解析器提取这两类信息。

## 原理

- **导入目录表**：`.idata` 起始处是 `IMAGE_IMPORT_DESCRIPTOR` 数组，每个成员对应一个被导入 DLL；数组以全 0 成员结束。字段：
  - `OriginalFirstThunk`：ILT（导入查询表/导入名称表）RVA；
  - `TimeDateStamp`：0 表示未绑定导入，-1 表示绑定导入（真实 DLL 时间戳在绑定导入目录）；
  - `ForwarderChain`：转发链索引；
  - `Name`：DLL 名字符串的 RVA；
  - `FirstThunk`：IAT（导入地址表）RVA。
- **ILT/IAT**：PE 文件中 IAT 初始内容通常等于 ILT；加载时 PE Loader 用解析出的真实函数地址覆盖 IAT。链接器可启用 IAT 分离优化，把 IAT 放 `.data`（可写）、ILT 放 `.rdata`（只读），二者不再相等。ILT 本质是“要导入哪些函数”的记录，IAT 是“加载后函数真实地址”的存储。
- **ILT 项格式**：32 位 PE 每项 4 字节，64 位每项 8 字节；最高位（Bit 31/Bit 63）为序号/名称标志：
  - 为 1：低 16 位是序号（Ordinal），按序号导入；
  - 为 0：低 31/63 位是 `IMAGE_IMPORT_BY_NAME` 的 RVA，结构为 `WORD Hint; CHAR Name[];`（Hint 用于在导出名称表中快速定位，失败则二分查找）。
- **绑定导入**：链接期预先计算并写入函数地址，减少加载时解析；若 DLL 版本变化导致地址不匹配，Loader 仍会重新计算。绑定导入目录是 `IMAGE_BOUND_IMPORT_DESCRIPTOR` 数组，`OffsetModuleName` 是相对于该结构起始的偏移。
- **基址重定位**：编译器按 `ImageBase` 生成硬编码地址；ASLR 等机制使实际加载基址变化时，需要修复这些地址。`.reloc` 由多个 4 字节对齐的 `IMAGE_BASE_RELOCATION` 块组成，以全 0 块结束；每块：
  - `VirtualAddress`：对应 4KB 页的 RVA；
  - `SizeOfBlock`：块总大小（含 8 字节头）；
  - 块项数 = `(SizeOfBlock - 8) / 2`；每个 WORD 项高 4 位为重定位类型（如 `IMAGE_REL_BASED_HIGHLOW`=3 表示修正 32 位地址），低 12 位为页内偏移；
  - 需要修复的地址 = 实际加载基址 + `VirtualAddress` + 低 12 位偏移；修复值通常加上“实际基址 - 期望基址”的差值。
- **RVA→文件偏移**：遍历节表，找到 `VirtualAddress <= RVA < VirtualAddress + VirtualSize` 的节，文件偏移 = `RVA - VirtualAddress + PointerToRawData`；解析导入表/重定位表前必须做这一步，否则 `fseek` 会读到错误位置。

## 触发条件

- 需要分析 Windows PE32/PE32+ 样本的导入函数、DLL 依赖、绑定导入或重定位信息（恶意样本 triage、IAT Hook 排查、脱壳后重建、漏洞利用中的 ROP/gadget 定位）。
- 有完整 PE 文件（磁盘文件或内存 dump 转换后的镜像）与节表信息。
- 了解目标 PE 是 32 位还是 64 位（Optional Header `Magic`：0x10b/0x20b），以选择 4/8 字节 ILT 项和正确的 DataDirectory 偏移。
- 样本未加壳或已脱壳；加壳样本的导入表可能被压缩/加密，需要先脱壳或动态 dump。

## 利用步骤

1. 读取 DOS Header，校验 `e_magic == 0x5A4D`，取 `e_lfanew`。
2. 在 `e_lfanew` 处读 NT Headers：校验 `Signature == 0x00004550`，读 FileHeader（节数、可选头大小）和 OptionalHeader（Magic、ImageBase、DataDirectory）。
3. 读节表，建立 RVA→文件偏移的映射函数。
4. 取 `DataDirectory[1]`（Import）的 RVA，遍历 `IMAGE_IMPORT_DESCRIPTOR` 直到全 0：
   - 读 DLL 名（`Name` RVA）；
   - 记录 ILT RVA、IAT RVA、`TimeDateStamp` 判断绑定导入；
   - 遍历 ILT 项：按最高位判断名称/序号；名称为 0 表示结束；名称导入读取 `Hint` 与以 null 结尾的函数名。
5. 取 `DataDirectory[5]`（BaseReloc）的 RVA，遍历 `IMAGE_BASE_RELOCATION` 块直到全 0：
   - 记录页 RVA、块大小、项数；
   - 逐项解析类型与页内偏移，计算修复地址。
6. 输出/比对：磁盘 ILT 与运行时 IAT 的差异可用于发现 IAT Hook；重定位块的异常页/类型可用于发现注入或畸形 PE。

## PoC

```python
import struct

def rva_to_off(rva, sections):
    for va, vsize, raw_ptr, raw_size in sections:
        if va <= rva < va + max(vsize, raw_size):
            return rva - va + raw_ptr
    raise ValueError(f"RVA 0x{rva:X} not in any section")

def parse_pe(path):
    data = open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew+4] == b"PE\0\0"
    machine, nsec = struct.unpack_from("<HH", data, e_lfanew+4)
    size_opt = struct.unpack_from("<H", data, e_lfanew+20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    dd_off = opt + (112 if is64 else 96)
    image_base = struct.unpack_from("<Q" if is64 else "<I", data, opt + (24 if is64 else 28))[0]
    import_rva = struct.unpack_from("<I", data, dd_off + 1*8)[0]
    reloc_rva  = struct.unpack_from("<I", data, dd_off + 5*8)[0]

    sec_off = opt + size_opt
    sections = []
    for i in range(nsec):
        o = sec_off + i*40
        name = data[o:o+8].rstrip(b"\0").decode(errors="replace")
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, o+8)
        sections.append((va, vsize, raw_ptr, raw_size))

    # 导入表
    off = rva_to_off(import_rva, sections)
    imports = []
    while True:
        oft, tds, fwd, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if oft == name_rva == ft == 0:
            break
        dll = data[rva_to_off(name_rva, sections):].split(b"\0", 1)[0].decode(errors="replace")
        ilt = rva_to_off(oft, sections)
        entry_size = 8 if is64 else 4
        fmt = "<Q" if is64 else "<I"
        high = 1 << (63 if is64 else 31)
        funcs = []
        while True:
            val = struct.unpack_from(fmt, data, ilt)[0]
            if val == 0:
                break
            if val & high:
                funcs.append(("ordinal", val & 0xFFFF))
            else:
                hint_name = rva_to_off(val & (high - 1), sections)
                hint = struct.unpack_from("<H", data, hint_name)[0]
                fname = data[hint_name+2:].split(b"\0", 1)[0].decode(errors="replace")
                funcs.append((fname, hint))
            ilt += entry_size
        imports.append((dll, funcs, tds == 0xFFFFFFFF))
        off += 20

    # 基址重定位
    off = rva_to_off(reloc_rva, sections)
    relocs = []
    while True:
        page_rva, block_size = struct.unpack_from("<II", data, off)
        if page_rva == 0 and block_size == 0:
            break
        count = (block_size - 8) // 2
        entries = []
        for i in range(count):
            w = struct.unpack_from("<H", data, off + 8 + i*2)[0]
            entries.append((w >> 12, w & 0xFFF, page_rva + (w & 0xFFF)))
        relocs.append((page_rva, block_size, entries))
        off += block_size
    return image_base, imports, relocs

image_base, imports, relocs = parse_pe("sample.exe")
print(hex(image_base), imports, relocs)
```

## 变体与关联

- 变体：IAT 分离优化（IAT 在 `.data`、ILT 在 `.rdata`）导致 `OriginalFirstThunk != FirstThunk`，解析时不能假设二者相等。
- 变体：绑定导入需额外解析 `DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]`；延迟导入使用 `DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]` 与 `ImgDelayDescr`，结构不同。
- 变体：加壳/加密导入表需要先脱壳或从内存 dump 读取；畸形 PE 需做边界校验，避免解析器越界。
- 关联：[[code-analysis-reverse-windows-iat-hook-install-messagebox]]（用导入表定位 IAT 槽安装 Hook）、[[code-analysis-reverse-windows-iat-hook-lstrcmp-xxtea]]（IAT Hook 识别）、[[code-analysis-reverse-windows-pe-text-code-cave-call-rel32-patch]]（PE 节表与代码洞）、[[code-analysis-reverse-windows-pe-tls-callback-pre-oep]]（PE 目录/回调）。
- 边界：PE32/PE32+ 的 DataDirectory 偏移、ILT 项宽度、ImageBase 宽度不同；解析前必须按 Magic 分支。

## 检测与防御

- 检测：对比磁盘 ILT 与运行时 IAT，发现被替换的函数地址（IAT Hook）；检查重定位表是否指向异常页/类型，或 `.reloc` 被清空/伪造；检查导入表是否包含异常 DLL/函数组合。
- 防御：对 PE 解析器做严格边界校验（RVA 落在节内、块大小合理、循环上限），防止恶意 PE 导致解析器崩溃或 OOB；分析不可信样本时在隔离环境运行。
- 加固：理解 ILT/IAT/重定位是脱壳、IAT Hook 排查和恶意样本 triage 的基础；防御方可监控 IAT 修改（VirtualProtect + 写入）与异常重定位行为。
