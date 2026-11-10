---
id: code-analysis-reverse-windows-minimal-pe32-manual-construction
title: 手工构造“最小”PE32：三节合一 + 压缩 DataDirectory + PE Headers 与 Section 重叠（Win10 Loader）
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: minimal-pe32-manual-construction
tags:
- reverse
- windows
- pe
- pe32
- loader
- section-table
- data-directory
- binary-format
- minimal-exe
- manual-construction
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T06:05:58+08:00'
  notes: 已对照原文核对；图01-04 三节合一布局/头部/导入表/代码地址，图05 MessageBox 弹窗，图06-07 DataDirectory 压缩与节表前移，图08 布局（节名 .mixed），图09-14 512 字节版本字段（SizeOfOptionalHeader 0x70、EntryPoint 0x130、Alignment 0x10、SizeOfImage 0x1000、SizeOfHeaders 0x130、Import RVA 0x1A0、节表 0xD0/0x130、导入表 0x1C8/0x1D0/0x1DB、代码 6A 40 68 50 01 40 00...），图15 最终 512 字节文件均与卡内一致；原文明确仅 Win10 可运行、Win7 不可，未设 affected_versions 正确；图15 最终节名显示为 .coded（原文表格与图08 为 .mixed），属原文自身不一致、不影响加载，卡内按正文 .mixed 记录；未实际运行 PoC
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-minimal-pe32-manual-construction/
draft: false
kb_aliases:
- 最小 PE
- PE32 手工构造
- 三节合一
- Headers 与 Section 重叠
- 512 字节 PE
- SizeOfOptionalHeader 压缩
- NumberOfRvaAndSizes 裁剪
- Win10 Loader 兼容
---

## 一句话结论

在一个能运行的标准 PE32 基础上手工改头部字段，可以把它从约 2KB 缩到 512 字节：先把 `.code/.data/.idata` 三节合并成一个 `.mixed` 节，再把 `NumberOfRvaAndSizes` 裁到 2 以压缩可选头并前移节表，最后让 PE Headers 与唯一节在文件中重叠（`FOA = RVA`）；Win10 的 Loader 仍按头部里的 `AddressOfEntryPoint` 与导入表 RVA 正常加载并弹出 MessageBox，Win7 下不可运行。

## 原理

- **Section 只是容器**：Windows Loader 取代码/数据靠的是头部指针——`AddressOfEntryPoint` 指向入口 RVA，`DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]` 指向导入表 RVA，`SizeOfImage`/`SizeOfHeaders` 界定镜像与头大小；`.code/.data/.idata` 的命名与分类是编译器/上层语言的约定，不参与加载定位。因此只要指针正确，把三类数据塞进一个节（甚至与头部重叠）也能运行。
- **节表与可选头的联动**：`IMAGE_FILE_HEADER.NumberOfSections` 决定节表项数（每项 40 字节），节表必须紧跟 `IMAGE_OPTIONAL_HEADER`；`NumberOfRvaAndSizes` 决定 `DataDirectory[16]` 的实际项数，`SizeOfOptionalHeader` 记录可选头总大小。把一个节之外的 14 个未用目录裁掉（`NumberOfRvaAndSizes=2`），可选头从 0xE0 缩到 0x70，节表相应前移 0x70 字节——文件仍可运行。
- **Headers 与 Section 重叠**：当 `SizeOfHeaders` 覆盖到节的内容、且节的 `PointerToRawData`/`VirtualAddress` 指向头部区域内时，`FOA = RVA`。把 `SectionAlignment`/`FileAlignment` 都设成 0x10（只要求非零并能整除节地址），`SizeOfImage=0x1000`、`SizeOfHeaders=0x130`，节放在 0x130，代码、字符串、导入表都在 0x130–0x200 之间，整个文件就是 512 字节。
- **Win10 Loader 的额外约束**：最小布局要求导入表仍位于某个 Section 内，否则 Win10 判定 PE 不合规；该 512 字节文件在 Win10 可运行、Win7 不行，说明不同 Windows 版本 Loader 对 PE 结构的容忍度不同——这是本文“最小 PE”能成立的关键前提。
- **对齐不是性能必需**：常规 PE 的页对齐/扇区对齐是为了映射与 I/O 效率；Loader 只做“地址 / Alignment 是否整除”的校验，分母非零即可，因此可以取很小的对齐值把数据压紧。
- **代价与边界**：头部与节重叠、可选头/节表被裁剪后，很多工具会认为文件异常；代码中字符串与 IAT 的绝对地址、导入表的 4 个 RVA 都要按新布局重算（示例代码 `push 0x400150`、`call ds:0x4001C8`）。

## 触发条件

- 使用十六进制编辑器手工编辑 PE32（本方法在 Win10 上测试通过，Win7 不适用）。
- 以一个可运行的标准 PE32 为基础（原文为手动构造的 MessageBoxA 示例），且已知其 DOS/NT/可选头/节表/导入表布局。
- 目标文件只需要在特定 Windows 版本运行，允许牺牲工具兼容性与格式规范性。
- 能重算入口、字符串、IAT、导入表等所有受影响字段的 RVA/FOA。

## 利用步骤

1. **三节合一**：新建 0x400 全零文件，复制原文件前 0x400 字节；把 `.data` 与 `.idata` 的数据块搬到 `.code` 节内（原文：导入表放 FOA 0x320、字符串放 0x260）。改 `NumberOfSections=1`、节名 `.mixed`、`AddressOfEntryPoint`、`BaseOfData`、`SizeOfImage`、导入表 RVA；把多余的两个 Section Header（0x1A0 起 80 字节）清零；按新 FOA 重算导入表内 4 个 RVA，并修正代码里的字符串/IAT 地址。运行验证。
2. **压缩 DataDirectory**：在 min_PE1.0 基础上设 `NumberOfRvaAndSizes=2`、`SizeOfOptionalHeader=0x70`，把唯一的 Section Header 从 0x178 前移到 0x108，原位置清零；运行验证。
3. **Headers 与 Section 重叠**：新建 512 字节文件，复制 min_PE1.1 的前 512 字节；把 Code、字符串、导入表分别放到 0x130、0x150、0x1A0；设 `SizeOfCode` 不小于实际代码、`AddressOfEntryPoint=0x130`、`BaseOfCode=BaseOfData=0`、`SectionAlignment=FileAlignment=0x10`、`SizeOfImage=0x1000`、`SizeOfHeaders=0x130`、导入表 RVA=0x1A0。
4. **节表与导入表**：Section Header 的 `VirtualSize=0xD0`、`VirtualAddress=0x130`、`SizeOfRawData=0xD0`、`PointerToRawData=0x130`；导入表的 Import Lookup/IAT/DLL Name 指向 0x1C8/0x1D0 等新位置；代码里的字符串地址改为 0x400150/0x40015E、IAT 调用改为 0x4001C8。
5. 保存为 512 字节文件，在 Win10 运行验证；若 Loader 报错，逐项核对 Size/Align/目录 RVA 与节范围。

## PoC

最终 512 字节布局的关键字段（FOA = RVA，取自原文第三步）：

```text
0x094 SizeOfOptionalHeader = 0x70
0x0A8 AddressOfEntryPoint  = 0x130
0x0AC BaseOfCode           = 0x0
0x0B0 BaseOfData           = 0x0
0x0B4 ImageBase            = 0x400000
0x0B8 SectionAlignment     = 0x10
0x0BC FileAlignment        = 0x10
0x0D0 SizeOfImage          = 0x1000
0x0D4 SizeOfHeaders        = 0x130
0x0F4 NumberOfRvaAndSizes  = 2
0x100 Import Table RVA     = 0x1A0
0x110 VirtualSize          = 0xD0
0x114 VirtualAddress       = 0x130
0x118 SizeOfRawData        = 0xD0
0x11C PointerToRawData     = 0x130
```

代码块（0x130 起，21 字节）：

```text
6A 40 68 50 01 40 00 68 5E 01 40 00 6A 00 FF 15 C8 01 40 00 C3
; push 0x40; push 0x400150; push 0x40015E; push 0; call ds:0x4001C8; ret
```

导入表（0x1A0 起）指向 `user32.dll` / `MessageBoxA`，IAT/ILT 指向 0x1C8，DLL 名 0x1D0、Hint/Name 0x1DB。运行后弹出 “Hello, Snake! / This is an example that created a PE file manually.” 对话框，证明 512 字节 PE 可被 Win10 加载。

## 变体与关联

- **进一步缩小**：PE Header 与 DOS Header 重叠（`e_lfanew` 指回 0x4）、把导入表结尾的全 0 项与文件末尾补齐字节重叠、继续压低 SectionAlignment/FileAlignment 并紧凑排列数据块；原文把这些列为后续思路。
- **解析侧**：PE 头字段的偏移与定位链见 [[code-analysis-reverse-windows-pe-header-layout-locate]]（本卡是构造侧，解析卡是读取侧，可互为校验）。
- **加载器差异**：不同 Windows 版本/更新对节表、导入表位置、对齐、SizeOfHeaders 的容忍度不同；跨版本使用前需逐项实测。
- **用途**：极小 PE 可用于体积受限的 loader/演示程序，也常用于理解恶意样本的畸形 PE 结构；对防御方，畸形/重叠 PE 本身是可疑特征。
- **边界**：需要 Win10 目标、基础 PE 可运行、所有 RVA 重算正确；对签名/清单/重定位有要求的场景不适用。

## 检测与防御

- **检测（防御/分析视角）**：PE 文件极小（数百字节）、`SizeOfHeaders` 覆盖节内容、节 `PointerToRawData` 落在头部区域内、`NumberOfRvaAndSizes` 被裁剪到极小值、`SectionAlignment/FileAlignment` 异常小——这些是手工构造/畸形 PE 的强特征。
- **解析器健壮性**：安全产品解析 PE 时应校验节范围、目录 RVA 与文件大小的一致性，避免被重叠布局欺骗；对异常 PE 采用保守判定。
- **运行控制**：按签名/信誉/行为而非仅文件格式放行；对极小无签名 PE 提高警惕。
- **说明**：本卡是二进制格式构造技法（severity 低），用于理解 Loader 行为与 PE 结构，不针对某个漏洞。
