---
id: code-analysis-reverse-windows-pe-resource-directory-three-level-tree-parse
title: PE 资源目录三层树解析：类型→ID/名称→语言目录块与 IMAGE_RESOURCE_DATA_ENTRY 定位资源数据
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-resource-directory-three-level-tree-parse
aliases:
- PE 资源目录
- Resource Directory
- IMAGE_RESOURCE_DIRECTORY
- 资源树解析
- .rsrc 资源定位
- NameIsString
- DataIsDirectory
- IMAGE_RESOURCE_DATA_ENTRY
tags:
- reverse
- windows
- pe
- resource
- rsrc
- parser
- malware-analysis
- embedded-payload
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T13:53:36+08:00'
  notes: 已对照原文与33图核对（图31/33资源类型ID表、图32资源树Type/Name/Language/Data Entry）；三层树、IMAGE_RESOURCE_DIRECTORY头、ENTRY两个联合位段NameIsString/DataIsDirectory、目录偏移相对资源根而叶子OffsetToData为RVA、标准类型ID表均与原文一致；原文'四层二叉排序树'表述含糊，卡片采用与原文主体一致的3层目录+叶子DATA_ENTRY；无affected_versions；无PoC
---

## 一句话结论

PE 的资源集中在 `.rsrc` 节，由 `DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE=2]` 指向一棵三层树：第一层按资源类型（RT_ICON/RT_RCDATA/…）、第二层按资源 ID 或名称、第三层按语言代码页，每个目录块都是 `IMAGE_RESOURCE_DIRECTORY` 头加 `IMAGE_RESOURCE_DIRECTORY_ENTRY` 数组；entry 的两个联合位段 `NameIsString`/`DataIsDirectory` 区分“名字 vs ID”“下级目录 vs 数据项”，最终叶子 `IMAGE_RESOURCE_DATA_ENTRY` 给出资源数据的 RVA 与大小。所有目录内偏移都相对资源根，不是 RVA；按这套规则即可从任意 PE 中枚举/提取图标、版本信息、配置或内嵌载荷。

## 原理

- **入口与根**：`DataDirectory[2]` 的 `VirtualAddress`/`Size` 指向资源目录根（通常在 `.rsrc` 节）。根是一个 `IMAGE_RESOURCE_DIRECTORY`，后面紧跟 `NumberOfNamedEntries + NumberOfIdEntries` 个 `IMAGE_RESOURCE_DIRECTORY_ENTRY`（每项 8 字节）。
- **`IMAGE_RESOURCE_DIRECTORY`**：`Characteristics`、`TimeDateStamp`（一般 0）、`MajorVersion/MinorVersion`、`NumberOfNamedEntries`（按字符串名命名的项数）、`NumberOfIdEntries`（按整数 ID 的项数）；后两者之和就是目录项数量。
- **`IMAGE_RESOURCE_DIRECTORY_ENTRY` 的两个 32 位联合**：
  - 第一项：`Name`（低 31 位）与最高位 `NameIsString`。`NameIsString=1` 时低 31 位是相对资源根的偏移，指向 `IMAGE_RESOURCE_DIR_STRING_U{WORD Length; WCHAR NameString[];}`（Unicode 名字）；`NameIsString=0` 时低 16 位是整数 ID。
  - 第二项：`OffsetToData`（低 31 位）与最高位 `DataIsDirectory`。`DataIsDirectory=1` 时低 31 位是相对资源根的下级目录块偏移；`DataIsDirectory=0` 时低 31 位指向叶子 `IMAGE_RESOURCE_DATA_ENTRY`。
- **三层语义**：
  - 第一层（类型）：entry 的 Name/ID 是资源类型。标准类型 ID：1 Cursor、2 Bitmap、3 Icon、4 Menu、5 Dialog、6 String、7 Font Directory、8 Font、9 Accelerators、10 RCDATA（非格式化资源）、11 Message Table、12 Group Cursor、14 Group Icon、16 Version Information；资源类型 ID 高位为 1 表示自定义类型（非标准）。
  - 第二层（名称/ID）：具体资源标识，如 `IDM_OPEN=2001h` 这类菜单 ID，或字符串名字。
  - 第三层（语言）：语言代码页，如 2052 简体中文、936 GBK 代码页；每个语言对应一个叶子数据项。
- **叶子 `IMAGE_RESOURCE_DATA_ENTRY`**：`OffsetToData` 是资源数据的 **RVA**（不是相对资源根的偏移），`Size` 是字节数，`CodePage`、`Reserved` 一般 0。读到它之后按节表把 RVA 换成文件偏移即可切出数据。
- **偏移基准容易搞错**：目录块之间、名字字符串指针都用“相对资源根的偏移”；只有叶子里的 `OffsetToData` 是 RVA。解析器需要同时维护“资源根地址”和“镜像基址/节表”两套换算。
- **资源目录的分析价值**：图标/版本信息可用于伪装识别（签名仿冒、VERSIONINFO 造假）；RCDATA/自定义类型常藏配置、shellcode、二阶段 PE；资源大小/熵异常是恶意样本的高价值线索。

## 触发条件

- 目标 PE 存在资源目录（`DataDirectory[2].VirtualAddress/Size` 非零），通常有 `.rsrc` 节。
- 需要提取资源内容（图标、版本、配置、内嵌载荷）或判断资源是否被用于藏匿数据。
- 资源类型可能是标准 ID、字符串名或高位为 1 的自定义类型；叶子语言层可能多语言并存。

## 利用步骤

1. 从 NT 头取 `DataDirectory[2]`，用节表把 RVA 换算成文件偏移，定位资源根；记录资源根在文件与内存中的基准。
2. 读根目录头，计算目录项数量 `NumberOfNamedEntries + NumberOfIdEntries`；逐项读 entry。
3. 解第一层：按 `NameIsString` 取类型名或类型 ID；按 `DataIsDirectory` 递归到第二层目录。
4. 解第二层：同样取资源名/ID，并递归到第三层语言目录。
5. 解第三层：取语言 ID，`DataIsDirectory=0` 的 entry 指向 `IMAGE_RESOURCE_DATA_ENTRY`；读 `OffsetToData`（RVA）与 `Size`，按节表换算文件偏移后切出资源数据。
6. 对每个叶子记录 `(类型, 名称/ID, 语言, RVA, Size)`，按类型过滤目标（如 RT_RCDATA、RT_VERSION、RT_ICON）；对可疑大体积/高熵资源做进一步解密/PE 识别。
7. 交叉核对：资源名/类型 ID 的高位、目录偏移是否越界、`NumberOfNamedEntries` 与实际项数是否一致，异常结构提示样本被篡改或手工构造。

## PoC

无 PoC（结构解析流程；原文未提供可运行代码）。解析伪代码：

```text
root = file_offset(DataDirectory[2].VirtualAddress)
walk(dir_off):
    d = read(IMAGE_RESOURCE_DIRECTORY at root+dir_off)
    for i in range(d.NumberOfNamedEntries + d.NumberOfIdEntries):
        e = read(entry at root+dir_off+sizeof(dir)+i*8)
        name = e.NameIsString ? read_resource_string(root + (e.Name & 0x7fffffff))
                              : (e.Name & 0xffff)
        if e.DataIsDirectory:
            walk(e.OffsetToData & 0x7fffffff)      # 相对资源根
        else:
            de = read(IMAGE_RESOURCE_DATA_ENTRY at root + (e.OffsetToData & 0x7fffffff))
            data = read(file_offset(de.OffsetToData), de.Size)   # 这里 OffsetToData 是 RVA
```

## 变体与关联

- **资源藏载荷/配置的实战**：[[code-analysis-reverse-windows-resource-section-embedded-pe-restorator]]（Restorator 查 BIN 资源 MZ 头）、[[code-analysis-reverse-windows-remcos-settings-config-extraction]]（SETTINGS 资源 RC4 配置）、[[code-analysis-reverse-windows-redline-native-multistage-shellcode-clr-resource-loader]]（FindResource/LoadResource 取 RCDATA 密文）、[[pentest-c2-dotnet-resource-dual-rcdata-xor-manual-pe-map-loader]]（双 RCData 异或 + 手工映射 PE）；本卡提供统一的目录树解析规则，那些卡是具体样本的后续利用。
- **资源伪装**：图标/VERSIONINFO 降熵 + SigThief 复制签名（见资源与元数据伪装类卡）依赖读取/替换资源目录项；解析规则相同。
- **工具**：Resource Hacker/Restorator/PE-bear/PEView 等可可视化资源树；脚本化批量分析时按本卡结构直接遍历即可。
- **边界**：`.rsrc` 节可能被加壳器加密/搬移，需先脱壳或动态定位内存中的资源目录；资源根可能不在 `.rsrc`（自定义布局），以 `DataDirectory[2]` 为准而非节名。

## 检测与防御

- **恶意样本检测**：统计资源类型/名称、大小与熵；RCDATA/自定义类型中出现高熵大块、MZ/PE 头、URL/密钥字符串是重点；VERSIONINFO/图标与签名主体不一致提示伪装。
- **防御/开发**：不要把密钥、配置或可执行载荷放在资源中（资源可被任意读取）；对加载资源的代码做完整性校验/签名验证；发布构建时清理调试/临时资源。
- **分析环境**：在隔离环境提取资源，先做文件类型识别与静态扫描，不直接执行从资源释放的 PE。
