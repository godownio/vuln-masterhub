---
id: code-analysis-reverse-windows-pe-export-directory-eat-name-ordinal-resolve
title: PE 导出表（EAT）解析：AddressOfNames/AddressOfNameOrdinals/AddressOfFunctions 三级索引按名字或序号解析导出函数 RVA
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-export-directory-eat-name-ordinal-resolve
tags:
- reverse
- windows
- pe
- export-table
- eat
- parser
- dll
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T13:53:31+08:00'
  notes: 已对照原文与33图核对（图25为EAT三级索引图）；IMAGE_EXPORT_DIRECTORY字段、AddressOfNames→AddressOfNameOrdinals→AddressOfFunctions解析路径、按序号ordinal-Base、SearchEAT代码均与原文一致；卡片把NameOrdinals明确为AddressOfFunctions下标（原文称序号，属更准确表述）；转发导出边界为通用PE知识补充，原文未提；无affected_versions（格式教学文）；PoC未编译运行
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-pe-export-directory-eat-name-ordinal-resolve/
draft: false
kb_aliases:
- IMAGE_EXPORT_DIRECTORY
- EAT 解析
- 导出表解析
- AddressOfNames
- AddressOfNameOrdinals
- AddressOfFunctions
- SearchEAT
- 导出函数 RVA
- DLL 导出枚举
---

## 一句话结论

PE 的导出表入口是 `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT=0]`：`IMAGE_EXPORT_DIRECTORY` 给出序号基数 `Base`、函数/名字数量，以及三个 RVA 数组——`AddressOfFunctions`（按序号存函数 RVA）、`AddressOfNames`（存导出名字符串 RVA）、`AddressOfNameOrdinals`（存名字到 `AddressOfFunctions` 下标的 WORD 映射）。按名字查函数是“名字→NameOrdinals[i]→Functions[idx]”，按序号查是“序号-Base→Functions[idx]”；两者最终都得到函数的 RVA，加上模块实际基址即函数地址。

## 原理

- **导出表结构与定位**：`IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[0]` 是 `IMAGE_DATA_DIRECTORY{VirtualAddress, Size}`，指向镜像中的 `IMAGE_EXPORT_DIRECTORY`（EXE 一般无导出表，DLL 常见，但资源型 DLL/特殊 EXE 也可能有）。
- **`IMAGE_EXPORT_DIRECTORY` 关键字段**：
  - `Name`：模块名（RVA 指向字符串）；
  - `Base`：导出序号的起始值，按序号导出的序号从 `Base` 开始递增；
  - `NumberOfFunctions`：`AddressOfFunctions` 数组元素数量（所有导出函数）；
  - `NumberOfNames`：按名字导出的数量；
  - `AddressOfFunctions`：DWORD 数组，每项是一个函数的 RVA，顺序与导出序号对应；
  - `AddressOfNames`：DWORD 数组，每项是函数名字符串的 RVA；
  - `AddressOfNameOrdinals`：WORD 数组，与 `AddressOfNames` 一一对应，值是“该名字的函数在 `AddressOfFunctions` 中的下标”（不是序号本身）。
- **按名字解析**：在 `AddressOfNames` 中比较字符串找到下标 `i` → 取 `AddressOfNameOrdinals[i] = idx` → 函数 RVA = `AddressOfFunctions[idx]`。原文示例：`Func2` 在名字表第 2 项（下标 1），`NameOrdinals[1]` 给出 2，则函数入口在 `AddressOfFunctions[2]`（第三项）。
- **按序号解析**：`index = ordinal - Base`；若 `index < NumberOfFunctions` 且 `ordinal >= Base`，函数 RVA = `AddressOfFunctions[index]`。原文的装载器步骤也是同一路径：取导出表 RVA → 取 `Base` → 序号减 `Base` → 检查 `< NumberOfFunctions` → 从 `AddressOfFunctions` 取 RVA → 加实际基址。
- **为什么名字表要走 NameOrdinals 中转**：链接器允许“有名字的导出”少于“全部导出函数”，也允许名字顺序与函数地址顺序不同；`AddressOfNames` 与 `AddressOfFunctions` 的大小和顺序都不保证一致，必须用 `AddressOfNameOrdinals` 做映射。按名字查时若直接拿名字下标索引函数数组会取错函数。
- **RVA 落地**：导出表中的地址都是 RVA（相对镜像基址）；磁盘静态解析时要按节表把 RVA 换算成文件偏移（`RVA - 节.VirtualAddress + 节.PointerToRawData`），动态分析时加模块实际加载基址。
- **导出表的分析价值**：枚举 DLL 能力（是否导出敏感函数）、比对导出与实现、定位导出函数供调试/调用、检查 EAT Hook（导出表项被改指向非本模块地址）等。

## 触发条件

- 目标文件存在导出目录（`DataDirectory[0].VirtualAddress/Size` 非零），通常是 DLL，也可能是带导出的 EXE。
- 需要在不运行样本的情况下枚举/定位导出函数（恶意 DLL 能力评估、调试时下断点、编写调用器）。
- 或需要核对导出表是否被篡改（EAT Hook/转发导出异常）。

## 利用步骤

1. 解析 DOS/NT 头，读取 `OptionalHeader.DataDirectory[0]` 的 RVA/Size，按节表换算成文件偏移。
2. 读取 `IMAGE_EXPORT_DIRECTORY`，记录 `Base`、`NumberOfFunctions`、`NumberOfNames`、三个数组的 RVA。
3. 按名字查：遍历 `AddressOfNames`（每项 RVA → 字符串），`strcmp` 目标名；命中下标 `i` 后取 `AddressOfNameOrdinals[i]`，再用该值索引 `AddressOfFunctions`，得到函数 RVA。
4. 按序号查：`idx = ordinal - Base`，边界检查后直接取 `AddressOfFunctions[idx]`。
5. 将函数 RVA 按节表换算为文件偏移（静态）或加模块基址（动态）后使用；可对照 `Name` 字段确认模块名。
6. 审计异常：函数 RVA 落在导出目录自身范围内时通常表示“转发导出”（该 RVA 指向 `DLL.Function` 字符串），不是本模块代码地址；导出表项指向其他节/不可执行区也应重点核对。

## PoC

原文的按名字/序号检索实现（C++，节选；未在本机编译运行）：

```cpp
DWORD* CEAT::SearchEAT(const char* szName)
{
    if (IS_VALID_PTR(m_pTable))
    {
        bool bByOrdinal = HIWORD(szName) == 0;
        DWORD* pProcs = (DWORD*)((char*)RVA2VA(m_pTable->AddressOfFunctions));
        if (bByOrdinal)
        {
            DWORD dwOrdinal = (DWORD)szName;
            if (dwOrdinal < m_pTable->NumberOfFunctions && dwOrdinal >= m_pTable->Base)
                return &pProcs[dwOrdinal - m_pTable->Base];
        }
        else
        {
            WORD* pOrdinals = (WORD*)((char*)RVA2VA(m_pTable->AddressOfNameOrdinals));
            DWORD* pNames = (DWORD*)((char*)RVA2VA(m_pTable->AddressOfNames));
            for (unsigned int i = 0; i < m_pTable->NumberOfNames; ++i)
            {
                char* pNameVA = (char*)RVA2VA(pNames[i]);
                if (strcmp(szName, pNameVA) != 0)
                    continue;
                return &pProcs[pOrdinals[i]];
            }
        }
    }
    return NULL;
}
```

## 变体与关联

- **运行期 EAT 遍历**：[[pentest-c2-pic-shellcode-export-forwarder-apiset-resolution]] 和 PEB/Ldr 系列卡在 shellcode/loader 中从 PEB 找模块基址后遍历同一套结构解析 `GetProcAddress`；本卡面向磁盘文件的结构解析（DLL 枚举/静态分析），触发环境与 PoC 不同。
- **导入侧**：[[code-analysis-reverse-windows-pe-import-reloc-parser]] 解析的是导入描述符/ILT/IAT 与重定位；导出表是“本模块提供给外部”的镜像面，两者常配合做 DLL 能力比对。
- **头部定位**：[[code-analysis-reverse-windows-pe-header-layout-locate]] 提供 DataDirectory 与 RVA↔文件偏移的基础；本卡从 `DataDirectory[0]` 继续。
- **边界**：转发导出（forwarder）的 RVA 指向导出目录范围内的字符串；按序号/名字取到的“函数地址”此时不是代码地址，需要再解析 `DLL.Function`。PE32/PE32+ 的 `IMAGE_EXPORT_DIRECTORY` 字段均为 DWORD RVA，布局一致。

## 检测与防御

- **EAT Hook 检测**：核对 `AddressOfFunctions` 每项是否落在本模块可执行节内、是否与该 DLL 的签名/原始副本一致；导出表所在节的写权限与内存完整性（对照磁盘文件与内存镜像）可发现运行时篡改。
- **可疑 DLL 分析**：导出函数名、数量、转发目标与模块名是能力画像的一部分；导出表指向异常节或外部模块时列为可疑。
- **开发者**：只导出必要函数，保持导出表稳定；对敏感导出做调用方校验；发布带签名以减少被篡改/替换的可信度。
