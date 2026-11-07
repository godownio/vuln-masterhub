---
id: defense-detection-elf-pt-note-hijack-static-detection
title: PT_NOTE 劫持静态检测：section/segment 一致性、微型 LOAD 段与入口点校验
type: scenario
domain: defense
path: defense/detection
technique: elf-pt-note-hijack-static-detection
tags:
- linux
- elf
- detection
- pt_note
- pt_load
- program-header
- static-analysis
- threat-hunting
- yara
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T19:41:56+08:00'
  notes: 已对照原文与37张图核对：四条规则与阈值、hello_infected 四告警、hello_v2(0x800000) 剩3条、hello_silent(12字节) 仍命中、hello_nosec_infected 剩程序头3条，均与原文一致；检测伪代码与原文 detector.py 逻辑一致。未验证点：脚本未本机复跑；规则对加壳/极小 ELF 的误报边界原文已注明。
url: /docs/defense/detection/defense-detection-elf-pt-note-hijack-static-detection/
draft: false
kb_aliases:
- ELF 注入检测
- PT_NOTE 检测
- 微型 LOAD 段检测
- ELF 入口点异常检测
- program header 审计
- ELF 段一致性检查
---

## 一句话结论

PT_NOTE→PT_LOAD 型 ELF 注入只改 program header 和 `e_entry`，`file` 与 section 视图完全看不出来；但只要交叉检查 section/segment 一致性、PT_LOAD 大小与地址分布、入口点归属，就能用四条静态规则稳定命中，并且这些规则在攻击者改动虚拟地址、静默化 shellcode、清零 section header 后仍大部分有效。

## 原理

- **检测的立足点**：正常编译器产出的 ELF 在 section 与 program header 之间存在稳定对应关系：有几个 `.note.*` section 就应有几个 PT_NOTE 段；`PT_LOAD` 段覆盖 `.text/.data/.rodata` 等正常节，大小从数百字节到数 MB；`e_entry` 落在 `.text` 或正常代码段内；`PT_LOAD` 虚拟地址基本连续（示例在 0x400000 附近）。PT_NOTE 劫持会打破其中至少一项。
- **规则 1：section/segment 数量一致性**。统计 `SHT_NOTE`（`sh_type == 7`）的 section 数与 `p_type == 4` 的 program header 数；若 section 数大于 PT_NOTE 段数，说明有 NOTE 被改了类型。该规则需要 section header 存在。
- **规则 2：微型 PT_LOAD**。正常代码段通常至少几百字节；`p_filesz` 小于 128 字节的 PT_LOAD 高度可疑（示例 shellcode 59 字节、静默 shellcode 仅 12 字节）。规则只依赖 program header，清零 section header 后仍有效。
- **规则 3：入口点在微型 LOAD 段 / 不属于任何 LOAD**。检查 `p_vaddr <= e_entry < p_vaddr + p_filesz`；若命中的段 `p_filesz < 128`，或 `e_entry` 不在任何 PT_LOAD 内，均可疑。正常 `_start` 应位于主代码段。
- **规则 4：PT_LOAD 地址跳跃**。把 PT_LOAD 的 `p_vaddr` 排序，若相邻间隔大于 16 MB（示例 0x403df8 → 0xc000000，间隔 187 MB），提示存在孤立的高位段。该规则依赖攻击者选择“离谱”的地址，可被规避。
- **检测脚本结构**：解析 ELF header（`e_entry/e_phoff/e_phentsize/e_phnum/e_shoff/e_shentsize/e_shnum`），遍历 program header 收集 PT_LOAD 与 PT_NOTE，遍历 section header 统计 SHT_NOTE，按上述四条规则累积告警；多条同时命中时置信度显著提高。
- **对抗实验**：
  - 把注入地址从 0xc000000 改为 0x800000（距正常段约 4 MB），规则 4 失效，但规则 1/2/3 仍命中。
  - 用 12 字节静默 shellcode（只跳回 OEP），运行行为与原程序完全一致，但规则 2/3 仍命中，`readelf -h` 也显示入口点已改。
  - 把 `e_shoff/e_shnum` 清零使规则 1 失效，但规则 2/3/4 仍命中。
- **最难规避的两条**：微型 LOAD 段与入口点落在其中。攻击者要把 shellcode 填充到几百字节以上，并放弃修改 `e_entry`（例如 hook `.init_array`），但这会引入新的代码/节修改痕迹。
- **边界**：规则可能对加壳、极小 ELF、特殊链接脚本、静态链接 musl、无 PT_NOTE 文件产生误报/漏报；应结合文件来源、签名、哈希与运行时行为综合判断，而不是单条规则定罪。

## 触发条件

- 具备待检 ELF 文件（本地样本、制品库、邮件附件、下载物等），可读取 ELF header、program header、section header。
- 检测方可运行 Python/readelf 等静态解析工具；无需执行样本。
- 目标攻击手法为 PT_NOTE→PT_LOAD 类注入（或类似的 program header 篡改）。
- 对加壳/保护二进制需要先脱壳或调整阈值，否则误报率会上升。

## 利用步骤

1. 解析 ELF header：确认 64/32 位与字节序，读取 `e_entry`、`e_phoff/e_phentsize/e_phnum`、`e_shoff/e_shentsize/e_shnum`。
2. 遍历 program header：记录每个 `PT_LOAD` 的 `p_vaddr/p_filesz/p_flags`，统计 `PT_NOTE` 数量；注意 `p_flags` 中 R|X 的组合。
3. 遍历 section header：统计 `SHT_NOTE`（type 7）数量；若 `e_shnum == 0` 或 `e_shoff == 0`，规则 1 跳过并标记“无节表”。
4. 应用规则 1：`note_sections > note_segments` → 告警“有 NOTE 被改类型”。
5. 应用规则 2：`0 < p_filesz < 128` 的 PT_LOAD → 告警“疑似 shellcode”。
6. 应用规则 3：`e_entry` 落在 `p_filesz < 128` 的 PT_LOAD 内，或不在任何 PT_LOAD 内 → 告警“入口点异常”。
7. 应用规则 4：PT_LOAD 虚拟地址排序后相邻间隔 > 16 MB → 告警“地址跳跃”。
8. 组合多条告警提升置信度；对告警样本再用 `readelf -l`、十六进制查看 program header 与文件末尾追加数据确认。
9. 对规避变体补充规则：检查 `e_entry` 是否等于某个非主映像段的 `p_vaddr`、检查 `.init_array`/GOT 等初始化路径是否被改写、检查文件末尾追加的高熵数据与页对齐填充。

## PoC

原文检测脚本对 `hello`（正常）与 `hello_infected`（注入）运行结果：

```text
✓ hello: 未发现异常
⚠ hello_infected: 疑似被注入
  [!] phdr[7]: PT_LOAD 大小 59 字节，疑似 shellcode
  [!] 入口点 0xc000000 在一个 59 字节的微型 LOAD 段里
  [!] PT_LOAD 地址跳跃: 0x403df8 → 0xc000000 (间隔 187 MB)
  [!] 3 个 NOTE section 但只有 2 个 PT_NOTE 段——有 NOTE 被改了类型
```

关键伪代码（按原文规则复述，未在本机执行）：

```python
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from('<II', data, off)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
        struct.unpack_from('<QQQQQQ', data, off + 8)
    if p_type == 1:  # PT_LOAD
        loads.append((i, p_vaddr, p_filesz, p_flags))
        if 0 < p_filesz < 128:
            alerts.append(f"phdr[{i}]: PT_LOAD 大小 {p_filesz} 字节，疑似 shellcode")

entry_in_load = any(v <= e_entry < v + sz for _, v, sz, _ in loads)
if not entry_in_load:
    alerts.append("入口点不在任何 PT_LOAD 段内")

# NOTE section 数与 PT_NOTE 段数对比
note_sections = sum(1 for i in range(e_shnum)
                    if struct.unpack_from('<I', data, e_shoff + i * e_shentsize + 4)[0] == 7)
if note_sections > note_segments:
    alerts.append("NOTE section 多于 PT_NOTE 段——有 NOTE 被改类型")
```

原文对抗结果：`hello_v2`（vaddr 0x800000）仍命中 3 条；`hello_silent`（12 字节静默 shellcode）仍命中微型 LOAD 与入口点规则；`hello_nosec_infected`（清零 section header）仍命中程序头三条规则。

## 变体与关联

- **加壳/压缩 ELF**：微型 LOAD、异常入口点可能是壳的正常特征；需先识别壳或降低规则权重。
- **静态链接/极小 ELF**：段数量少、没有 `.note.*`、入口点可能不在常规 `.text`，规则 1/3 需谨慎。
- **32 位 ELF**：解析 32 位 header/program header 布局，阈值同样适用。
- **补充检测**：结合 `readelf -l` 人工复核、文件末尾追加数据与页对齐填充、`.init_array`/GOT 改写检查、YARA 规则匹配 `PT_LOAD` 头字段模式。
- **关联**：注入手法见 [[code-analysis-reverse-linux-elf-pt-note-to-load-injection]]；section header 清零见 [[code-analysis-reverse-linux-elf-section-header-zeroing]]。

## 检测与防御

- **部署位置**：CI/制品库入库扫描、邮件/下载网关、主机侧定期巡检、威胁狩猎脚本；对高风险来源的 ELF 优先跑 program header 规则。
- **组合规则**：单条规则易误报，建议至少两条同时命中才升级告警；保留原始告警字段供人工复核。
- **完整性体系**：IMA/EVM、代码签名、发布物哈希、包管理器签名是根本缓解；静态检测只作为补充。
- **对抗演进**：攻击者可 padding shellcode、改 vaddr、清 section header、hook `.init_array`；检测方需持续补充 `e_entry` 归属、初始化数组、文件尾部追加数据等规则，不能只依赖四条基础规则。
- **响应**：确认注入后隔离样本、回溯分发链路与同批次制品、检查同源构建产物是否被篡改，并重新签发/重新构建。
