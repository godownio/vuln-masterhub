---
id: code-analysis-reverse-firmware-quantitative-scope-assessment
title: 大型固件反编译的定量范围评估：函数行数统计、模块分类与抽样源码匹配
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: firmware-reverse-quantitative-scoping
aliases:
- 固件逆向工作量评估
- 反编译函数行数统计
- 模块分类透视表
- 逆向范围量化
tags:
- reverse
- firmware
- methodology
- ghidra
- spreadsheet
- bl602
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V512
  verified_at: '2026-11-11T11:19:54+08:00'
  notes: '已对照原文第八节与全部38张图（重点图01/27-34）核对：grep --line-number "^[_a-zA-Z]" 提取函数与行号、grep -v LAB_、按相邻行号差算函数行数、按前缀/聚集批量分类、每模块抽样1-2个最复杂函数比对上游、透视表汇总 11,300/7,500/3,500/10,500 行均与原文一致；分类行数按图01底部 Lines Classified: 97290 已由 97,200 修正为 97,290（97290/113007=86%）；图01 Grand Total 2992函数/113007行。dedup 20个候选全为new，与既有固件二进制diff上游对照卡不同链；原文无CVE与受影响版本，未设versions；frontmatter无sources/source_url。未验证点：未复跑电子表格/透视表流程。'
---

## 一句话结论

把反编译产物中的全部函数名与起始行号导入电子表格，按相邻行号差估算函数体量、按前缀归类模块、对每个模块抽样最复杂函数与开源代码比对，再用数据透视表算出"需逆向/部分匹配/已有源码"的代码行数，据此把逆向投入压到真正缺失的部分。

## 原理

- Ghidra 等工具输出的反编译结果是单个线性 C 文件，函数定义顶格出现，因此相邻函数起始行号之差近似该函数体量（含注释与空行）；体量最大的函数通常也是模块核心逻辑。
- 同一模块的函数在文件中往往聚集且命名前缀一致（如 `rxl_`、`ke_`、`txl_`、`wifi_mgmr_`），用前缀加相邻关系可批量归类，只有少数函数需要人工判定。
- 大型固件中同类函数实现高度一致（同一编译器与源码基线），因此每个模块只抽样 1-2 个最复杂函数与 GitHub 上游比对，即可较可靠地估计该模块的整体匹配率。
- 定量结果直接决定优先级：实例中 BL602 WiFi 固件 113,007 行反编译代码有 97,290 行（86%）完成分类，其中约 11,300 行有 GitHub 源码、7,500 行有 SDK 源码、3,500 行部分匹配、10,500 行需要逆向，因此重点放在 LMAC 接口与未匹配的 Supplicant 片段。

## 触发条件

- 反编译产物是文本 C 文件，或能通过脚本导出函数列表（Ghidra/IDA）。
- 固件规模大（数千函数、十万行级），需要规划逆向优先级与工作量。
- 已有可检索的开源源码基线（例如通过 GitHub 代码搜索定位到上游，见关联卡片）。

## 利用步骤

1. 提取函数名与行号：`grep --line-number "^[_a-zA-Z]" bl602_demo_wifi.c | grep -v LAB_ > bl602_demo_wifi.txt`（反编译函数定义顶格，排除 `LAB_` 标签）。
2. 导入电子表格，清洗返回类型/参数列，按相邻行号差计算每个函数行数，用条件格式标出体量最大的函数。
3. 按函数名前缀与相邻聚集关系批量填写模块列；无法判定的标 `???`，允许跳过以保持进度。
4. 每个模块挑 1-2 个最复杂函数，用 GitHub 代码搜索匹配上游源码，在"Source Code"列记录匹配情况与差异备注。
5. 第二页建数据透视表，按模块汇总函数数与行数，并按匹配状态（需逆向/部分/已有源码）分类求和。
6. 按"需逆向且体量大"排序安排后续逐函数分析，优先攻克真正无源码的模块。

## PoC

```bash
# 1) 提取反编译函数名与行号（Ghidra 输出为单个 C 文件时）
grep --line-number "^[_a-zA-Z]" bl602_demo_wifi.c | grep -v LAB_ > bl602_demo_wifi.txt

# 2) 读取前若干行，确认函数边界格式
head -20 bl602_demo_wifi.txt

# 3) 在电子表格中：行数 = 下一函数行号 - 本函数行号
#    透视表按 Module 汇总 Lines of Code，按匹配状态求和
```

## 变体与关联

- 变体：用 IDA 脚本导出函数地址与大小（`get_func_off`/`get_func_size`），替代行号差，适用于非文本反编译流程。
- 变体：对多模块固件，先按二进制段（text/rodata）与调用图聚类，再做模块分类。
- 关联：[[code-analysis-reverse-firmware-github-code-search-open-source-attribution]]（抽样匹配所用的开源源定位方法）；[[code-analysis-reverse-firmware-uboot-bindiff-symbol-custom-base58]]（用 BinDiff 恢复符号后同样可做范围评估）。
- 限制：行号差包含注释与空行，函数内联/拆分会使体量估计失真；抽样匹配只能给出近似覆盖率，最终仍需逐函数核对。

## 检测与防御

- 固件厂商（防御）：剥离符号与调试信息、裁剪断言与日志字符串、控制固件体积并混淆关键函数，会同时降低本方法的估算精度和开源匹配率。
- 研究者：定量评估只用于规划投入，不能替代对关键路径（协议状态机、校验、加密）的逐函数确认。
