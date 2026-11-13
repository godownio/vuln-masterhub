---
id: mobile-android-axml-manifest-hardening-repair
title: AndroidManifest 二进制 AXML 加固修复：魔改 magic/stylesStart/stringCount 后用 010Editor 模板与 AXMLPrinter2 报错逐字段还原
type: scenario
domain: mobile
path: mobile/android
technique: axml-manifest-hardening-repair
aliases:
- AndroidManifest 加固
- AXML 加固修复
- binary AndroidManifest.xml
- AXMLPrinter2 排错
- androidmanifest.bt
- 010editor AXML 模板
- 魔改 AXML 头部
tags:
- android
- apk
- axml
- androidmanifest
- reverse-engineering
- anti-analysis
- file-format
- 010editor
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V668
  verified_at: '2026-11-13T10:06:20+08:00'
  notes: 已对照原文与22张截图逐字段核对：图01 AXML 结构图、图02 magic 03 00 08 00 与文件大小 0x9B4、图03/04 stringCount=36/stylesStart=172(0xAC)/stylesStart@0x20=0 及 template 字段偏移、图05/06 stringOffsets[0]=0 与 0xB4 处 05+theme、图07/08 010Editor 模板库 AndroidManifest.bt、图09 模板完整结构、图10 Expected chunk of type 0x80003 read 0x80000、图11 magic 被改 00 00 08 00 且 0x20 为 00 EE FF EE、图12 magic 修回、图13 NegativeArraySizeException -71304363、图14/15 stylesStart 00 EE FF EE→00 00 00 00、图16 Invalid chunk type (24)、图17/19 stringoffsets[255]+stringdata 报错、图18 重开后 stringoffsets 越界值、图20 0x10=FF、图21 FF→24 后 stringoffsets[36] 正常、图22 成功输出 manifest XML。卡内偏移、报错、示例值（0xAC/0xB4/36/0xFF/0x24）均与截图一致。未验证点：未拿到原样本复跑，模板为 010Editor 1.1.1(2019)。
---

## 一句话结论

恶意 APK 常通过篡改二进制 `AndroidManifest.xml`（AXML）的文件头与 StringPool 字段来让 apktool/AXMLPrinter2 等反编译失败；分析时用 010Editor 的 `AndroidManifest.bt` 模板看清结构，再根据 AXMLPrinter2 报错逐一定位并还原被改的 `magic`（0x00080003）、`stylesStart`（正常为 0）与 `stringCount`（应等于真实字符串数），即可重新反编译出明文 Manifest。

## 原理

- **AXML 结构**：二进制 AndroidManifest.xml 先是 8 字节文件头——4 字节 magic（正常 `03 00 08 00`，小端即 0x00080003）加 4 字节文件大小；紧跟 StringPool chunk（chunk 头从偏移 0x08 开始）：`stringCount` 在 0x10、`styleCount` 在 0x14、`flags` 在 0x18、`stringsStart` 在 0x1C、`stylesStart` 在 0x20，之后是 `stringOffsets[stringCount]` 数组，再往后是字符串数据区。
- **字符串定位方法**：`stringsStart` 是相对 chunk 起始（文件偏移 0x08）的偏移，示例值 0xAC 需加 8 得到绝对位置 0xB4；第一个字符串偏移 `stringOffsets[0]=0`，故第一个字符串在 0xB4；该处首字节 0x05 为长度，后接 `theme`，以 00 结束。理解该寻址方式后，才能判断被改字段对解析器意味着什么。
- **加固手法 1——改 magic**：把 `03 00 08 00` 改成 `00 00 08 00`（0x00080000）；AXMLPrinter2 报 `Expected chunk of type 0x80003, read 0x80000`，直接拒绝解析。
- **加固手法 2——改 stylesStart**：在 0x20 写入 `00 EE FF EE` 之类的异常值（正常应为 0）；解析器按该值计算样式区偏移/长度时得到负数，抛 `NegativeArraySizeException`。
- **加固手法 3——放大 stringCount**：把 0x10 处的字符串数量从真实值（示例 36/0x24）改成 0xFF；解析器据此把后续数据全部当作 `stringOffsets` 数组读取，偏移值离谱，010Editor 模板中 `stringoffsets[255]` 及后续 `stringstrdata` 全部标红报错，AXMLPrinter2 最终报 `Invalid chunk type (24)`。
- **修复思路**：AXMLPrinter2 的报错会指出期望值与实际读取值——先转换报错中的数字，再回到 010Editor 对照模板与正常 Manifest，把被魔改字段改回合法值；每次只修一处、重新运行，逐步推进到完整反编译。
- **为什么有效**：AXML 是自描述结构，各字段之间有冗余约束（magic 固定、stringCount 与字符串表长度/后续 chunk 位置一致、stylesStart 通常为 0）；加固只能破坏解析器读取，无法同时保持这些约束，因此可依据报错与对照逐字段判定并还原。

## 触发条件

- 取得恶意/加固 APK，其 `AndroidManifest.xml` 为二进制 AXML 且被篡改，常规反编译工具（apktool、AXMLPrinter2、androguard）解析失败。
- 分析环境有 010Editor（可安装模板库）或等效十六进制编辑器，以及 AXMLPrinter2.jar/Java 环境。
- 能获得同应用的正常版本或已知正常 Manifest 作为对照（可选但显著加速）。

## 利用步骤

1. 从 APK 解出二进制 `AndroidManifest.xml`（zip 内的该文件），用 `java -jar AXMLPrinter2.jar AndroidManifest.xml` 复现报错。
2. 在 010Editor 中安装并运行 `AndroidManifest.bt` 模板（模板库搜索 androidmanifest.bt），确认文件头、StringPool 各字段与字符串区结构，记录异常字段。
3. 按报错修第一处：如 `Expected chunk of type 0x80003, read 0x80000`，把文件头 magic 改回 `03 00 08 00`。
4. 再次运行，遇到 `NegativeArraySizeException` 时定位 0x20 的 `stylesStart`，对照正常样本改为 `00 00 00 00`。
5. 再次运行，若因 `stringCount` 被改大而出现偏移数组异常/`Invalid chunk type (24)`，把 0x10 处数量改回真实值（示例 0x24=36，可由模板/正常样本确认）。
6. 重复「运行—读报错—改字段」，直至 AXMLPrinter2 输出完整明文 XML（`<manifest ...>`、versionCode/versionName、package 等）。

## PoC

```text
# 复现与逐步排错（原文流程）
java -jar AXMLPrinter2.jar AndroidManifest.xml
# 报错1: java.io.IOException: Expected chunk of type 0x80003, read 0x80000
#   -> 010Editor 把文件头 00 00 08 00 改回 03 00 08 00
# 报错2: java.lang.NegativeArraySizeException: -71304363
#   -> 0x20 stylesStart 原为 00 EE FF EE，正常应为 00 00 00 00
# 报错3: java.io.IOException: Invalid chunk type (24)
#   -> 0x10 stringCount 被改为 0xFF，正常为 0x24(36)
java -jar AXMLPrinter2.jar AndroidManifest.xml
# 输出 <?xml version="1.0" encoding="utf-8"?><manifest ...>
```

说明：偏移按原文示例文件（文件大小 0x9B4、stringsStart 0xAC、stringCount 36）标注，实际样本需结合 010Editor 模板核对；未在原文之外复跑。

## 变体与关联

- [[mobile-android-dex-format-manual-parse]]：DEX 结构手工解析；本卡是同类「文件格式层逆向」在 AXML 上的应用，思路均为按头部字段偏移手工核对。
- [[mobile-android-apk-static-entry-layout-resource-locate]]：APK 静态入口定位；本卡是其前置——Manifest 被加固时先修复才能定位入口组件。
- 变体：除 magic/stylesStart/stringCount 外，还可能篡改 `stringsStart`、chunk size、stringOffsets 数组内容或插入垃圾 chunk；修复原则相同（对照正常样本 + 解析器报错）。
- 工具替代：010Editor 模板可换 `axml`/androguard 的 Python 解析脚本，AXMLPrinter2 可换 apktool（其报错信息也可用于定位）。
- 边界：若字符串数据区本身被加密/压缩（不仅是头部字段），仅修头部无法恢复，需要脱壳或从运行时内存 dump。

## 检测与防御

- 检测（样本分析/查杀）：校验 AXML 文件头 magic 是否为 0x00080003、文件大小字段与实际长度一致、`stringCount` 与 `stringsStart`/后续 chunk 偏移自洽、`stylesStart` 为 0 或合法；头部字段异常可作为加固/免杀样本的启发式特征。
- 检测：APK 中 AndroidManifest.xml 无法被常规工具解析而其他资源正常，通常意味着被恶意篡改；可结合 YARA 规则匹配异常头字段。
- 防御（分析侧）：建立正常 Manifest 对照库；用容错解析器（如 androguard 的 AXML 解析）输出字段级诊断，而不是只依赖 apktool；保留原始字节以便还原。
- 说明：本卡为逆向分析/抗混淆技术，本身不构成漏洞利用；加固只提高分析成本，不能阻止有对照样本的分析。
