---
id: code-analysis-source-audit-feature-code-reuse-sibling-sink-mining
title: 从 1day 特征代码复用批量挖同系统 0day：Multipart 强转与 setOrder 特征全局搜索
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: feature-code-reuse-sibling-sink-mining
aliases:
- 1day 挖 0day
- 特征代码复用
- 同系统同类型接口批量审计
- MultipartHttpServletRequest 特征搜索
- setOrder 特征搜索
tags:
- code-analysis
- source-audit
- code-reuse
- 0day
- java
- multipart
- mybatis
- sql-injection
- file-upload
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T07:00:16+08:00'
  notes: 已对照原文与图32-35核对：MultipartHttpServletRequest强转特征搜索命中9文件9处、分析后8处任意上传（名单与原文一致）；.setOrder(order)搜索45文件86处；方法为1day特征代码→全库搜索→人工确认参数可控与sink，PoC为搜索清单而非漏洞利用；原文未逐接口验证，卡内已注明
---

## 一句话结论

同一套系统里同类功能往往由同一段代码复制而来：从已披露的 1day 漏洞代码中提取“这个系统特有”的代码写法（如 `MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest)request;`、`record.setOrder(order);`），用 IDE 全局搜索定位所有相同特征，再逐个确认参数可控性与 sink，就能把单个已知漏洞快速扩展成一批同系统 0day 接口。

## 原理

- 代码复用的必然性：一个产品里多个 Controller/Action 处理同类业务（上传、分页查询）时，开发者通常复制同一段模板代码，只改路由和字段名；安全补丁也常只修被披露的那一个入口，兄弟接口继续保留原缺陷。
- 特征代码的可搜索性：某些写法是该系统/框架组合特有的，例如把 `HttpServletRequest` 强转为 `MultipartHttpServletRequest`、对分页参数统一 `record.setOrder(order)`。这些字符串在代码库中出现的次数有限，适合作为“锚点”。
- 漏洞扩展方法：1day 披露的 diff、PoC 或审计报告给出一个入口和一段 sink 代码 → 从这段代码提取最小特征字符串 → 全库搜索同名 API/同段逻辑 → 对每个命中点检查“输入是否来自 @RequestParam/getParameter/原始文件名”和“最终 sink 是否相同（Files.copy、`${}` 拼接等）”。
- 该方法的局限：搜索命中不等于可利用，仍需逐个验证鉴权、参数可控性、路径/后缀校验与运行环境；不同接口可能有额外过滤或不同框架版本。

## 触发条件

- 已有该系统的 1day 漏洞细节（代码段、PoC 或补丁 diff），或能拿到反编译源码。
- 系统规模较大、同类功能多，且存在明显的复制粘贴式代码。
- 漏洞特征字符串足够独特，能在全库中缩小到可人工审阅的数量（几十处以内最佳）。
- 审计者能区分“相同 sink”与“仅相似命名”，避免把安全写法误判为漏洞。

## 利用步骤

1. 选定一个已知漏洞入口，阅读其 Controller → Service → DAO/工具类完整代码，提取 2–5 行最独特的特征代码。
2. 在 IDE 中全局搜索该特征（如 `MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest)request;`），记录所有文件与行号。
3. 对每个命中点检查：请求参数/文件名/排序字段是否由客户端控制；是否有后缀白名单、`..` 过滤、路径规范化、鉴权。
4. 对通过初筛的接口构造与 1day 相同或相近的 PoC，确认可达与 sink 行为。
5. 记录“新增可利用接口清单”，并在授权范围内验证；未验证的只作为待测线索，不当作已完成漏洞。
6. 反向补充特征：例如 SQL 注入的 `order` 参数常用 `.setOrder(order);`，可再用 Mapper 中的 `${order}`/`${columnKey}` 交叉搜索，提高命中率。

## PoC

文章中的两个特征搜索示例：

```text
搜索: MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest)request;
结果: 9 处命中（9 个文件），分析后 8 处存在任意文件上传：
  ResourceUploadController.resourceUploadFile
  DgmCommandController.resourceUploadFile
  EmployeeCardRecordController.employeeCardRecordImport
  BlackListController.uploadMeetingFile
  MeetingController.uploadMeetingFile
  MeetingPersonalController.uploadMeetingFile
  VisitorMapConfigController.uploadMapFile
  MobiMeetingAppController.uploadMeetingFile
```

```text
搜索: .setOrder(order);
结果: 45 个文件、86 处匹配；结合 Mapper 的 ${columnKey} ${order} 可快速筛出大量 ORDER BY 注入接口
```

原文未列出全部注入接口与逐个验证结果，只给出搜索命中数量与 8 个上传接口名单。

## 变体与关联

- 特征选择变体：`getOriginalFilename()`、`new FileInputStream(`、`JSON.parseObject(`、`${` + `order`、`Files.copy(`、`Runtime.getRuntime().exec` 等，按目标系统代码风格选择。
- 跨系统变体：同一厂商的不同产品/版本常共享代码库，可用同一特征跨产品搜索。
- 关联：本文章中的任意文件上传、MyBatis 排序注入、任意文件读取均可用该方法从单个 1day 扩展到多个接口。
- 与 SAST 的关系：CodeQL/Tai-e 等工具可自动化部分数据流，但“特征字符串 + 人工确认”在拿不到完整构建或规则覆盖不足时更快。

## 检测与防御

- 防御（开发侧）：修复漏洞时不要只修被披露的入口，应按 sink/特征全库排查同类代码；把安全校验下沉到公共工具/框架，避免复制粘贴式缺陷。
- 检测（防守侧）：关注同一系统在短时间内被批量测试多个同类型接口（上传、列表排序、下载），可能是攻击者在用特征复用方法扩展攻击面。
- 治理：建立危险 API 清单与代码评审规则（`MultipartHttpServletRequest` 强转、`${}` 拼接、原始文件名直用、`new FileInputStream`），在 CI 中做特征扫描。
