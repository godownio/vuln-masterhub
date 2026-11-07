# .NET 反序列化

## 这层是什么

BinaryFormatter、LosFormatter、ObjectStateFormatter 等。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [ASP.NET ViewStateUserKey/Anti-XSRF 防护绕过：选择未继承母版页的 Download.aspx 伪造 ViewState](web-dotnet-deser-viewstate-userkey-masterpage-bypass.md) | verified | high | 2026-11-06 |
| [CVE-2019-18935 定制 WAF 绕过：参数源迁移、密文等价变异与加密 metadata](web-dotnet-deser-telerik-cve-2019-18935-waf-bypass.md) | verified | high | 2026-11-05 |
| [ERP OpenServerDialog 任意类实例化叠加 BinaryFormatter 反序列化 RCE](web-dotnet-deser-erp-openserverdialog-binaryformatter-rce.md) | verified | high | 2026-11-04 |
| [SharePoint ToolShell（CVE-2025-53770）：SignOut Referer 认证绕过 + ExcelDataSet 反序列化 RCE](web-dotnet-deser-sharepoint-toolshell-cve-2025-53770.md) | verified | medium | 2026-11-06 |
| [Telerik.Web.UI CVE-2019-18935：外部 Type 驱动 JavaScriptSerializer 加载混合模式 DLL](web-dotnet-deser-telerik-cve-2019-18935-assemblyinstaller.md) | verified | high | 2026-11-05 |
| [U9 ERP DataTransfer 导入包无 Binder 的 BinaryFormatter 反序列化 RCE](web-dotnet-deser-u9-datatransfer-binaryformatter-rce.md) | verified | high | 2026-11-05 |
| [已知 MachineKey 伪造 ASP.NET ViewState：ysoserial.net TextFormattingRunProperties 反序列化 RCE](web-dotnet-deser-viewstate-machinekey-textformattingrunproperties.md) | verified | high | 2026-11-05 |
| [未授权 ServiceHandler 配合 TypeNameHandling.All 的 JSON 反序列化](web-dotnet-deser-servicehandler-typenamehandling.md) | verified | medium | 2026-11-04 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
