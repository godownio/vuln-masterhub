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
| [.NET Json.NET 新 gadget XamlImageInfo：构造 Stream 注入 XAML，经 XamlReader.Load 触发 ObjectDataProvider RCE（LazyFileStream SMB / ReadOnlyStreamFromStrings 内联两链）](web-dotnet-deser-xamlimageinfo-lazyfilestream-xamlreader-rce.md) | verified | high | 2026-11-12 |
| [.NET Remoting 未授权反序列化：BinaryServerFormatterSinkProvider 配 TypeFilterLevel.Full 直接接收 BinaryFormatter 载荷](web-dotnet-deser-remoting-typefilterlevel-full.md) | verified | medium | 2026-11-12 |
| [.NET TransactionManager.Reenlist 分布式事务反序列化：int32=1 前缀校验后用 BinaryFormatter 还原事务数据触发 RCE（含 Sharp4TransactionManager.aspx Webshell）](web-dotnet-deser-transactionmanager-reenlist-binaryformatter-rce.md) | verified | high | 2026-11-12 |
| [ActiveMQ NMS .NET 客户端 ActiveMQObjectMessage.Body 无类型校验反序列化：消费恶意 ObjectMessage 即触发 BinaryFormatter RCE](web-dotnet-deser-activemq-nms-objectmessage-body-binaryformatter.md) | verified | high | 2026-11-13 |
| [ActivitySurrogateSelector + LINQ 延迟执行 gadget：ObjectSerializedRef 包装任意类型，PagedDataSource/AggregateDictionary/DesignerVerb 串联到 Assembly.Load/Activator.CreateInstance](web-dotnet-deser-activitysurrogateselector-linq-assembly-load-gadget.md) | verified | high | 2026-11-13 |
| [ActivitySurrogateSelector 类型检查绕过：ObjectDataProvider 反序列化先改 AppSettings.DisableActivitySurrogateSelectorTypeCheck](web-dotnet-deser-activitysurrogateselector-disable-typecheck-bypass.md) | verified | medium | 2026-11-11 |
| [AjaxPro CVE-2021-23758：ajaxpro/*.ashx 调用 [AjaxMethod] 并把 object 参数反序列化，ObjectDataProvider 链执行命令](web-dotnet-deser-ajaxpro-cve-2021-23758-objectdataprovider.md) | verified | high | 2026-11-11 |
| [ASP.NET ViewStateUserKey/Anti-XSRF 防护绕过：选择未继承母版页的 Download.aspx 伪造 ViewState](web-dotnet-deser-viewstate-userkey-masterpage-bypass.md) | verified | high | 2026-11-06 |
| [BinaryFormatter SerializationBinder 黑名单绕过：BindToType 返回 null 不阻断（FastBindToType 回退）+ 类型名改用 AssemblyQualifiedName 等可解析变体绕过字符串比对](web-dotnet-deser-binaryformatter-serializationbinder-bypass.md) | verified | high | 2026-11-13 |
| [CVE-2019-18935 定制 WAF 绕过：参数源迁移、密文等价变异与加密 metadata](web-dotnet-deser-telerik-cve-2019-18935-waf-bypass.md) | verified | high | 2026-11-05 |
| [DataSet 反序列化二段载体：Tables_0 字段经 DeserializeDataSetSchema 再走 BinaryFormatter，XmlDiffGram 经 ReadXml 再走 XmlSerializer（含 TypeSpoof 变体）](web-dotnet-deser-dataset-serializationinfo-tables-binaryformatter-readxml-xmlserializer.md) | verified | high | 2026-11-13 |
| [ERP OpenServerDialog 任意类实例化叠加 BinaryFormatter 反序列化 RCE](web-dotnet-deser-erp-openserverdialog-binaryformatter-rce.md) | verified | high | 2026-11-04 |
| [JSON.NET GetterSecurityException gadget：SecurityException.Method getter 触发 BinaryFormatter 反序列化，PropertyGrid.SelectedObjects 递归读取属性完成 RCE](web-dotnet-deser-json-net-gettersecurityexception-propertygrid.md) | verified | high | 2026-11-13 |
| [JsonSerializationBinder 白/黑名单绕过：产品内置 PowerShellLauncher.Run 任意方法调用或 WindowsIdentity 绕过 IsSecurityCritical（CVE-2024-23478）](web-dotnet-deser-json-net-serializationbinder-whitelist-bypass.md) | verified | high | 2026-11-10 |
| [LosFormatter/ObjectStateFormatter 二次反序列化：ClaimsIdentity/WindowsIdentity/RolePrincipal/SessionSecurityToken 等类在反序列化构造函数中再次 BinaryFormatter.Deserialize](web-dotnet-deser-losformatter-objectstateformatter-claims-identity-second-order.md) | verified | high | 2026-11-13 |
| [PSObject + ObjectDataProvider gadget：反序列化构造函数读 CliXml 交给 PSSerializer.Deserialize，经 XamlReader.Parse 执行 ObjectDataProvider](web-dotnet-deser-psobject-clixml-psserializer-xamlreader.md) | verified | medium | 2026-11-13 |
| [SharePoint ToolShell（CVE-2025-53770）：SignOut Referer 认证绕过 + ExcelDataSet 反序列化 RCE](web-dotnet-deser-sharepoint-toolshell-cve-2025-53770.md) | verified | medium | 2026-11-06 |
| [SolarWinds Access Rights Manager AnalyzeActionController Json.NET 反序列化：FromJson + IFormTemplate 泛型值字段注入 ysoserial payload](web-dotnet-deser-solarwinds-arm-iformtemplate-typenamehandling.md) | verified | high | 2026-11-10 |
| [Telerik Reporting 报表 XML 反序列化 RCE（CVE-2024-1800/1801/1856）：旧版 Type 属性二次 XmlSerializer、新版 ReportXmlSerializer 按标签实例化，均可接 ExpandedWrapper/XamlReader gadget](web-dotnet-deser-telerik-reporting-xmlserializer-type-expandedwrapper-xamlreader.md) | verified | high | 2026-11-09 |
| [Telerik.Web.UI CVE-2019-18935：外部 Type 驱动 JavaScriptSerializer 加载混合模式 DLL](web-dotnet-deser-telerik-cve-2019-18935-assemblyinstaller.md) | verified | high | 2026-11-05 |
| [TextFormattingRunProperties gadget：ForegroundBrush 存 XAML，反序列化构造函数经 XamlReader.Parse 触发 ObjectDataProvider 命令执行](web-dotnet-deser-textformattingrunproperties-xamlreader-odp-gadget.md) | verified | high | 2026-11-13 |
| [ToolboxItemContainer 二段反序列化：ToolboxItemSerializer 反序列化构造函数直接把 Stream 字段交给 BinaryFormatter，可拖运任意内层 gadget 字节](web-dotnet-deser-toolboxitemcontainer-stream-field-binaryformatter.md) | verified | high | 2026-11-13 |
| [TypeConfuseDelegate：Comparer<string>.Create 混淆多播委托调用列表，SortedSet 反序列化时经 Compare 调用 Process.Start（.NET 4.5+）](web-dotnet-deser-typeconfusedelegate-sortedset-delegate-confusion.md) | verified | high | 2026-11-13 |
| [U9 ERP DataTransfer 导入包无 Binder 的 BinaryFormatter 反序列化 RCE](web-dotnet-deser-u9-datatransfer-binaryformatter-rce.md) | verified | high | 2026-11-05 |
| [XmlSerializer type 参数可控时选 ExpandedWrapper<XamlReader,ObjectDataProvider> 作反序列化根类型：XamlReader.Parse 解析 ResourceDictionary 启动进程](web-dotnet-deser-xmlserializer-type-expandedwrapper-xamlreader-odp.md) | verified | high | 2026-11-13 |
| [已知 MachineKey 伪造 ASP.NET ViewState：ysoserial.net TextFormattingRunProperties 反序列化 RCE](web-dotnet-deser-viewstate-machinekey-textformattingrunproperties.md) | verified | high | 2026-11-05 |
| [未授权 ServiceHandler 配合 TypeNameHandling.All 的 JSON 反序列化](web-dotnet-deser-servicehandler-typenamehandling.md) | verified | medium | 2026-11-04 |
| [金蝶云星空 KDSVC 接口 format=3 BinaryFormatter 前台反序列化 RCE](web-dotnet-deser-kingdee-kdsvc-binaryformatter-rce.md) | verified | high | 2026-11-12 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
