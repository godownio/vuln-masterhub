---
id: web-java-framework-do-filter-reflection-dispatch
title: Java *.do 过滤器按 URL 反射调用任意 Action 方法导致未授权 SQL 注入
type: scenario
domain: web
path: web/java/framework
technique: do-filter-url-reflection-dispatch
tags:
- java
- servlet
- filter
- reflection
- unauth
- sqli
- action
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:42:44+08:00'
  notes: 已对照原文核对：*.do过滤器按URL类名!方法名反射Class.forName/newInstance/getMethod/invoke，无登录校验；StudentAction!getStudentListJson.do?studentNo=...注入返回200含IDCard/passWord，截图佐证。原文脱敏，类名需按目标枚举；未设versions；未执行PoC
url: /docs/web/java/framework/web-java-framework-do-filter-reflection-dispatch/
draft: false
kb_aliases:
- .do 反射调用链
- URL 指定类名方法名
- Java 反射分发绕过认证
- 类名!方法名.do
- StudentAction!getStudentListJson.do
---

## 一句话结论

当 `*.do` 过滤器把 URL 中的 `类名!方法名` 直接拼成完整类名，用 `Class.forName` + `newInstance` + `getMethod` + `invoke` 反射执行，且执行前没有登录校验时，攻击者可以未授权调用 Action 中的任意 public 无参方法；若该方法从 request 取参并拼接 SQL，就形成“一行 URL = 指定类 + 指定方法 + 注入参数”的未授权 SQL 注入。

## 原理

过滤器 `doFilter` 的处理流程：

1. 取 `request.getRequestURI()`，例如 `/StudentAction!getStudentListJson.do`；
2. 截取 `.do` 前的 `StudentAction!getStudentListJson`，按 `!` 拆成类名与方法名；
3. 拼成 `com.xql.action.StudentAction`，`Class.forName` 加载并 `newInstance`；
4. 反射调用 `setRequest(request)` 把当前请求对象塞进 Action；
5. `getMethod(methodName, new Class[0])` 取无参方法并 `invoke`。

危险点有三层叠加：

- **类名、方法名由 URL 控制**：`!` 前后完全来自用户，等于把“调用哪个类的哪个方法”暴露给攻击者；
- **没有认证**：过滤器只做分发，没有校验 session/用户，任何能访问 `*.do` 的人都可调用；
- **方法内部继续信任 request**：反射调用的是无参方法，但 Action 通过 `this.getRequest().getParameter(...)` 取参数，所以“无参方法”仍可携带攻击参数；示例 `getStudentListJson()` 把 `studentNo` 直接拼进 `select * from student where studentNo='...'`，再由 `Statement` 执行。

因此攻击者不需要登录，也不需要知道路由配置：只要知道（或猜到）Action 类名和方法名，就能触发其业务逻辑；再叠加 DAO 层的字符串拼接，就得到未授权注入与数据泄露。

## 触发条件

- Java Web（Servlet 容器），存在映射到 `*.do` 的过滤器；
- 过滤器用 URL 的 `类名!方法名` 反射调用，且没有在 `invoke` 前做登录/角色校验；
- Action 类位于固定包下、有无参 public 方法，并提供 `setRequest` 一类方法把 request 注入；
- 至少有一个 Action 方法读取 request 参数并拼接 SQL/执行危险操作；
- URL 中的 `!`、`.` 未被前置过滤器拦截。

## 利用步骤

1. 从 JSP/JS/静态资源、报错页或源码中收集 Action 类名与方法名，确认 URL 形如 `/ClassName!methodName.do`。
2. 直接请求一个业务方法，观察是否需要登录；若返回 200 与业务数据，说明未授权可达。
3. 找到该方法使用的参数名（如 `studentNo`），先发正常值确认回显。
4. 拼接 SQL 测试：`studentNo=2201104001' and '1'='1`，对比正常/异常响应。
5. 进一步用 `UNION`、布尔或时间盲注读取其他表；若方法本身执行文件/命令操作，也可直接调用对应方法。

## PoC

```http
GET /StudentAction!getStudentListJson.do?studentNo=2201104001%27%20and%20%271%27=%271 HTTP/1.1
Host: target
```

响应为 JSON 数组，包含 `studentNo`、`name`、`IDCard`、`passWord` 等字段，说明反射链已执行且 `studentNo` 被拼进 SQL。通用形态：

```text
/ClassName!methodName.do?param=<payload>
```

注意 `.do` 前的 `!` 与类名/方法名需按目标实际包名和 Action 命名调整；反射只调用无参方法，参数必须通过 request（GET/POST/Cookie）传入。

## 变体与关联

- 变体：调用 Action 中其他 public 无参方法（导出、删除、查询、文件操作）；结合 `setRequest` 之外的其他注入方法（如 `setResponse`、`setSession`）。
- 变体：若过滤器对类名做了包前缀限制，仍可在该包内枚举 Action；若方法名有后缀/前缀规则，按规则构造。
- 关联：[[web-generic-auth-servlet-null-role-fail-open]]（同一系统的另一处鉴权逻辑缺陷）；[[web-generic-auth-type-dispatch-unauth-data-exposure]]（无认证分发接口泄露数据）；[[web-generic-sqli-metinfo-search-para-base64-blind]]（另一种未授权注入入口）。
- 不确定点：文章对包名/类名做了脱敏，实际类名需按目标枚举；反射方法为无参调用，带参方法不能直接通过 URL 调用。

## 检测与防御

- **日志检测**：URL 中出现 `!` 且以 `.do` 结尾；Action 类名/方法名不在正常前端调用集合；同一 IP 枚举大量 `XxxAction!yyy.do`；请求参数含 SQL 关键字。
- **修复**：不要用 URL 反射任意类/方法；改为显式路由表或注解映射，并在分发前做统一认证与角色校验；Action 方法只允许白名单。
- **纵深防御**：DAO 全部改 `PreparedStatement` 参数化；对 Action 方法做权限注解/拦截器；限制 `Class.forName` 的可加载包范围。
- **审计要点**：搜索 `*.do` 过滤器中的 `Class.forName`、`newInstance`、`getMethod`、`invoke`，以及 `getRequest().getParameter` 到 SQL 拼接的闭合链。
