---
id: web-generic-auth-servlet-null-role-fail-open
title: Servlet 权限表达式在 session 角色为 null 时放行导致未登录访问业务
type: scenario
domain: web
path: web/generic/auth
technique: null-role-check-fail-open
tags:
- auth-bypass
- java
- servlet
- session
- access-control
- logic-flaw
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:42:46+08:00'
  notes: 已对照原文核对：performTask权限表达式把(roleList=session.getAttribute(...))==null作为放行分支，未登录operType=6直达业务，截图1返回学生数据。卡片已注明线上可能已补入口、需看业务方法二次校验；未设versions；未执行PoC
url: /docs/web/generic/auth/web-generic-auth-servlet-null-role-fail-open/
draft: false
kb_aliases:
- 权限判断 null 放行
- roleList null 绕过
- 未登录绕过鉴权
- 门卫逻辑反转
- 权限校验短路
---

## 一句话结论

Servlet 的权限判断写成 `if (!(白名单操作 || (roleList = session.getAttribute("Login_UserRoleList")) == null || checkRole(...)))` 时，未登录用户的 session 中根本没有该属性，`roleList` 为 null 使内层表达式为 true，取反后不进入拦截分支——结果是“没带工牌的人反而被放行”。

## 原理

把表达式拆开看：

```java
if (!(operType.equals("-1") || operType.equals("1") || operType.equals("911")
   || operType.equals("62") || operType.substring(0, 1).equals("3")
   || (roleList = (String)session.getAttribute("Login_UserRoleList")) == null
   || this.checkRole(operType, roleList))) {
    // 无权限 → error.jsp
}
```

设计意图可能是“白名单操作放行；已登录且角色匹配放行；其他拦截”。但 `roleList == null` 被放在 `||` 链中，含义变成了“没有角色列表也放行”：

- 已登录且角色匹配：`checkRole` 为 true → 内层 true → 不拦截；
- 已登录但角色不匹配：`checkRole` 为 false，`roleList != null` → 内层 false → 拦截；
- **未登录**：session 无 `Login_UserRoleList` → 赋值结果为 null → `roleList == null` 为 true → 内层 true → **不拦截**。

登录校验应默认拒绝，只有明确满足条件才放行；这里把“缺失属性”当成了通过条件，属于 fail-open（失败开放）。白名单中的 `operType`（如 1 登录、6 查询）进一步扩大了可达范围。

## 触发条件

- Java Servlet 的 `performTask` 一类入口用上述复合条件做权限判断；
- 权限依据来自 session 属性，且未登录时该属性不存在（而不是空集合或默认角色）；
- 攻击者能访问 Servlet 并控制 `operType`；
- 目标 `operType` 对应的业务方法在放行后可直接执行（如查询学生、导出数据）。

## 利用步骤

1. 确认 Servlet 入口和 `operType` 参数；从报错、页面 JS 或源码中收集操作码。
2. 不带 Cookie/未登录直接请求一个非白名单操作，例如 `operType=6`。
3. 观察响应：若返回 200 与业务数据/错误页但未跳转登录，说明已进入业务代码。
4. 枚举其他 `operType`（查询、导出、修改）扩大影响面。
5. 若线上已补入口（返回 401/登录页），仍可结合其他缺陷或同款未修补实例利用；源码缺陷本身仍应报告。

## PoC

```http
POST /***servlet HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

operType=6
```

预期两种结果：

- `401` 或跳转登录：线上入口已修补；
- `200` + 业务数据/业务错误页：未登录已进入业务代码，鉴权短路成立。

## 变体与关联

- 变体：`roleList == null` 换成 `roleList.isEmpty()`、`session.getAttribute(...) == null`、`user == null` 等“缺失即放行”的写法；角色列表为空数组/空字符串时同样可能短路。
- 变体：条件里混入 `||` 而非 `&&`、取反层级错误、默认返回 true 的 `checkRole`。
- 关联：[[web-java-framework-do-filter-reflection-dispatch]]（同一系统的反射分发未授权入口）；[[web-generic-auth-type-dispatch-unauth-data-exposure]]（另一处完全缺失鉴权的接口）。
- 不确定点：文章对 Servlet 名和操作码做了脱敏；是否可利用取决于该 `operType` 对应的业务方法是否有二次校验。

## 检测与防御

- **代码审计**：搜索 `getAttribute("Login_UserRoleList")`、`== null` 与权限判断的组合；重点看 `if (!(...))` 中是否把“无 session/无角色”当成放行条件。
- **正确写法**：默认拒绝，先判断 `user != null` 且 `roleList != null`，再判断角色；白名单只保留登录等必要操作，并单独校验。
- **统一入口**：用认证过滤器/拦截器统一拦截，业务 Servlet 不各自实现权限判断；对未登录请求返回 401/302。
- **测试**：把“无 Cookie”“空角色”“角色不匹配”“白名单操作”写成四组回归用例，断言只有明确允许的组合才放行。
- **日志**：记录 `operType`、session 是否存在、命中哪条放行分支，便于发现异常放行。
