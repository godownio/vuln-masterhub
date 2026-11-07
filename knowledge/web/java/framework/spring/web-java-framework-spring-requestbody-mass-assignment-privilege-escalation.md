---
id: web-java-framework-spring-requestbody-mass-assignment-privilege-escalation
title: Spring @RequestBody 大量赋值：普通用户注入 role 字段注册为管理员
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-requestbody-mass-assignment
aliases:
- 大量赋值漏洞
- Mass Assignment
- 批量赋值
- '@RequestBody 参数绑定'
- 敏感字段注入
- role 字段注入提权
- Spring 自动绑定提权
tags:
- java
- spring
- mass-assignment
- parameter-binding
- privilege-escalation
- api
- json
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:44:00+08:00'
  notes: 已对照原文大量赋值原理示例核对：@RequestBody 直接绑定 User 实体，前端只发 name/password，role 由 DB 默认 user；未限制绑定字段时可注入 role=admin 落库。卡内将机制泛化到 id/userId/balance/price/status/deleted 等字段，属同一根因的合理变体。原文未给 Spring 受影响版本，未设置 affected_versions。未复现 PoC。
---

## 一句话结论

Spring MVC 控制器用 `@RequestBody` 把 JSON 请求体直接绑定到实体对象、随后原样交给 service 持久化，且没有在保存前显式重置敏感字段时，攻击者只要在请求体里多带一个 `role`（或 `isAdmin`、`status`、`deleted` 等）字段，就能让后端把该值写入数据库，实现普通用户注册即管理员或篡改受保护属性。

## 原理

- Spring MVC 的 `HttpMessageConverter`（默认 Jackson）按 JSON 属性名与目标 POJO 的 setter/字段匹配并逐项赋值。它只负责“能绑就绑”，不区分布局字段是否应该由客户端控制。
- 前端注册代码只发送 `name` 和 `password`，`role` 由数据库默认值 `'user'` 填充；但 `@RequestBody User newUser` 会把请求体中出现的任意 `role` 属性也调用 `setRole("admin")`，于是对象在进入 service 前就已是管理员角色。
- 控制器随后调用 `userService.save(newUser)` 或 MyBatis 的 insert/update，把绑定后的对象整体落库。根因不是反序列化漏洞，而是**缺少字段白名单/禁止绑定列表，也没有在保存前显式覆盖敏感字段**。
- 同一机制适用于所有可写的业务实体属性：`id`（覆盖他人记录）、`userId`/`ownerId`（越权归属）、`balance`/`price`（金额篡改）、`status`/`auditStatus`（绕过审核）、`deleted`（逻辑删除）、`createTime`/`updateTime` 等。

## 触发条件

- 控制器方法参数使用 `@RequestBody <实体或宽泛 DTO>`，且未使用专用入参 DTO。
- 绑定对象包含敏感属性及 public setter；属性不在 `@JsonIgnore` 或 `@JsonProperty(access = READ_ONLY)` 之列。
- 控制器没有在调用 service 前显式设置/校验该字段（如 `newUser.setRole("user")`），也没有 `@InitBinder` 的 `setAllowedFields` 白名单。
- 接口对普通用户/未登录用户可达，且请求 `Content-Type: application/json` 能被正常解析。

## 利用步骤

1. 找到使用 `@RequestBody` 接收 JSON 的写接口（注册、资料修改、下单、评论、创建资源等）。
2. 从前端请求或接口文档确认正常字段，再从源码/建表语句/接口返回中推测实体敏感字段名（`role`、`isAdmin`、`status`、`deleted`、`price`、`userId` 等）。
3. 在正常 JSON 中追加候选字段，观察响应中该字段是否被回显、后续查询是否生效；也可用布尔/枚举值逐个 FUZZ。
4. 注册场景直接追加 `"role":"admin"`，随后用该账号登录后台或访问管理员接口验证权限。
5. 修改场景追加 `"userId":<他人ID>`、`"price":0.01`、`"status":1` 等，验证越权归属、金额篡改或审核绕过。

## PoC

存在漏洞的控制器与实体：

```java
public class User {
    private String name;
    private String password;
    private String role;   // 敏感字段，带 public setRole
    // getters/setters
}

@PostMapping("/register")
public ResponseEntity<User> register(@RequestBody User newUser) {
    userService.save(newUser);   // 未重置 role
    return ResponseEntity.ok(newUser);
}
```

正常请求与大量赋值请求的差异只在多出的字段：

```http
POST /user/register HTTP/1.1
Host: target
Content-Type: application/json

{"name":"attacker","password":"P@ssw0rd","role":"admin"}
```

修复方式（任选其一或组合）：

```java
// 1) 保存前显式覆盖
newUser.setRole("user");

// 2) 使用只含允许字段的 DTO，再手工映射
public class RegisterRequest { private String name; private String password; }

// 3) 实体字段禁止反序列化
@JsonProperty(access = JsonProperty.Access.READ_ONLY)
private String role;

// 4) Spring WebDataBinder 白名单（@ModelAttribute 表单绑定同样适用）
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("name", "password");
}
```

## 变体与关联

- 变体：`@ModelAttribute` 表单绑定、Spring WebFlux 的函数式路由 + `ServerRequest.bodyToMono(Entity.class)` 有相同风险；核心都是“客户端可控属性名直接映射到服务端对象”。
- 变体：嵌套对象与集合也可被赋值（如 `{"profile":{"isAdmin":true}}`、`{"items":[{"price":0}]}`），白名单需要覆盖嵌套路径。
- 变体：MyBatis Generator 生成的实体常带 `setDeleted`、`setAdminContent` 等运维字段，是 CodeQL/人工审计的高价值目标。
- 关联卡片：[[web-java-framework-spring-requestbody-mass-assignment-admin-content-forgery]]（同一根因导致内容伪造）、[[code-analysis-sast-codeql-spring-mass-assignment-query]]（自动化发现方法）。

## 检测与防御

- 检测特征：`@RequestBody` 参数类型为实体/含敏感 setter 的类；该参数在方法内被直接传给 service；方法体中没有对应 `setXxx` 显式赋值；实体字段缺少 `@JsonIgnore`/只读注解。
- 运行时检测：对比请求 JSON 字段与接口 schema，记录超出白名单的属性；对注册/资料修改接口监控 `role`、`isAdmin`、`status` 等字段出现。
- 修复：默认使用请求 DTO（只声明允许字段）；实体敏感字段加只读注解；保存前显式设置服务端决定的值；用 `@InitBinder` 或全局 `WebDataBinder` 配置允许字段；对更新接口采用字段级授权校验，而不是整体覆盖。
- 注意：仅靠前端不发送字段无效，攻击者可直接构造请求；仅靠 WAF 关键字也容易被大小写、嵌套、额外字段绕过。
