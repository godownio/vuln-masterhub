---
id: code-analysis-sast-codeql-spring-horizontal-authz-session-attribute
title: CodeQL 启发式挖 Spring MVC 水平越权：筛选未调用 HttpSession.getAttribute 的 Controller 方法
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-spring-horizontal-authz-session-absence
tags:
- codeql
- sast
- java
- spring
- access-control
- idor
- horizontal-privilege-escalation
- session
- code-audit
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V234
  verified_at: '2026-11-07T09:05:42+08:00'
  notes: 已对照 18753 原文与全部 8 张图片核对：callsHttpSessionGetAttribute/isController/isNotAdmin/returnsStringLiteral 四谓词与最终查询一致，结果 55→12→4、4 条为 defaultKaptcha/mallKaptcha/paySuccess/updateInfo 与 CodeQL 截图一致；paySuccess 按 orderNo 置已支付有请求/数据库截图佐证。未验证点：原文 updateInfo 片段实际从 session 取 userTemp.getUserId()，与文中“按传入 userId 任意修改”结论不一致（卡片已注明需按源码核对）；未复跑 CodeQL。dedup 候选 missing-auth-annotation 为注解鉴权缺失、目标不同，其余为 mass-assignment/multipart/tabby/gadget，非同一链。
url: /docs/code-analysis/static/sast/code-analysis-sast-codeql-spring-horizontal-authz-session-attribute/
draft: false
kb_aliases:
- CodeQL 水平越权
- ABAC 权限挖掘
- 未调用 getAttribute
- Spring Controller 越权审计
- HttpSession 身份获取缺失
- newbee-mall CodeQL
---

## 一句话结论

在 Spring MVC 项目里，如果水平鉴权的惯例是“从 `HttpSession.getAttribute(...)` 取当前用户，再与资源属主比较”，就可以用一段 CodeQL 查询枚举所有带路由注解、但没有调用 `HttpSession.getAttribute` 的 Controller 方法，再排除 `/admin` 控制器、VO 包和返回字符串字面量的模板渲染方法；原文在 newbee-mall 上把 55 条结果收敛到 12 条、再收敛到 4 条，发现 `paySuccess` 支付状态越权、`updateInfo` 资料越权和两个验证码接口。

## 原理

- **ABAC 水平鉴权的实现惯例**：控制器先从 session 取当前登录用户（`(NewBeeMallUserVO) httpSession.getAttribute(Constants.MALL_USER_SESSION_KEY)`），把 `userId` 写进待查询/待更新对象，服务层再检查数据库记录的 `userId` 是否等于当前用户。只要方法完全没有获取当前用户，就基本不可能做“资源属主”比较，因而是一个高价值的越权候选。
- **CodeQL 的匹配能力**：
  - `Call.getCallee() = targetMethod` 精确匹配被调用方法；
  - `targetMethod.hasName("getAttribute")` + `getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpSession")` 只匹配 `HttpSession.getAttribute`，不会误匹配同名方法；
  - `m = call.getEnclosingCallable()` 把调用点归属到所在方法；
  - `Method.getAnAnnotation()` + `Annotation.getType().hasQualifiedName(...)` 识别 `@GetMapping`/`@PostMapping`/`@RequestMapping`/`@PutMapping`/`@DeleteMapping`；
  - `getDeclaringType().getAnnotation()` 读取类级 `@RequestMapping("/admin")`；
  - `ReturnStmt`/`StringLiteral` 的 `getParent*()` 传递闭包判断方法是否直接返回字符串（模板视图）。
- **过滤策略**：
  1. `not callsHttpSessionGetAttribute(m)`：没有从 session 取身份；
  2. `isController(m)`：只保留路由方法；
  3. `isNotAdmin(m)`：排除类上标注 `@RequestMapping("/admin")` 的后台控制器（后台通常没有水平越权语义），并排除 `ltd.newbee.mall.controller.vo` 包；
  4. `not returnsStringLiteral(m)`：排除返回 `"mail/index"` 这类视图名的模板渲染 GET，减少页面路由噪声。
- **为什么能挖到真问题**：原文 55 条原始结果里大量是 `/admin` 与页面路由；过滤后剩 12 条，再排除模板渲染后剩 4 条：`defaultKaptcha`、`mallKaptcha`、`paySuccess`、`updateInfo`。人工跟进发现 `paySuccess` 直接按 `orderNo` 把订单置为已支付（无支付校验、无归属校验），`updateInfo` 的资料更新缺少当前用户与目标用户的一致性检查（具体版本可能从请求体取 `userId` 或从 session 取，需按源码核对），两个验证码接口则引出“验证码生命周期由客户端刷新控制”的问题。
- **为什么只是启发式**：调用了 `getAttribute` 不代表真的用了返回值，也不代表后续做了比较；反之，身份也可能来自 JWT、`SecurityContextHolder`、`@RequestAttribute`、网关头等。查询只负责把审计面从“全部 Controller”缩到“没有取 session 身份的方法”，最终必须阅读服务层与数据访问层确认。

## 触发条件

- 目标为 Java/Spring MVC 项目，有源码且能构建 CodeQL Java 数据库。
- 项目使用 session 保存登录用户，且水平鉴权惯例是从 `HttpSession.getAttribute` 取当前用户后再比较资源属主。
- 控制器混有后台路由（`/admin`）、VO 包、模板渲染路由等噪声，需要过滤条件。
- 目标接口可在部署环境访问，便于人工验证；CodeQL 结果只是候选清单。

## 利用步骤

1. 阅读一个已知有水平鉴权的接口（如购物车更新），确认当前用户来源与比较方式，记录 session key、用户 VO 类型与服务层检查逻辑。
2. 构建数据库：`codeql database create cq-db --language=java --command="mvn clean install -DskipTests" --source-root=. --overwrite`。
3. 编写查询：`callsHttpSessionGetAttribute`、`isController`、`isNotAdmin`、`returnsStringLiteral` 四个谓词，`select` 出同时满足“路由方法 + 未取 session 身份 + 非 admin + 非 VO + 非字符串返回”的方法。
4. 在 VS Code CodeQL 插件或 `codeql query run` 中执行；原文初始 55 条，加 admin/VO 过滤后 12 条，加字符串返回过滤后 4 条。
5. 逐条 triage：优先看直接修改订单/支付/资料/余额、按客户端 ID 查询或更新、调用 `selectByPrimaryKey`/`updateByPrimaryKeySelective` 的方法；跟进 service/mapper 确认是否有归属校验、支付校验、状态机校验。
6. 对候选接口构造两个账号的测试：用 A 的会话传 B 的资源 ID，观察是否成功；确认后形成漏洞报告。
7. 把查询放进 CI/代码审计流程，对新出现的无 session 身份路由做告警。

## PoC

```java
import java

predicate callsHttpSessionGetAttribute(Method m) {
  exists(Call call, Method targetMethod |
    call.getCallee() = targetMethod and
    targetMethod.hasName("getAttribute") and
    targetMethod.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpSession") and
    m = call.getEnclosingCallable()
  )
}

predicate isController(Method m) {
  exists(Annotation a |
    a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "GetMapping") or
    a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PostMapping") or
    a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping") or
    a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PutMapping") or
    a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "DeleteMapping")
    | a = m.getAnAnnotation()
  )
}

predicate isNotAdmin(Method m) {
  not exists(Annotation a, Literal l |
    a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping") and
    a.getValue("value") = l and
    l.getValue() = "/admin"
    | a = m.getDeclaringType().getAnAnnotation()
  ) and
  not m.getDeclaringType().getPackage().getName() = "ltd.newbee.mall.controller.vo"
}

predicate returnsStringLiteral(Method m) {
  exists(ReturnStmt r, StringLiteral s |
    r.getParent*() = m.getBody() and
    s.getParent*() = r
  )
}

from Method m
where not callsHttpSessionGetAttribute(m) and
      not returnsStringLiteral(m) and
      isController(m) and
      isNotAdmin(m)
select m
```

原文在 newbee-mall 上得到 4 条：`defaultKaptcha`、`mallKaptcha`、`paySuccess`、`updateInfo`；随后人工确认 `paySuccess` 可按任意 `orderNo` 把订单改为已支付，`updateInfo` 的资料更新缺少归属校验，验证码接口引出复用问题。

## 变体与关联

- **身份来源变体**：把 `HttpSession.getAttribute` 换成 `SecurityContextHolder.getContext().getAuthentication()`、JWT claim 解析、`@RequestAttribute`、网关注入的用户头；查询应匹配项目实际的身份获取 API。
- **数据流变体**：对候选方法再做一层污点分析，追踪 `@RequestParam`/`@RequestBody` 的 ID 是否流入 `selectByPrimaryKey`/`updateByPrimaryKey`/`deleteByPrimaryKey`，可进一步降低人工 triage 成本。
- **注解鉴权变体**：若项目用 `@PreAuthorize`/`@SaCheckPermission` 等方法注解，参考 [[code-analysis-sast-codeql-spring-missing-auth-annotation]] 查询“缺失注解”的接口。
- **框架变体**：Spring Data REST、MyBatis-Plus、JPA 的 `findById`/`deleteById` 是常见 sink；可把 sink 谓词扩展到这些方法。
- 关联：[[code-analysis-sast-codeql-spring-missing-auth-annotation]]（缺失鉴权注解查询）、[[code-analysis-sast-codeql-custom-taint-steps]]（CodeQL 污点传播补全）、[[web-generic-auth-newbeemall-paysuccess-payment-bypass]]（paySuccess 具体漏洞）、[[web-generic-auth-newbeemall-updateinfo-userid-idor]]（updateInfo IDOR）。

## 检测与防御

- **集中鉴权**：用 Spring Security / 统一拦截器做默认拒绝，所有业务接口显式声明所需权限；不要依赖“每个方法自己记得取 session 用户并比较”。
- **归属校验**：任何以客户端 ID 查询/更新/删除资源的接口，都必须在服务层校验资源属主等于当前登录用户（或管理员），并对支付/订单状态做可信回调校验。
- **CodeQL 门禁**：把该查询加入 CI，新增的无 session 身份路由直接报错；对 `@RequestParam`/`@RequestBody` 的 ID 到 mapper 做污点分析。
- **检测特征**：Controller 方法直接调用 `selectByPrimaryKey`/`updateByPrimaryKeySelective`/`deleteById` 且没有 `getAttribute`/`SecurityContext` 取身份；接口只凭 orderNo/商品 ID/用户 ID 操作，未校验归属。
