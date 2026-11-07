---
id: code-analysis-sast-codeql-spring-missing-auth-annotation
title: CodeQL 枚举 Spring Controller 缺失自定义鉴权注解：以 PowerJob @ApiPermission 为例
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-spring-missing-auth-annotation
tags:
- codeql
- sast
- java
- spring
- access-control
- unauth
- code-audit
- annotation
- api-permission
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:48:34+08:00'
  notes: 已对照原文与图01核对：CodeQL 查询谓词 isController/isSpecController/hasApiPermission 与原文一致，PowerJob 5.1.2 上跑出 51 条结果，含 OpenAPIController.saveJob/auth/copyJob/exportJob/fetchJob 与 MigrateController 方法；原文查询 @description 提到 checkJobIdValid 但查询体未实现该谓词，卡片按实际查询重写并在变体中给出补充写法，未误述。未验证点：未在本机建 CodeQL 库复跑。
url: /docs/code-analysis/static/sast/code-analysis-sast-codeql-spring-missing-auth-annotation/
draft: false
kb_aliases:
- CodeQL 查未授权接口
- CodeQL 缺失鉴权注解
- '@ApiPermission 缺失查询'
- Spring Controller 鉴权审计
- 注解驱动鉴权漏标
---

## 一句话结论

当 Java/Spring 项目用“方法上标注自定义权限注解”来实现鉴权时，可以用一段 CodeQL 查询匹配所有带 `@GetMapping`/`@PostMapping`/`@RequestMapping` 等路由注解、但不带该权限注解的方法，排除 `AuthController`/`TestController` 这类显式公开的控制器后，一次性列出全部未授权接口；原文用该查询在 PowerJob 5.1.2 中跑出 51 条结果，发现 `/user/list` 用户名枚举与 `OpenAPIController` 下 `/openApi/runJob` 等未鉴权接口。

## 原理

- **注解驱动鉴权的失效模式**：PowerJob 的权限拦截器只对标注 `@ApiPermission(name, roleScope, requiredPermission)` 的方法做校验；没有注解的方法不会进入权限判断，等价于公开接口。漏洞不是“校验逻辑写错”，而是“应该加注解的方法漏加了”，因此需要找的是**注解缺失**，而不是传统污点数据流。
- **CodeQL 的优势**：`Method.getAnAnnotation()` 与 `Annotation.getType().hasQualifiedName(pkg, name)` 在语义层精确匹配注解类型，不受注释、字符串、同名不同包影响；相比 grep `@ApiPermission` 反向找“没有注解的方法”，CodeQL 能直接枚举全部路由方法再排除，避免遗漏和多报。
- **查询结构**：
  1. `isController(m)`：方法带 Spring Web 的 `GetMapping`/`PostMapping`/`RequestMapping`/`PutMapping`/`DeleteMapping` 注解之一。
  2. `isSpecController(m)`：在上一条件基础上排除 `AuthController`、`TestController` 等已知公开控制器，降低噪声。
  3. `hasApiPermission(m)`：方法带目标项目的自定义权限注解（本例 `tech.powerjob.server.auth.interceptor.ApiPermission`）。
  4. 选择 `isSpecController(m) and not hasApiPermission(m)` 的方法。
- **为什么能挖到真漏洞**：原文对 51 条结果人工复核，`UserInfoController#list` 确实没有任何权限注解且直接 `findAll()`；`OpenAPIController` 的 `runJob`/`saveJob`/`copyJob`/`exportJob`/`fetchJob` 等方法同样漏标，且依赖的 `AppId` 头可为 `null`，从而在未登录状态下触发任务或修改任务配置。查询本身只负责“把可疑面收窄”，最终仍需阅读方法体与发起 HTTP 请求验证。
- **局限**：如果项目采用全局过滤器/网关统一鉴权、或权限注解加在类/接口/父类上，简单的方法级查询会误报；需要补充类级注解、父类/接口继承与过滤器/拦截器配置的分析；注解全限定名随项目不同要替换。

## 触发条件

- 目标为 Java/Spring 项目，鉴权依赖自定义方法注解（如 `@ApiPermission`、`@RequirePermission`、`@SaCheckPermission` 等），而非全局默认拒绝。
- 能拿到源码或可编译的工程，安装 CodeQL CLI 并能成功构建 Java 数据库。
- 已知鉴权注解的全限定名与需要排除的公开控制器名称。
- 目标接口在部署环境中可被未认证访问（无网关/反向代理额外拦截）。

## 利用步骤

1. 阅读一个受保护接口（如 `saveJob`），确认鉴权注解的全限定名、注解属性与拦截器行为，判断“无注解 = 无鉴权”。
2. 构建 CodeQL Java 数据库：`codeql database create cq-db --language=java --command="mvn clean install -DskipTests -Drat.skip=true" --source-root=. --overwrite`。
3. 编写查询：路由注解谓词 + 权限注解谓词 + 公开控制器排除，`select` 出缺失权限注解的方法。
4. 在 VS Code CodeQL 插件或 CLI 中运行查询；原文在 PowerJob 5.1.2 上得到 51 条结果。
5. 逐条 triage：优先看返回业务数据（用户/配置/任务）、执行动作（run/save/copy/delete/export）或调用外部命令的方法；阅读方法体确认是否有内部二次校验（如 `checkJobIdValid`、`AppId` 归属校验）。
6. 对候选接口发起未登录 HTTP 请求，验证是否返回 200 与业务数据/成功状态；确认后形成漏洞清单。
7. 可选：把查询改造成 CI 门禁，对新增漏标方法直接报错（见检测与防御）。

## PoC

```ql
/**
 * @name Spring controller methods missing custom auth annotation
 * @description Finds controller methods that lack the project's ApiPermission annotation
 * @kind problem
 * @problem.severity warning
 * @id java/controller/missing-auth-annotation
 */
import java

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

predicate isSpecController(Method m) {
  isController(m) and
  not m.getDeclaringType().hasName("AuthController") and
  not m.getDeclaringType().hasName("TestController")
}

predicate hasApiPermission(Method m) {
  exists(Annotation a |
    a.getType().hasQualifiedName("tech.powerjob.server.auth.interceptor", "ApiPermission")
    | a = m.getAnAnnotation()
  )
}

from Method m
where isSpecController(m) and not hasApiPermission(m)
select m, "Controller method '" + m.getName() + "' is missing ApiPermission annotation"
```

```bash
# 建库并运行（原文命令）
codeql database create cq-db --language=java \
  --command="mvn clean install -DskipTests -Drat.skip=true" \
  --source-root=. --overwrite
codeql query run example.ql --database=cq-db
```

说明：查询为按原文逻辑重写的最小版本，未在本机运行；原文在 PowerJob 5.1.2 上得到 51 条结果，并在 `UserInfoController#list`、`OpenAPIController` 中确认了未授权接口。

## 变体与关联

- 变体（换注解）：把 `hasApiPermission` 的包名/类名替换为目标项目的 `@RequirePermission`、`@SaCheckPermission`、`@PreAuthorize` 等；对 Spring Security 可反向匹配“没有 `@PreAuthorize` 的方法”。
- 变体（减少误报）：增加 `not exists(MethodCall c | c.getMethod().hasName("checkJobIdValid") and c.getEnclosingCallable() = m)`，要求方法也没有自行做 jobId/appId 归属校验；或把类级注解、父类/接口上的注解一并纳入判断。
- 变体（扩大范围）：加入 `@RequestMapping` 类级前缀解析，输出实际 URL 路径；与 `Actuator`/`Swagger` 端点清单交叉比对。
- 关联：[[web-generic-auth-powerjob-missing-apipermission-unauth-endpoints]]（本文查询挖到的具体漏洞与 HTTP PoC）；[[code-analysis-source-audit-java-auth-config-unauth-endpoint-enumeration]]（从鉴权配置枚举匿名路径的互补方法）；[[code-analysis-sast-codeql-spring-mass-assignment-query]]、[[code-analysis-sast-codeql-spring-multipartfile-upload-endpoints]]（同属 CodeQL Java 查询套路）。
- 边界：项目若使用全局默认拒绝 + 白名单、或注解加在类/父类/接口上，本查询会误报；CodeQL 建库失败（依赖缺失、非 Maven 工程）时需换构建命令；查询只做静态枚举，接口是否真正可未授权访问仍取决于部署层。

## 检测与防御

- 防御（架构）：把鉴权改为默认拒绝——拦截器对未标注 `@ApiPermission` 的方法也要求登录，公开接口必须显式标注 `requiredPermission = NONE` 或加入白名单；Controller 基类/包级统一加注解，避免漏标。
- 防御（CI）：把本查询加入 CodeQL/SAST 门禁，新增 Controller 方法缺少权限注解时阻断合并；为鉴权注解写 ArchUnit 测试（如“所有 `@RestController` 的 public 方法必须带 @ApiPermission 或 @PublicApi”）。
- 检测（运行时）：未认证请求访问 `/user/list`、`/openApi/*` 返回 200；`AppId` 为空/`null` 的 OpenAPI 调用；短时间遍历 `jobId`/`appId` 的 `runJob`/`saveJob` 请求。
- 检测（审计）：定期用该查询扫描代码库并与上一次结果 diff，关注新增的未标注方法；重点审查 OpenAPI、迁移、测试、内部工具类 Controller。
