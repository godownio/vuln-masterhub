---
id: code-analysis-sast-codeql-spring-mass-assignment-query
title: CodeQL 挖掘 Spring @RequestBody 大量赋值：未显式调用 setter 的数据流查询
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-java-spring-mass-assignment
aliases:
- CodeQL 挖 Spring 大量赋值
- '@RequestBody 未调用 setter 查询'
- setter 缺失 CodeQL 规则
- CodeQL mass assignment
- Spring 参数绑定审计
tags:
- codeql
- sast
- java
- spring
- mass-assignment
- dataflow
- taint-tracking
- code-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:45:04+08:00'
  notes: 已对照原文与图01-11核对：RequestbodyAnnotation/daoClass/BodyParameter/SetterMethod/GetterMethod 类与 DataFlow::localFlow、admin-api 排除条件均与原文一致；结果数 95→50→539→94→66→56 逐图吻合；最终查询发现 setAdminContent。原文未给 CodeQL/Spring 版本，未设置 affected_versions。未运行查询。
---

## 一句话结论

针对 Spring MVC 大量赋值，可用一个 CodeQL Java 查询把“`@RequestBody` 绑定的实体参数”“该实体上未被显式调用的 setter”“参数确实以局部数据流进入 service 层”“未被同名 getter 读取”四个条件串起来，把成千上万个控制器收窄到几十条可疑字段；文章用该查询发现了 CVE-2025-6702 的 `setAdminContent`。

## 原理

- 大量赋值的代码特征是：控制器把 `@RequestBody` 参数直接交给 service 持久化，但某些敏感属性从未被显式 `set`。因此查询的核心不是找 sink，而是找“参数类型上的 setter 没有被该参数显式调用”。
- 查询分四层收窄：
  1. 注解匹配：`Annotation.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody")` 找到所有 `@RequestBody` 参数。
  2. 类型限定：用 `daoClass` 谓词把参数类型限定到目标项目的实体包/命名（如 `org.linlinjava.litemall.db.domain` 且类名 `Litemall%`），排除 `String`、`HttpServletRequest` 等非绑定类型。
  3. setter 缺失：定义 `SetterMethod`（public、`set.*`、单参数、声明类型属于实体），用 `not exists(MethodCall ...)` 判断该参数上从未调用该 setter。
  4. 真实使用：用 `DataFlow::localFlow(parameterNode(requestBodyParam), exprNode(call.getAnArgument()))` 要求参数确实传到某个 service 类方法的实参，避免“参数根本没被使用”的误报。
- 额外的降噪条件：
  - 排除 `%admin-api%` 路径，只看普通用户可达接口；
  - 若实体属性被 `getter` 读取，则认为该系统本来就要接收该字段，用 `getterName.replaceAll("get","set") == setterName` 把对应 setter 排除。
- 每轮执行的数量变化可作为规则有效性的旁证：全部 `@RequestBody` 95 条 → 限定实体类型 50 条 → 未调用 setter 539 条（setter×参数展开）→ 排除 admin 接口 94 条 → 加数据流约束 66 条 → 排除 getter 对应项 56 条。
- 该方法是语义近似而非证明：`replaceAll("get","set")` 只适用于简单 JavaBean 命名；Lombok、继承属性、接口默认方法、泛型 DTO、跨方法传递都可能漏报或误报，结果仍需人工确认。

## 触发条件

- 目标为 Java/Spring MVC 项目，且已用 CodeQL 生成数据库（`codeql database create --language=java`）。
- 知道实体类的包名/命名模式（或愿意用 `@Entity`、继承关系、字段特征替代 `daoClass`）。
- 控制器方法把 `@RequestBody` 参数直接传给 service/DAO；若项目使用 DTO 转换，需把查询对象改为 DTO 与实体映射处。
- 查询包可 import `semmle.code.java.dataflow.DataFlow`（标准 CodeQL Java 库自带）。

## 利用步骤

1. 为目标项目建库，在 VS Code CodeQL 插件或 CLI 中新建 `.ql` 查询。
2. 先只查 `@RequestBody` 参数并观察类型分布，确定实体包名/命名前缀，替换 `daoClass`。
3. 加入 `SetterMethod` 与“未显式调用”条件，浏览结果；若数量过大，追加 service 层限定与路径排除。
4. 对每条结果回到控制器源码，确认：参数类型确为实体、参数被传入持久化方法、缺失的 setter 对应字段是敏感字段（角色、价格、状态、审核、管理员回复等）。
5. 构造请求追加该字段验证（例如注册接口加 `role`、评论接口加 `adminContent`）。
6. 把确认过的规则固化到 CI/审计流程，并针对 Lombok、继承、DTO 映射补充变体。

## PoC

完整查询（按目标项目替换包名/类名前缀即可）：

```ql
import java

class RequestbodyAnnotation extends Annotation {
  RequestbodyAnnotation() {
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody")
  }
}

predicate daoClass(Class c) {
  c.getPackage().getName() = "org.linlinjava.litemall.db.domain" and
  c.getName().matches("Litemall%")
}

class BodyParameter extends Parameter {
  BodyParameter() {
    this.getAnAnnotation() instanceof RequestbodyAnnotation and
    daoClass(this.getType())
  }
}

class SetterMethod extends Method {
  SetterMethod() {
    exists(Class c |
      daoClass(c) and
      this.getDeclaringType() = c and
      this.isPublic() and
      this.getName().regexpMatch("set.*") and
      this.getNumberOfParameters() = 1
    )
  }
}

import semmle.code.java.dataflow.DataFlow

predicate serviceClass(Class c) {
  c.getPackage().getName() = "org.linlinjava.litemall.db.service" and
  c.getName().matches("%Service")
}

class GetterMethod extends Method {
  GetterMethod() {
    exists(Class c |
      daoClass(c) and
      this.getDeclaringType() = c and
      this.isPublic() and
      this.getName().regexpMatch("get.*")
    )
  }
}

from SetterMethod allSetterMethods, BodyParameter requestBodyParam
where
  requestBodyParam.getType() = allSetterMethods.getDeclaringType() and
  not exists(MethodCall explicitCall |
    explicitCall.getCallee() = allSetterMethods and
    explicitCall.getQualifier().(VarAccess).getVariable() = requestBodyParam
  ) and
  exists(MethodCall call |
    serviceClass(call.getQualifier().(VarAccess).getVariable().getType()) and
    DataFlow::localFlow(DataFlow::parameterNode(requestBodyParam),
      DataFlow::exprNode(call.getAnArgument()))
  ) and
  not exists(GetterMethod getterCall, MethodCall explicitCall |
    daoClass(getterCall.getDeclaringType()) and
    explicitCall.getCallee() = getterCall and
    explicitCall.getQualifier().(VarAccess).getVariable() = requestBodyParam and
    getterCall.getName().replaceAll("get", "set") = allSetterMethods.getName()
  ) and
  not requestBodyParam.getFile().getAbsolutePath().matches("%admin-api%")
select requestBodyParam, "Don't call setter: " + allSetterMethods.getName() + " explicitly"
```

结果解读：每行是“某个 `@RequestBody` 参数 + 某个从未被显式调用的 setter”。优先看 `setRole`、`setAdminContent`、`setPrice`、`setStatus`、`setDeleted`、`setUserId` 等字段；对 `setPrice` 一类结果要确认参数是否真的进入持久化路径（数据流条件已做初步过滤）。

## 变体与关联

- 变体：把 `daoClass` 改为注解匹配（`@Entity`/`@TableName`）或包名通配，适配非 MyBatis Generator 项目。
- 变体：用 `DataFlow::Global` 替代 `localFlow`，追踪参数经 DTO 转换、工具类、跨方法调用后的传播；但误报会增加，需要 barrier。
- 变体：对 `@ModelAttribute`、WebFlux `bodyToMono`、Rails strong params、.NET model binding 编写同构查询。
- 关联卡片：[[web-java-framework-spring-requestbody-mass-assignment-privilege-escalation]]（提权形态）、[[web-java-framework-spring-requestbody-mass-assignment-admin-content-forgery]]（该查询发现的实例）、[[code-analysis-sast-codeql-custom-taint-steps]]（数据流断链补全）、[[code-analysis-sast-codeql-isbarrier-parameterized-simple-type]]（误报消除）。

## 检测与防御

- 本卡是审计/检测方法，防御视角：
  - 在 CI 中对新增控制器跑该查询，把 `@RequestBody` + 实体参数 + 缺失 setter 作为评审阻断项；
  - 维护实体包名/命名规则，项目重构后同步更新查询；
  - 对查询结果建立人工复核清单，避免把 getter 过滤、Lombok、继承导致的假阴性当成安全。
- 修复侧：统一使用请求 DTO 白名单、实体敏感字段只读注解、保存前显式赋值；这样查询结果会自然归零。
- 边界：查询只覆盖“控制器直接使用实体且同步调用 service”的常见形态；异步消息、反射赋值、Map 绑定、复杂继承需单独建模。
