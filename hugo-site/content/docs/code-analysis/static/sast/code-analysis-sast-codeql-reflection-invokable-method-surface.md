---
id: code-analysis-sast-codeql-reflection-invokable-method-surface
title: CodeQL 枚举反射调用面：按 public + 无参构造 + String 参数 + 包名白名单筛选被任务调度器反射调用的可利用方法
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-reflection-invokable-method-surface
tags:
- codeql
- java
- sast
- code-audit
- reflection
- quartz
- method-surface
- ruoyi
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V381
  verified_at: '2026-11-09T08:09:09+08:00'
  notes: 已对照原文与图05核对：CodeQL 查询按无参构造+public+String参数+com.ruoyi包前缀及排除项筛选，原文得到418条结果并筛出 createTable/sendGet，均一致；查询通用化为任意反射调度器方法面，属方法而非已有 gadget-chain 挖掘；affected_versions 不适用保持空
url: /docs/code-analysis/static/sast/code-analysis-sast-codeql-reflection-invokable-method-surface/
draft: false
kb_aliases:
- CodeQL 反射调用面
- CodeQL 找可利用方法
- 定时任务方法枚举
- Quartz 反射调用方法查询
- public 无参构造 String 参数查询
- RuoYi CodeQL 审计
---

## 一句话结论

当 Java 应用存在「用户可控字符串 → `Class.forName` + `newInstance` + `getMethod(...).invoke(...)`」的反射调度器（如 RuoYi 定时任务的 `JobInvokeUtil`）时，可以在 CodeQL 中按调度器的实际约束——类有 public 无参构造、方法是 public、参数类型只能是 String/Boolean/Long/Double/Integer、类名落在允许的包前缀内——写一条方法级查询，把整张「可被调度器反射调用的方法面」一次性枚举出来，再按 sink 危险度（SQL 执行、SSRF、文件 IO、类加载、脚本执行）人工筛选利用 gadget。

## 原理

- **反射调度器的能力边界就是查询条件**：`JobInvokeUtil.invokeMethod` 用 `getBeanName`/`getMethodName`/`getMethodParams` 解析调用目标，Spring 容器取不到 Bean 时 `Class.forName(className).getDeclaredConstructor().newInstance()`，再 `getMethod(name, paramTypes).invoke(...)`。因此可被调用的方法必须满足：声明类可实例化（有无参构造、非抽象）、方法 public、参数是有限的基本包装类型。把这三条翻译成 CodeQL 谓词，就得到全部候选方法。
- **包白名单/黑名单直接映射为过滤条件**：RuoYi 4.7.8 的 `invokeTarget` 只允许 `com.ruoyi` 前缀（`ScheduleUtils.whiteList`），并排除 `com.ruoyi.common.config`、`com.ruoyi.common.utils.file`，同时过滤器 getter（`get%`/`is%`/`has%`）能去掉大量噪音。查询结果从成千上万条降到几百条，人工 triage 可行。
- **为什么按方法而不是按调用图**：调度器的入口是字符串拼接，CodeQL 的常规 taint 追踪无法把「HTTP 参数 → 反射方法名」连起来；直接枚举「可被反射调用的方法面」，再逐个看方法体里的危险 sink，是更贴合这类调度器的审计方式。
- **triage 顺序**：先看直接执行 SQL/命令/脚本的方法（如 `createTable(String sql)` 拼 `${sql}`），再看 SSRF/文件读写/类加载/反序列化；结合包名判断是否在业务白名单内，确认参数可控后即为候选 gadget。
- **边界**：查询只给出「方法签名可被调用」的必要条件，不保证参数值能由攻击者控制、不保证类加载成功（依赖、静态初始化、构造副作用）；仍需人工阅读方法体与调用方。不同调度器的参数类型/实例化方式不同，需要按实际代码调整谓词。

## 触发条件

- 目标 Java 应用存在基于用户输入字符串的反射调度器（定时任务、规则引擎、插件调用、工作流等）。
- 已用 CodeQL 创建 Java 数据库（`codeql database create --language=java --command='mvn clean package -f "pom.xml"'`），且源码路径不含中文等导致建库失败的问题。
- 知道调度器允许的包前缀/黑名单与参数类型约束，能把它们写成过滤条件。

## 利用步骤

1. 建库：`codeql database create ruoyi-database --language=java --command='mvn clean package -f "pom.xml"'`（路径避免中文）。
2. 编写方法面查询：
   ```ql
   import java

   from Method m
   where
       m.getDeclaringType().getAConstructor().hasNoParameters()
       and m.isPublic()
       and m.getAParamType() instanceof TypeString
       and m.getDeclaringType().getPackage().getName().matches("com.ruoyi%")
       and not m.isAbstract()
       and not m.getDeclaringType().getPackage().getName().matches("com.ruoyi.common.config%")
       and not m.getDeclaringType().getPackage().getName().matches("com.ruoyi.common.utils.file%")
       and not m.getName().matches("get%")
       and not m.getName().matches("is%")
       and not m.getName().matches("has%")
   select m.getDeclaringType().getPackage().getName(), m.getDeclaringType(), m
   ```
3. 运行查询（原文得到 418 条结果），先按类名/方法名排序，排除明显的业务 CRUD 与 getter。
4. 对候选方法逐个阅读方法体，优先标记：执行原始 SQL（MyBatis `${}`/JDBC `Statement`）、发起网络请求（URL/HttpClient）、读写文件、加载类/脚本、反序列化。
5. 确认方法参数能否由调度器传入的攻击者字符串控制（类型匹配、参数数量匹配、是否有额外校验），形成 gadget 列表。
6. 用调度器实际调用（如新增定时任务）验证候选方法，再组合成完整链。

## PoC

```ql
// 查询核心：找出包白名单内、可被无参实例化并反射调用的 public 方法
import java
from Method m
where
    m.getDeclaringType().getAConstructor().hasNoParameters()
    and m.isPublic()
    and (
        m.getAParamType() instanceof TypeString
        or m.getAParamType() instanceof TypeBoolean
        or m.getAParamType() instanceof TypeLong
        or m.getAParamType() instanceof TypeDouble
        or m.getAParamType() instanceof TypeInteger
    )
    and m.getDeclaringType().getPackage().getName().matches("com.ruoyi%")
    and not m.isAbstract()
select m.getDeclaringType(), m
```

原文用第一条查询定位到 `GenTableServiceImpl#createTable(String)` 等候选，并进一步组合出 SQL 注入绕过定时任务黑名单的利用链。

## 变体与关联

- **按 sink 精化**：在查询中追加「方法体内存在 `execute`/`invoke`/`openConnection`/`new URL`/`FileInputStream` 等调用」的谓词，把结果缩到高价值方法。
- **按可达性精化**：用 `MethodAccess`/`Call` 找出从 Controller 到反射调度器的调用路径，确认调度入口可由低权限触发。
- **其它参数类型**：若调度器支持 String[]、Integer 等数组或更多类型，应扩展 `instanceof` 条件；若通过 setter 注入参数，查询条件改为 public setter。
- **关联卡**：RuoYi 4.7.8 createTable SQL 注入绕过任务白名单链（本条查询的直接产物）。

## 检测与防御

- **开发侧**：不要用用户可控字符串直接反射调用任意类；改为枚举/映射表（任务类型 → 固定方法），执行侧做类/方法白名单。
- **CI 门禁**：把该查询加入 CodeQL 分析集，对新增的「可反射调用 + 危险 sink」方法做人工评审。
- **审计侧**：查询结果只是候选，需结合参数可控性与运行环境确认；不要把「方法签名匹配」误报为漏洞。
