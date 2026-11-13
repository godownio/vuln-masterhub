---
id: web-generic-ssti-beetl-gettemplate-user-rule-print-rce
title: Beetl getTemplate 模板串由业务参数拼接：rule 表达式经 print() 进入模板引擎 RCE
type: scenario
domain: web
path: web/generic/ssti
technique: beetl-gettemplate-user-controlled-template-string-rce
aliases:
- Beetl getTemplate 审计
- 模板串由用户输入拼接
- ComputationRuleUtil getValue
- print 表达式注入
- Beetl 存储型模板注入
tags:
- java
- ssti
- beetl
- code-audit
- rce
- template-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:20:29+08:00'
  notes: '已对照原文核对：GroupTemplate#getTemplate("<!--: print("+s2+"); -->") 拼接、rule() 对不含 @sum/@avg 的输入原样返回、ComputationRuleUtil.getValue<-checkRule<-/checkRule 数据流、Shiro /druid/** anon 与 /druid/../ 跳到后台路由、图07 响应回显 ipconfig 均与原文一致；原文高版本 Beetl 黑名单的反射加载 js 绕过已被现有 Nashorn/defineClass 卡覆盖并由 worker reject 草稿，本卡只覆盖 getTemplate 注入链，PoC 为结构化示意；未实测。'
---

## 一句话结论

应用把业务参数拼进 `GroupTemplate#getTemplate` 的模板字符串（例如 `getTemplate("<!--: print(" + rule + "); -->")`）时，模板源码本身就由用户控制；只要参数在拼接前没有被当作纯值处理、也没有表达式白名单，攻击者提交 Beetl 表达式即可在页面/接口渲染时执行任意 Java 代码，形成 SSTI RCE。

## 原理

- Beetl 的 `GroupTemplate#getTemplate(key)` 把传入的字符串当作模板资源/模板内容解析，返回可 `binding()`、`render()` 的 `Template` 对象。正常写法是传固定模板名或固定源码；一旦拼接了用户输入，模板解析器就会把用户输入当成模板语法的一部分。
- 常见的拼接形态是代码块 + `print()`：`"<!--: print(" + user + "); -->"`。Beetl 会编译这段模板，渲染时求值 `print(...)` 里的表达式；用户输入的 `${...}`、`@类.方法`、函数调用等都会进入模板 AST。
- 用户输入之所以能一路到达模板，往往是因为中间的工具函数只做“特定标记处理”，其他输入原样返回。例如 `rule(src, "@sum")` / `rule(src, "@avg")` 只在字符串里找到对应标记时才替换，找不到就直接 `return src`；攻击者只要不提交 `@sum`/`@avg`，输入就原样进入 `getTemplate`。
- 数据流通常是：Controller 接收 `@RequestBody Map` → 取出 `rule`/`condition`/`establish` 等字段 → Service 计算 → 工具类 `getValue` 拼接模板 → `render()`。任何一层只做业务格式校验（数字、JSON、非空）而不做模板字符白名单，都不构成防护。
- 与“后台模板编辑”型 Beetl RCE 的区别：那种要求攻击者能写模板文件；本场景模板内容来自请求参数，是反射/存储型 SSTI，入口通常在前台或半前台接口，危害面更大。
- Beetl 高版本可能对常见命令执行类名做黑名单；此时可换用未被黑名单覆盖的解释器/类加载路径（如脚本引擎 + `defineClass`），见关联卡。

## 触发条件

- 应用使用 Beetl，且存在把外部参数拼进 `GroupTemplate#getTemplate`（或等价的字符串模板 API）的调用点。
- 拼接前的处理函数对普通输入原样放行（只处理特定标记/格式），没有模板语法白名单或转义。
- 入口接口可从攻击位置访问；若受鉴权保护，需先有可用会话或存在鉴权绕过。
- 模板渲染结果会被返回/执行，且 JVM 允许 `@` 静态调用或等效的表达式求值能力。

## 利用步骤

1. 审计/黑盒定位：全局搜索 `GroupTemplate#getTemplate`、`getStringTemplate`、`Template.render`，筛出模板内容不是硬编码常量的调用点。
2. 对每个调用点向上追溯参数：确认参数来自 Controller 的 `@RequestParam`/`@RequestBody`/表单字段，并检查中间工具函数是否原样透传（例如只处理 `@sum`/`@avg` 等标记）。
3. 找到入口路由（如 `/checkRule`）与参数名（如 `rule`），确认参数类型与包装（`print(...)`、`${...}` 或直接模板源码）。
4. 先发无害表达式验证求值：如 `1+1`、`${@java.lang.Math.max(1,2)}`，观察响应是否变成 `2`。
5. 若直接命令执行被黑名单拦截，改用脚本引擎/反射/类加载等绕过（见关联卡）；无回显时用写文件、DNS/HTTP 外带或时间盲注验证。
6. 检查鉴权：若接口在 Shiro/拦截器保护下，先确认是否存在路径规范化绕过或其他前台入口。

## PoC

```json
{"rule":"<Beetl 表达式>","type":"1"}
```

```text
# 探路（确认模板求值）
rule = 1+1
# 或
rule = ${@java.lang.Math.max(1,2)}

# 命令执行（若未被黑名单拦截，示意）
rule = ${@java.lang.Runtime.getRuntime().exec("id")}
```

说明：实际表达式是否需要 `${...}`、`@` 前缀，取决于调用点把参数拼进 `print(...)` 还是直接作为模板源码；以目标代码的拼接方式为准。PoC 为结构化示意，未在目标环境复跑。

## 变体与关联

- 变体：拼接位置可能是 `getTemplate("<html>..." + user + "...")` 的整段模板、`print(user)`、`${user}` 或 `include` 路径，表达式边界不同，需按代码调整 payload。
- 变体：参数经过 JSON 解析后逐字段拼接（如 `condition`/`establish`/`noEstablish`），任一字段可控即可。
- 关联：[[web-generic-ssti-beetl-static-class-reflect-runtime-blacklist-bypass]]（Beetl 静态调用 + 反射绕过默认黑名单）；[[web-java-rce-nashorn-java-type-blacklist-file-read]]（脚本引擎 + Java.type 绕过内容黑名单）；[[web-java-component-jimureport-queryfieldbysql-objectconstructor-nashorn-memshell]]（ScriptEngineManager→Nashorn→defineClass 的完整实现）；[[web-generic-ssti-velocity-evaluate-string-template-rce]]（同为“用户输入拼进字符串模板”的另一引擎）；[[web-java-framework-shiro-spring-path-auth-bypass]]（本场景常见的鉴权前置绕过）。
- 边界：模板内容硬编码、参数经过严格白名单/转义、Beetl 禁用 `@` 静态调用且表达式能力受限、入口不可达时失效。

## 检测与防御

- 代码层：禁止把外部输入拼进模板源码；需要动态模板时使用固定模板 + 变量绑定（`binding` 传值），不要让用户控制模板结构。
- 对 `getTemplate`/`getStringTemplate` 的调用点做专项审计，模板参数必须是常量或经过白名单校验的模板名。
- 输入层：对进入模板拼接的参数做字符白名单（拒绝 `${`、`#{`、`@`、`<%` 等模板语法字符），而不是只做业务格式校验。
- 检测：请求参数中出现 `${@`、`print(`、`Class.forName`、`getRuntime`、`ScriptEngineManager` 等模板/命令执行特征；Beetl 渲染异常日志；应用进程异常子进程。
- 响应：升级/加固 Beetl 安全配置，禁用不必要的 `@` 静态调用；排查同入口的历史请求与已执行的命令。
