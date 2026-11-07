---
id: web-java-framework-struts2-actionproxy-ognl-injection
title: Struts2 ActionProxy 取值流入 OGNL 执行：getMethod/getNamespace/getActionName 注入链
type: scenario
domain: web
path: web/java/framework/struts2
technique: struts2-actionproxy-ognl-injection
aliases:
- Struts2 ActionProxy OGNL 注入
- getMethod OGNL 注入
- getNamespace OGNL 注入
- getActionName OGNL 注入
- OgnlUtil.compileAndExecute
- TextParseUtil.translateVariables
- S2-032 S2-033 S2-037 同源
- S2-057 namespace
tags:
- java
- struts2
- ognl
- expression-injection
- rce
- actionproxy
- taint-analysis
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V23
  verified_at: '2026-11-05T02:36:09+08:00'
  notes: 已对照原文核对；getMethod/getNamespace/getActionName 三类 source、OgnlUtil.compileAndExecute/TextParseUtil.translateVariables sink、S2-032/033/037/057 关联及 ServletActionRedirectResult→conditionalParse 链均与原文一致。原文未给可发送载荷与版本区间，卡内已标无 PoC、confidence medium。
---

## 一句话结论

Struts2 把 `ActionProxy` 中来自 URL 的 `getMethod()`、`getNamespace()`、`getActionName()` 返回值直接拼进字符串并交给 OGNL 求值，且部分路径最终汇入没有安全过滤的 `OgnlUtil.compileAndExecute()`；攻击者控制这些 URL 组成部分即可让框架把输入当代码执行，形成 RCE。S2-032/S2-033/S2-037 是同一模式，S2-057 及后续变体只是换了取值入口。

## 原理

- `ActionProxy` 封装当前请求要调用的 Action：方法名、命名空间、Action 名都从请求 URL 解析而来，属于不可信输入。框架在多处把它们当作“普通字符串”继续拼接，却没有意识到后续会进入表达式引擎。
- 最直接的路径是方法名：
  ```java
  String methodName = proxy.getMethod();
  // ...
  methodResult = ognlUtil.getValue(methodName + "()", ...);
  ```
  `methodName` 被拼上 `"()"` 后交给 `OgnlUtil.getValue()`，OGNL 会把整段字符串当作表达式解析执行。攻击者在 URL 中构造方法名即可注入表达式。
- 更底层的汇聚点是 `OgnlUtil.compileAndExecute()`：它没有额外的安全检查，脏数据只要作为第一个参数（`ma.getArgument(0)`）流入，就会编译并执行。历史上的 `OgnlUtil.getValue()` 与 `TextParseUtil.translateVariables()` 最终都会调用到它；因此把这两个底层函数当作 sink，比只盯表面 API 更容易覆盖不同版本和不同调用入口。
- 命名空间路径（S2-057 一类）：
  ```java
  // ServletActionRedirectResult.execute
  if (namespace == null) {
      namespace = invocation.getProxy().getNamespace();   // 污染源
  }
  String tmpLocation = actionMapper.getUriFromActionMapping(
      new ActionMapping(actionName, namespace, method, null));
  setLocation(tmpLocation);                               // 存入父类 StrutsResultSupport.location
  super.execute(invocation);
  ```
  `ServletActionResult.execute` 随后读取 `location`：
  ```java
  lastFinalLocation = conditionalParse(location, invocation);
  doExecute(lastFinalLocation, invocation);
  ```
  而 `conditionalParse` 在 `parse` 为真时直接调用：
  ```java
  return TextParseUtil.translateVariables(param, ...);
  ```
  `translateVariables` 会对字符串中的 `${...}`/`%{...}` 做 OGNL 求值。namespace 从 URL 进入、经过 `ActionMapping` 构造与 `setLocation` 潜伏在父类字段、再跨继承链在另一个类的 `execute` 中被取出，最终到达 OGNL 引擎。
- 之所以成立：框架把“路由元数据”与“代码表达式”混为一谈，URL 中本应只作为标识符的部分没有做字符白名单或标识符校验，且求值发生在框架内部、不经过业务层过滤。
- 补丁演进说明这是同一根因的反复：S2-032/033/037 修了三次；后续版本把 `ognlUtil.getValue()` 换成 `ognlUtil.callMethod()`，但 `callMethod` 只是壳子，内部仍调用 `compileAndExecuteMethod()`，后者加了 `checkSimpleMethod()` 过滤才阻断；与此同时 `compileAndExecute()` 仍无保护，其他调用入口继续可达。

## 触发条件

- 目标为受影响版本的 Struts2，且 URL 中的 method、namespace 或 action name 能到达上述求值路径。
- 重定向结果等配置没有把 `namespace` 写死，导致框架回退到 `invocation.getProxy().getNamespace()` 动态取值。
- `conditionalParse` 的 `parse` 开关开启（默认结果类型通常开启），或存在其他把 ActionProxy 值直接交给 OGNL 的调用点。
- 攻击者能构造带特殊字符的 URL，且前置网关未对方法名/命名空间做严格白名单。

## 利用步骤

1. 识别 Struts2 应用及其版本/补丁级别；观察 `.action`、`.do` 等路由与重定向结果行为。
2. 定位可由 URL 控制且会进入 OGNL 的字段：优先测试 method 名、namespace、action name。
3. 在 method 路径上，把方法名替换为 OGNL 表达式（框架会补 `"()"`）；在 namespace 路径上，构造含 OGNL 表达式的 namespace，并触发一个会走 `ServletActionRedirectResult`/`conditionalParse` 的重定向结果。
4. 用无副作用表达式（算术、DNS、延时）确认求值发生，再替换为命令执行表达式。
5. 若目标已升级到用 `callMethod` 的版本，注意 `compileAndExecuteMethod` 内的 `checkSimpleMethod` 会拦截常见危险调用；需要寻找仍走无保护 `compileAndExecute` 的其它入口。
6. 原研究用同一模式在 `ActionChainResult`、`PostbackResult`、`ServletUrlRenderer` 等组件中又打通了多条 RCE，说明应枚举所有 ActionProxy 取值点到 OGNL 的路径，而不是只测一个入口。

## PoC

原文未给出可直接发送的 OGNL 载荷与 HTTP 请求，仅描述原研究在本地环境发送构造请求后成功弹出计算器。以下为原文给出的关键脆弱代码，用于定位与复现：

```java
// 方法名路径
String methodName = proxy.getMethod();
methodResult = ognlUtil.getValue(methodName + "()", getStack().getContext(), action);

// namespace 路径
namespace = invocation.getProxy().getNamespace();
String tmpLocation = actionMapper.getUriFromActionMapping(
    new ActionMapping(actionName, namespace, method, null));
setLocation(tmpLocation);

// 最终求值
protected String conditionalParse(String param, ActionInvocation invocation) {
    if (parse && param != null && invocation != null) {
        return TextParseUtil.translateVariables(param, ...);
    }
}
```

无 PoC（原文未提供载荷）；confidence 标 medium。

## 变体与关联

- 变体：source 换成 `getMethod()`（S2-032/033/037）、`getNamespace()`（S2-057）、`getActionName()`，或其他从 URL 解析出的路由字段。
- 变体：sink 换成 `OgnlUtil.compileAndExecute()`、`OgnlUtil.getValue()`、`TextParseUtil.translateVariables()`、`ValueStack.findValue()`；同一表达式注入原语可换不同汇聚点。
- 变体：把 namespace 存入父类字段再跨类取出，说明审计时不能只看单函数内的赋值，要跟踪成员变量与继承链。
- 关联：[[web-java-framework-struts2-s2-067-ognl-upload-filename-bypass]]（另一条 OGNL 入口）、[[web-java-expression-ognl-high-version-reflection-invoke-bypass]]、[[web-java-expression-ognl-jshell-eval-bypass]]（拿到 OGNL 注入后的表达式构造与黑名单绕过）。
- 关联：[[code-analysis-sast-codeql-struts-ognl-taint-modeling]]（用 CodeQL 系统定位本类路径的方法）。

## 检测与防御

- 修复：升级到最新 Struts2，确认所有已知 S2 公告均已覆盖；不要只替换表面 API 名，必须确认底层 `compileAndExecute` 前的净化逻辑对所有入口生效。
- 修复：对 method、namespace、action name 做严格标识符白名单（字母、数字、下划线、点号等），拒绝 `${`、`%{`、`@`、括号等表达式字符；重定向结果尽量写死 namespace，不要回退到请求值。
- 加固：关闭不必要的 OGNL 求值（如结果的 `parse=false`）；使用 OGNL `MemberAccess` 白名单而非仅类级黑名单；对表达式长度和字符集做限制。
- 检测：URL 中出现 `${`、`%{`、`@java.lang.Runtime@`、`#context`、`(#` 等 OGNL 特征；同一来源探测 method/namespace 的异常字符；WAF 规则覆盖编码后的表达式（URL 编码、双重编码、Unicode）。
- 审计：以 `ActionProxy.getMethod/getNamespace/getActionName` 为 source，以 `OgnlUtil.compileAndExecute`、`TextParseUtil.translateVariables`、`ValueStack.findValue` 为 sink 做数据流追踪，并覆盖字段赋值/读取与继承链。
