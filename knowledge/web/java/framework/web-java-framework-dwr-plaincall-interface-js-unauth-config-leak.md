---
id: web-java-framework-dwr-plaincall-interface-js-unauth-config-leak
title: DWR plaincall 任意路径未授权调用：/dwr/interface/*.js 枚举方法签名后执行无参 getSMTPConfig 泄露 SMTP 凭据
type: scenario
domain: web
path: web/java/framework
technique: dwr-plaincall-interface-js-unauth-method-config-leak
aliases:
- DWR plaincall
- /dwr/call/plaincall
- DWR interface js 枚举
- getSMTPConfig 泄露
- DWR 任意路径调用
- Direct Web Remoting 未授权方法调用
tags:
- java
- dwr
- rpc
- plaincall
- unauth
- method-invocation
- information-disclosure
- credential-leak
- smtp
- recon
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V287
  verified_at: '2026-11-08T05:49:12+08:00'
  notes: 已对照原文与9图核对：debug测试页（01）、/dwr/interface下GlobalController.js/ResourceController.js/engine.js/util.js（02）、plaincall调用configRemoteCallController.getSMTPConfig返回defaultMailSender含host/port/protocol/ssl/user/pass（03）、GlobalController.js与ResourceController.js方法清单及形参个数（04-06）均一致；plaincall路径任意与interface js匿名可读符合原文。dedup除自身外候选均related（debug-index/exec、weaver DWR PlainCall等），机制/PoC不同；dup-scan与16515等均related。未验证点：未复跑目标站；原文未给DWR版本，未设affected_versions；frontmatter无sources/source_url。
---

## 一句话结论

DWR（Direct Web Remoting）除了 `/dwr/exec/<类>.<方法>.dwr` 之外还有 `plaincall` 调用方式：`POST /dwr/call/plaincall/<任意串>.dwr` 的路径部分**不参与路由**，服务端只按报文体里的 `c0-scriptName` 与 `c0-methodName` 反射调用方法；攻击者先读默认可匿名访问的 `/dwr/interface/<类名>.js` 恢复出全部方法名和参数个数，再对无参方法（如 `configRemoteCallController.getSMTPConfig`）直接发起调用，即可在未登录状态下拿到 `defaultMailSender` 的 host、user、pass 等 SMTP 凭据。

## 原理

- DWR 把服务端 Java 类按 `dwr.xml` 的 `<create creator="..." javascript="类名">` 暴露给浏览器；每个暴露类还会自动生成一个 `/dwr/interface/<类名>.js`，内容固定为一行行 `dwr.engine._execute(p._path, "<类名>", "<方法名>", arguments)`。`function(p0, p1, ..., callback)` 的形参个数就是该方法的参数个数，因此这个 JS 文件等于一份「可调用方法 + 参数个数 + 类名」清单，无需 `debug=true` 即可获取。
- `plaincall` 的报文是 `key=value` 行：`callCount=1`、`c0-scriptName`、`c0-methodName`、`c0-param0=<类型前缀>:<值>`、`c0-id`、`batchId`、`instanceId`、`page`、`scriptSessionId`。脚本名到类的映射来自 `dwr.xml`，方法名直接用于反射；`/dwr/call/plaincall/` 后面那段（原文用 `dwrtest.findByUserId.dwr`）只是形式上的路径，换成任意字符串服务端仍按报文体分发，这解释了为什么请求路径可以随便写。
- 无参方法最容易打：只要拿到类名和方法名（`interface/*.js` 里 `function(callback)` 的方法即无参），不需要知道参数类型就能发 `c0-scriptName`/`c0-methodName`，服务端反射执行后把返回值包进 `dwr.engine._handleCallback` 的 JS 回调。配置类的 getter 天然无参，`getSMTPConfig` 返回 `defaultMailSender` 对象，序列化后 host、user、pass 全部明文出现在响应里。
- 未授权的原因与 `exec` 端点相同：`DwrServlet` 只检查方法是否在 `dwr.xml` 的 allow 范围内，不检查登录态；应用常把 `/dwr/*` 映射在业务路径下却漏加鉴权过滤器，于是 `interface/*.js` 可匿名下载、`plaincall` 可匿名调用。
- 参数个数多、签名未知的方法不适合盲 fuzz（原文对多参数接口的穷举失败），所以「从 `interface/*.js` 读形参个数 → 只打无参或参数少的 getter」是这条链的实际打法。

## 触发条件

- 目标 Java Web 应用部署了 DWR（`org.directwebremoting.servlet.DwrServlet` 或老包 `uk.ltd.getahead.dwr.DWRServlet`），常见映射 `/dwr/*`。
- `/dwr/interface/<类名>.js` 可匿名访问（默认行为），或 `debug=true` 使 `/dwr/index.html`、`/dwr/test/<类>` 可访问以枚举类名。
- `dwr.xml` 暴露的类里存在无参/少参、返回敏感配置或业务数据的方法（如 `getSMTPConfig`、各类 `getXxxList/Count`）。
- DWR servlet 未被登录过滤器覆盖（匿名可达）。

## 利用步骤

1. 识别 DWR：页面前端有 `/dwr/engine.js`、`/dwr/util.js`、`/dwr/interface/*.js` 引用；或直接请求 `/<app>/dwr/`、`/<app>/dwr/index.html` 看是否出现 DWR 类列表。
2. 枚举类名：从浏览器源码面板/网络请求里收集 `/dwr/interface/<类名>.js`；请求每个 JS 文件，提取 `dwr.engine._execute(p._path, "类名", "方法名", arguments)`，记录方法名与 `function(...)` 的形参个数。
3. 优先挑 `function(callback)` 的无参方法和 `get*Config`、`get*List`、`get*ById` 这类数据读取方法。
4. 构造 plaincall 报文：`POST /<app>/dwr/call/plaincall/<任意串>.dwr`，`Content-Type: text/plain`，正文写 `callCount=1`、`c0-scriptName=<类名>`、`c0-methodName=<方法名>`、`c0-id=0`、`batchId=1`、`instanceId=0`、`page=<任意>`、`scriptSessionId=<任意>`；有参数时补 `c0-param0=string:<值>`（数字用 `number:`）。
5. 从响应 JS 回调里的对象读取敏感字段；对返回业务列表的方法按方法名推断参数含义（如 `getUnApprovedUnitItemResourceListById` 传任意字符串即可触发查询并回显数据/异常）。
6. 保存可匿名调用的类/方法清单，逐个验证是否有返回配置、口令、业务数据的 getter。

## PoC

```http
POST /DwrProject/dwr/call/plaincall/dwrtest.findByUserId.dwr HTTP/1.1
Host: target
Content-Type: text/plain
Content-Length: 237

callCount=1
windowName=
c0-scriptName=configRemoteCallController
c0-methodName=getSMTPConfig
c0-id=0
batchId=1
instanceId=0
page=%2FDwrProject%2Fdwr%2Ftest%2Fdwrtest
scriptSessionId=7viforTWTj$BVBJSxv99$V*hVgn/*YsBVgn-XOm0BUHfr
```

```text
# 响应（节选，敏感值已由原文打码）
throw 'allowScriptTagRemoting is false.';
//#DWR-REPLY
//#DWR-START#
function() {
  if (window.dwr)return;
  var dwr=window.dwr._;
  dwr.engine.remote.handleCallback("1","0",{defaultMailSender:
    {...,"from":"...","host":"...","port":"80","protocol":null,"ssl":true,"user":"...","pass":"..."}});
}
//#DWR-END#
```

```javascript
// /dwr/interface/GlobalController.js 中的一条（形参个数即参数个数）
dwr.engine._execute(p._path, "GlobalController", "getGlobalResourceList", arguments);
// p.getGlobalResourceList=function(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,callback) {...}
```

## 变体与关联

- 变体：同一 DWR 端点也接受 `/dwr/exec/<类>.<方法>.dwr` 形式（见 `[[web-java-framework-dwr-debug-index-exec-unauth-method-invoke]]`）；`plaincall` 与 `exec` 的差别主要在路径与响应包装，参数仍按 `c0-paramN` 类型前缀传递。
- 变体：`debug=true` 时 `/dwr/index.html` 会列出所有暴露类，`/dwr/test/<类>` 直接给出带 Execute 按钮的方法测试页，类名与包名（如 `com.test.dwrtest`）也一并泄露。
- 变体：原文把参数类型前缀写成业务字段名 `c0-param0=resource_module_id:1122222`，服务端仍把值带进了下游查询，说明类型前缀并非在所有版本/配置下被严格校验；该细节未进一步验证，复现时优先用标准 `string:`/`number:`。
- 关联：拿到方法后把字符串参数当注入点即 `[[web-generic-sqli-dwr-typed-param-injection-point]]`；参数错误回显完整 SQL 见 `[[web-java-framework-dwr-sql-exception-full-statement-disclosure]]`。
- 边界：`interface/*.js` 被鉴权、`dwr.xml` 只 include 无副作用方法、DWR 端点被过滤器覆盖时，利用面收窄。

## 检测与防御

- 检测：匿名访问 `/dwr/interface/*.js`、`/dwr/index.html`、`/dwr/test/*`；`POST /dwr/call/plaincall/*` 报文体含 `callCount=`、`c0-scriptName=`、`c0-methodName=`；响应体含 `DWREngine._handleCallback` 或 `dwr.engine.remote.handleCallback`；短时间遍历多个 `c0-methodName`。
- 修复：把 DWR servlet 纳入统一登录与权限过滤；生产关闭 `debug`；`dwr.xml` 用 `<exclude>` 收紧方法，禁止暴露配置 getter、返回敏感数据或带 SQL 拼接的方法。
- 加固：对 DWR 报文做结构/方法白名单校验；配置类凭据改用密文并限制读取接口；WAF 对 `c0-scriptName`/`c0-methodName` 枚举特征与 `interface/*.js` 批量下载告警。
