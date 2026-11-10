---
id: web-java-framework-dwr-debug-index-exec-unauth-method-invoke
title: DWR 组件 debug 索引暴露：按 dwr.xml allow 列表构造 /dwr/exec 请求未授权调用服务端方法
type: scenario
domain: web
path: web/java/framework
technique: dwr-debug-index-exec-unauthorized-method-invoke
aliases:
- DWR 未授权调用
- /dwr/exec 端点
- DWR debug 页面
- dwr.xml allow include
- Direct Web Remoting 接口枚举
- workflowSync.getLeaderByOrgId
tags:
- java
- dwr
- rpc
- unauth
- method-invocation
- debug
- component
- recon
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:35:32+08:00'
  notes: 已对照原文与图01/03/04/05/06核对：web.xml 中 dwr-workflow servlet 映射 /workflow/dwr/*、servlet-class uk.ltd.getahead.dwr.DWRServlet、debug=true 与 config-webform=/WEB-INF/xml/jsflow.xml 均一致；图03 的 /jsoa/workflow/dwr/test/workflowSync 页列出 16 个方法与 getLeaderByOrgId 的 Execute(回显 noleader)、图04 报文 callCount=1/c0-scriptName/c0-methodName/c0-id/c0-param0=string:/xml=true 与响应 DWREngine._handleResponse 一致；图05/06 的 include 清单与 WorkflowSync.getLeaderByOrgId(String) 调用 bd.getLeaderListByOrgId 一致。未验证点：原文未给受影响版本区间，未设 affected_versions；未复跑请求。
---

## 一句话结论

Java 应用把 DWR（Direct Web Remoting，老包名 `uk.ltd.getahead.dwr`）以 `debug=true` 部署时，`/dwr/` 索引页会列出所有可被 JS 调用的类、`/dwr/test/<类>` 甚至给出每个方法的「Execute」测试链接；攻击者据此直接构造 `POST /dwr/exec/<类>.<方法>.dwr` 的批量调用报文，就能在**未登录**状态下调用 `dwr.xml` 中 `<include>` 放行的任意服务端方法，把「前端 JS 才用的 RPC 接口」变成任意业务方法调用入口（SQL 注入、命令执行、越权读数据都由此展开）。

## 原理

- DWR 的模型是「服务端 Java 类通过 `dwr.xml` 的 `<create creator="new" javascript="名">` 暴露给浏览器 JS」，浏览器发出的是 `callCount=1` 起的批量调用报文，由 `DWRServlet` 反序列化后反射调用目标方法。
- 请求不需要鉴权的原因：`DWRServlet` 只校验「该方法是否在 `<allow>` 白名单里」，不校验会话；很多系统把这个 servlet 映射在 `/workflow/dwr/*` 这类业务路径下，但从未接入登录过滤器，于是 `exec` 端点天然匿名可达。
- `debug=true` 会把 `index.html` 的类列表、`test/<类>` 的方法列表（含每个方法的参数类型与 Execute 链接）渲染出来；这等于把白名单内容与调用格式直接交给攻击者，无需再逆向 `dwr.xml`。
- 报文格式固定：`callCount=1`、`c0-scriptName=<JS 名>`、`c0-methodName=<方法名>`、`c0-id=<任意>`、`c0-param0=<类型前缀:值>`、`xml=true`（返回 XML 而非 JS，便于工具处理）。方法有几个参数就写 `c0-param0`/`c0-param1`…，复杂对象用 `c0-param0=Object_xxx:{...}`。
- 为什么危险面大：被暴露的方法通常是内部业务方法（`getLeaderByOrgId`、`getUserStatus`、`userCanCreateFlow`），签名要求的是 String/int，内部再拼 SQL 或调 DAO；它们从未被设计成「对外 HTTP 接口」，缺参数校验，因此把参数当用户输入的地方就会直接成洞。
- `debug=false` 时索引页消失，但 `exec` 端点仍然按同一格式工作，只是要靠泄露的 `interface/<类>.js` 或错误回显来枚举方法与签名。

## 触发条件

- 目标为 Java Web 应用且 `WEB-INF/web.xml` 中存在 `uk.ltd.getahead.dwr.DWRServlet`（或新版 `org.directwebremoting.servlet.DwrServlet`）映射，常见路径 `/dwr/*`、`/<app>/workflow/dwr/*`。
- `init-param debug=true`（或索引页/测试页可访问），或 `interface/*.js` 可下载，使方法与签名可枚举。
- `dwr.xml` 的 `<create>` 里 `include` 了带危险内部逻辑的方法（拼 SQL、执行命令、读写文件、返回敏感数据）。
- 该 servlet 路径未纳入登录/权限过滤器（匿名可达）。

## 利用步骤

1. 探测：访问 `/<app>/dwr/`，出现 `Classes known to DWR:` 列表即确认；再访问 `/<app>/dwr/index.html`。
2. 点某类的链接进入 `/dwr/test/<类>`，页面列出方法名、参数类型与「Execute」按钮；或直接下载 `/dwr/interface/<类>.js` 读方法签名。
3. 复制 Execute 链接对应的请求（形如 `POST /<app>/dwr/exec/<类>.<方法>.dwr`，`Content-Type: text/plain`），把参数值替换为探测载荷。
4. 先发合法值确认方法可调用（观察返回的 `DWREngine._handleResponse(...)` 或 XML），再按业务含义替换为注入/越权载荷。
5. 对返回字符串的方法做数据读取（列出组织、用户、流程），对拼接 SQL 的方法做注入（见关联卡），对执行类方法直接命令执行。
6. 记录可调用的方法清单（`include` 名单通常就是攻击面清单），逐个验证。

## PoC

```http
GET /jsoa/workflow/dwr/ HTTP/1.1
Host: target
```

```text
# 回显（索引页）
Classes known to DWR:
  workflowSync (com.js.oa.jsflow.util.WorkflowSync)
```

```http
POST /jsoa/workflow/dwr/exec/workflowSync.getLeaderByOrgId.dwr HTTP/1.1
Host: target
Content-Type: text/plain
Content-Length: 122

callCount=1
c0-scriptName=workflowSync
c0-methodName=getLeaderByOrgId
c0-id=1908_1736498493215
c0-param0=string:
xml=true
```

```text
# 响应
var s0="noleader";
DWREngine._handleResponse('1908_1736498493215', s0);
```

```xml
<!-- dwr.xml 中被放行的方法清单（攻击面） -->
<create creator="new" javascript="workflowSync">
  <param name="class" value="com.js.oa.jsflow.util.WorkflowSync"/>
  <include method="getUserStatus"/>
  <include method="getUserStatusByEmpIdStr"/>
  <include method="getUserStatusByEmpOrgGrp"/>
  <include method="getUserStatusByRole"/>
  <include method="getLeaderByOrgId"/>
  <include method="getWFOnlineUser"/>
  <include method="userCanCreateFlow"/>
</create>
```

## 变体与关联

- 变体：`debug=false` 时改用 `interface/*.js` 或 `test/` 页残留来恢复方法名；也可从 `dwr.xml` 泄露（备份文件、源码）直接读白名单。
- 变体：新版 DWR（`org.directwebremoting`）的 `exec` 路径与参数格式基本一致，仅脚本名/类名映射不同。
- 变体：方法参数是复杂对象时按 `c0-param0=Object_<id>:{属性:值}` 构造；数组用 `Array:<id>:[...]`。
- 关联：`[[web-generic-sqli-dwr-typed-param-injection-point]]` 是本卡最典型的消费方式（把注入 payload 放进 `c0-param0`）；`[[web-java-framework-gwt-rpc-hidden-method-authz-rce]]` 是另一套 Java RPC 协议（GWT-RPC）的同类「未授权方法调用」面。
- 边界：`debug=false` 且 `interface` 不可读、`<exclude>`/方法级 `include` 收紧到只放无参无副作用方法、servlet 被鉴权过滤器覆盖、DWR 版本启用 `scriptSessionManager` 校验时，利用面收窄。

## 检测与防御

- 检测：`/dwr/`、`/dwr/index.html`、`/dwr/test/` 出现匿名访问；`POST /dwr/exec/<类>.<方法>.dwr` 请求体含 `callCount=`、`c0-methodName=`；响应体含 `DWREngine._handleResponse`。
- 修复：生产关闭 `debug`（`debug=false`），删除 `index.html`/`test` 页面；`dwr.xml` 用 `<exclude>` 收紧到最小方法集，禁止暴露返回敏感数据或拼接 SQL 的方法。
- 加固：把 DWR servlet 纳入统一鉴权与 CSRF 校验；对 `/dwr/exec` 做方法白名单与参数类型/长度校验；WAF 对 `callCount=`/`c0-param` 特征与异常参数内容告警。
