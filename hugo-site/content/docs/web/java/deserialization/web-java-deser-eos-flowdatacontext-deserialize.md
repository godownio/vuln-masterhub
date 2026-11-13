---
id: web-java-deser-eos-flowdatacontext-deserialize
title: 普元 EOS ControllerServlet 的 _eosFlowDataContext 参数 Base64 原生反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: eos-flowdatacontext-contextserializer-deserialize
tags:
- java
- deserialization
- eos
- primeton
- controller-servlet
- base64
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:51:08+08:00'
  notes: 已对照原文与图03-04核对：ControllerServlet 映射 *.flow 等后缀，AbstractPageFlowProcessor 参数集 build 读取 _eosFlowDataContext 非空即调用 ContextSerializer.deserialize（BASE64Decoder→ObjectInputStream.readObject，无白名单）；图04 POST /coframe/auth/login/org.gocom.components.coframe.auth.login.login.flow 携带 _eosFlowDataContext，与卡片 PoC 一致；原文未附完整 gadget 执行截图（卡片已注明）。修正：EOS6 只在原文产品简介出现，默认 web.xml 引自官网且未标版本，图03 依赖为 eos-server-access-7.1.4.0.jar，故移除卡内 EOS6 归因（改为普元 EOS 并注明截图依赖），affected_versions 已清除（库内卡片与 staging 草稿同步）。未在本机复跑。
url: /docs/web/java/deserialization/web-java-deser-eos-flowdatacontext-deserialize/
draft: false
kb_aliases:
- EOS 反序列化
- _eosFlowDataContext
- ContextSerializer.deserialize
- 普元 EOS 漏洞
- com.eos.access.http.ControllerServlet
---

## 一句话结论

普元 EOS 的 `com.eos.access.http.ControllerServlet` 在处理 `*.flow` 等映射请求时，会把请求参数 `_eosFlowDataContext` 当作 Base64 字符串交给 `ContextSerializer.deserialize`，内部直接 `new ObjectInputStream(...).readObject()`；攻击者在该参数中放入任意原生序列化 gadget 的 Base64，即可在服务端触发反序列化 RCE（原文示例请求走 `/coframe/auth/login/*` 登录流程）。

## 原理

- **入口 Servlet**：EOS 默认 `web.xml` 把 `ControllerServlet` 映射到 `*.flow`、`*.flowx`、`*.gzip`、`*.ajax`、`*.beanx`、`*.debug`、`*.remote`、`*.precompile`、`*.ext`、`*.terminate` 等后缀，以及多个 `WS*ManagerService` 路径；`InterceptorFilter` 再按 `handler-web.xml`/`handler-processor.xml` 组装拦截器与处理器链。
- **参数集构建**：`AbstractPageFlowProcessor.doProcess` 在构建 `IParameterSet` 时调用 `build(...)`；`build` 读取 `this.values.get("_eosFlowDataContext")`，只要值非空就进入 `ContextSerializer.deserialize(var33)`。
- **危险 sink**：`ContextSerializer.deserialize` 用 `BASE64Decoder` 解码字符串，`new ByteArrayInputStream(buf)` 包装后 `new ObjectInputStream(bais).readObject()`——没有任何类白名单、`ObjectInputFilter` 或类型校验，等于一个 HTTP 参数直达的 Java 原生反序列化点。
- **为什么参数可控**：`_eosFlowDataContext` 是普通请求参数（GET/POST 均可被参数集读取），攻击者只需构造 Base64 序列化流即可；原文截图显示登录路径 `/coframe/auth/login/org` 携带该参数，说明登录流程也会进入参数集构建，鉴权要求取决于部署的拦截器白名单（登录类路径通常无需登录）。
- **危害**：原生反序列化可接任意 classpath gadget（CommonsCollections、CommonsBeanutils、Rome、JDBC 等）；若目标 JDK/依赖满足条件，直接命令执行、文件写入或 JNDI 出网。即使过滤器只做类名黑名单，也可用未拦截的 gadget 或二次反序列化链绕过。

## 触发条件

- 目标部署普元 EOS（原文引用官网默认 web.xml；截图依赖为 eos-server-access-7.1.4.0.jar，原文未明确标注产品版本；亦适用于使用相同 `ControllerServlet`/`ContextSerializer` 代码的 EOS 系产品），默认或类似 `web.xml` 映射生效。
- 请求能到达 ControllerServlet 的参数集构建逻辑（如 `*.flow`、登录流程等），且 `_eosFlowDataContext` 参数被读取。
- 目标 classpath 存在可用反序列化 gadget；JDK 未启用有效的 JEP 290 全局过滤器。
- 该路径的拦截器未要求登录（登录流程）或攻击者已有低权限会话。

## 利用步骤

1. 指纹识别 EOS：访问 `*.flow` 后缀路径、观察 `ControllerServlet` 报错、检查 `handler-processor.xml` 相关特征或默认登录页 `/coframe/auth/login/`。
2. 选择一个在目标 classpath 可用的 gadget（如 CommonsCollections），生成原生序列化字节并 Base64 编码。
3. 向 ControllerServlet 可处理的路径（如 `/coframe/auth/login/org`）发送 `_eosFlowDataContext=<base64>` 参数；请求方式按目标参数解析习惯选 GET/POST。
4. `ContextSerializer.deserialize` 解码并 `readObject`，触发 gadget 链；若走 JNDI/远程类加载，同时观察目标的出站请求。
5. 验证：本地/回显通道出现命令执行或 DNS/HTTP 回连；失败时检查参数是否被框架覆盖、路径是否进入参数集构建、过滤器与 gadget 依赖。

## PoC

```http
POST /coframe/auth/login/org HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

_eosFlowDataContext=<Base64(原生序列化 gadget 字节)>
```

说明：原文只给出 `_eosFlowDataContext` 请求样例与 `ContextSerializer.deserialize` 代码，未附完整 gadget 执行截图；实际利用需按目标 classpath 选择链并确认参数解析路径。本卡未在本机复跑。

## 变体与关联

- [[web-java-deser-readobject-reflection-rmiconnector-secondary]]：同类“参数/字段直达 readObject”的入口，可接二次反序列化绕过黑名单。
- [[web-java-deserialization-custom-readobject-runtime-exec]]、[[web-java-deserialization-app-readobject-controlled-put-aspectj-file-write]]：其它框架自定义 readObject 入口，可对照黑名单与触发差异。
- [[web-java-deser-objectstreamclass-private-readobject-hook]]：反序列化过滤器/钩子被绕过的通用思路。
- 变体：`_eosFlowDataContext` 也可出现在不同业务后缀（`.flow`、`.ajax` 等）与不同参数集实现中；gadget 可按 classpath 替换。
- 边界：目标启用 JEP 290 全局过滤器并拦截 gadget 类、ControllerServlet 映射被移除、或该参数在到达 `build` 前被签名/加密时链断。

## 检测与防御

- 检测：请求参数名 `_eosFlowDataContext` 出现 Base64 长串；反序列化调用栈出现 `ContextSerializer.deserialize → ObjectInputStream.readObject`；EOS 日志中的 `process _eosFlowDataContext has exception!` 等异常。
- 防御：升级/修补 EOS 或移除该参数的序列化能力；对反序列化数据做签名/加密与类型白名单；启用 JEP 290 `ObjectInputFilter`；在 WAF/网关拦截 `_eosFlowDataContext` 等框架内部参数；最小化 classpath gadget。
- 响应：保留原始请求与序列化字节，确认是否执行命令/出网，排查同入口的其它参数与业务路径。
