---
id: web-java-component-apereo-cas-heapdump-flow-execution-key-forgery
title: Apereo CAS 5.3.16 默认口令 + /status/heapdump 泄露 flow execution 加密/签名密钥 → 伪造 execution 参数执行命令
type: scenario
domain: web
path: web/java/component
technique: cas-heapdump-flow-execution-cipher-key-forgery
tags:
- java
- cas
- apereo
- heapdump
- default-credentials
- flow-execution
- cipher-key
- forgery
- rce
cve: []
severity: high
confidence: medium
affected_versions: Apereo CAS 5.3.16（原文版本；cas-overlay-template 5.3 默认配置）
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:58:35+08:00'
  notes: 已对照原文与 17 张图核对：CAS 5.3.16 默认 casuser::Mellon、Dashboard→/status/heapdump、MAT OQL WebflowConversationStateCipherExecutor 取 encryptionSecretKey/signingKey、伪造 execution+cmd 执行与图 13-17 一致；affected_versions 5.3.16 按原文保留；伪造 execution 依赖原文配套 exp5316 工程，未复跑
url: /docs/web/java/component/web-java-component-apereo-cas-heapdump-flow-execution-key-forgery/
draft: false
kb_aliases:
- CAS heapdump 密钥泄露
- Apereo CAS execution 参数伪造
- WebflowConversationStateCipherExecutor
- CAS 默认口令 casuser Mellon
- CAS /status/heapdump
---

## 一句话结论

Apereo CAS 5.3.16 若使用默认静态账号 `casuser::Mellon` 且暴露 `/status/dashboard`、`/status/heapdump`，攻击者可登录后台下载堆转储，用 MAT 的 OQL 从 `WebflowConversationStateCipherExecutor` 对象中取出 `encryptionSecretKey` 与 `signingKey`，再用这两把密钥伪造登录请求里的 `execution` 参数并附加 `cmd` 参数，让服务端恢复被篡改的 Web Flow 执行状态并执行命令，最终读取 flag。

## 原理

- **默认静态认证**：CAS overlay 模板的 `application.properties` 默认包含 `cas.authn.accept.users=casuser::Mellon`，属于演示用静态账号；未改成 LDAP/JDBC 等真实认证源时，攻击者可直接用该账号登录。
- **Dashboard 暴露管理端点**：登录后访问 `service=<target>/status/dashboard` 进入 CAS Dashboard，同级的 `/status/heapdump` 可直接下载 JVM 堆转储；这是 actuator 式的运维端点未限制访问。
- **flow execution 是客户端状态**：Spring Web Flow 的 `execution` 参数（`CasDefaultFlowUrlHandler.getFlowExecutionKey` 直接 `request.getParameter("execution")`）是一个 `ClientFlowExecutionKey`，内含序列化的 flow 执行状态；服务端用 `BaseBinaryCipherExecutor.decode` 先 `verifySignature` 校验签名，再用 AES 解密，恢复状态后继续执行流。
- **密钥只在内存中**：`WebflowConversationStateCipherExecutor` 构造时接收 `encryptionSecretKey` 与 `signingKey`（`BaseBinaryCipherExecutor` 的字段），正常情况下攻击者无法获得；堆转储把这两个字段原样带出，等于同时拿到加密密钥和 MAC 签名密钥。
- **为什么能伪造**：AES 保证机密性、签名保证完整性，两者都依赖密钥保密；密钥泄露后，攻击者可以构造任意 `ClientFlowExecutionKey` 密文并生成合法签名，服务端会把它当作自己签发的状态来恢复，进而影响流的执行路径/属性；在登录 POST 中同时带上 `cmd` 参数，即可在该状态下触发命令执行并把输出回显到响应。
- **链式条件**：需要默认/弱口令能登录、`/status/*` 未被网络层限制、heapdump 含 keys、攻击者能生成与目标版本匹配的 flow 状态密文（原文使用配套 exp 工程完成该步）。

## 触发条件

- 目标为 Apereo CAS 5.3.x（原文 5.3.16），仍使用 `cas.authn.accept.users` 默认静态账号或等价弱口令。
- `/status/dashboard`、`/status/heapdump` 等管理端点可从外网访问且无额外鉴权。
- 攻击者能下载并分析 heapdump（MAT/OQL），且能访问与服务端一致的 CAS/Spring Web Flow 版本以生成合法密文。
- 登录流程使用客户端 flow execution 状态（默认配置）。

## 利用步骤

1. 访问 CAS 登录页，用默认账号 `casuser` / `Mellon`（来自 `application.properties` 的 `cas.authn.accept.users`）登录。
2. 登录后把路径改为 `/status/heapdump` 下载堆转储；若 Dashboard 链接不可见，可构造 `service=https://target/status/dashboard` 的登录 URL 进入。
3. 用 Eclipse MAT 打开 heapdump，执行 OQL：
   `select * from org.apereo.cas.util.cipher.WebflowConversationStateCipherExecutor`
4. 在结果中保存 `encryptionSecretKey`（byte[16]）与 `signingKey`（AES Key 的 key 字节）。
5. 用配套 exp 工程（原文为 `exp5316.java`）读取两把密钥，生成伪造的 `execution` 值；抓取正常登录包，把 `execution` 参数中 uuid 之后的部分替换为生成值。
6. 在同一个 POST 中追加 `cmd=<命令>`（如 `cat /flag.txt`），提交后命令输出随响应返回。

## PoC

```text
POST /login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=aa&password=bb&cmd=cat /flag.txt&execution=<伪造的 ClientFlowExecutionKey>
```

```text
# MAT OQL
select * from org.apereo.cas.util.cipher.WebflowConversationStateCipherExecutor
```

伪造 `execution` 需要原文配套 exp 工程；仅凭堆转储中的密钥无法直接复制出可用密文（还依赖目标版本的 flow 状态结构与序列化格式）。

## 变体与关联

- 变体：若 `/status/heapdump` 被关闭，可寻找其他 heapdump 入口（actuator、诊断端口、错误页导出），密钥字段名与类名不变。
- 变体：CAS 的 `service` 参数未校验时还可把 ST ticket 带到任意外域接管账号，见 [[web-generic-auth-cas-service-open-redirect-ticket-theft-ato]]。
- 关联：heapdump 提取其他组件密钥的同类思路见 [[web-java-framework-shiro-actuator-heapdump-key-account-forgery]]；JDK 反序列化链与 flow 状态的关系可参考 [[web-java-deser-hessian-typed-map-jsonobject-wrap-tostring]]。
- 边界：原文未展开伪造 flow 状态的具体序列化结构，exp 依赖外部工程，故 confidence 标 medium；若目标改过 flow 加密密钥或禁用客户端状态，链断。

## 检测与防御

- 修复：删除默认静态账号，改用真实认证源；禁止外网访问 `/status/**`、`/actuator/**`，heapdump 端点必须鉴权并限制来源。
- 加固：为 flow execution 状态使用独立强密钥并定期轮换；不要把管理端点与业务登录放在同一暴露面。
- 检测：登录日志出现 `casuser` 默认账号；`/status/heapdump` 被下载；同一账号短时间内登录并携带异常 `cmd` 参数或超长 `execution`。
