---
id: web-java-deser-hessian-xxl-job-api-waf-bypass-dirty-data
title: XXL-Job /api Hessian 反序列化实战 WAF 绕过：//api 双斜杠 + javachain 脏数据/超长 UTF-8 混淆
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: xxl-job-hessian-waf-bypass-dirty-data
aliases:
- xxl-job WAF 绕过
- //api 双斜杠
- javachain Hessian2Payload
- 脏数据填充
- dirtyCollectionSize
- overlong UTF-8 混淆
- X-Authorization 命令回显
tags:
- java
- hessian
- deserialization
- xxl-job
- waf-bypass
- dirty-data
- overlong-encoding
- javachain
- double-slash
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: xxl-job 2.0.2 或更低
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:46:03+08:00'
  notes: 已对照原文与图片16-23核对：/xxl-job//api 返回 request data is empty、X-Authorization ls/ifconfig 回显、dirtyCollectionSize=10000/dirtyClassSize=0/overlongMode=1、JDK 8u231 一致；PoC 未在本库执行。
---

## 一句话结论

实战中 xxl-job 的 context path 可能是 `/xxl-job` 而不是 `/xxl-job-admin`，`/api` 会被 WAF 拦截；用 `//api` 双斜杠让 WAF 的路径规则不匹配、后端仍路由到 `/api`，再用 javachain 的 Hessian2Payload 加入随机集合“脏数据”与 2/3 字节 UTF-8 超长编码混淆 payload，并把命令放在 `X-Authorization` 头里，可绕过 WAF 完成 Hessian 反序列化 RCE 并在响应中拿到 `ls`/`ifconfig` 输出。

## 原理

- 漏洞入口与现有卡一致：XXL-Job Admin 的 `JobApiController.api()` 标注 `@PermissionLimit(limit=false)`，`/api` 不校验登录；`XxlJobDynamicScheduler.invokeAdminService()` → `ServletServerHandler.handle()` → `parseRequest()` 调用 Hessian `deserialize()`，请求体直接进入 Hessian 反序列化。
- 路径绕过：WAF 按字面路径匹配 `/api` 或规则只在单斜杠路径上生效；请求 `/xxl-job//api` 时 WAF 看到的是带双斜杠的路径（可能不命中规则），而 Tomcat/Spring 规范化重复斜杠后仍映射到 `/xxl-job/api`。原文用 `//api` 访问到了接口，返回 `XxlRpcException: xxl-rpc request data is empty`，证明已进入 Hessian 处理。
- 脏数据混淆：javachain 的 Hessian2Payload 支持 `dirtyCollectionSize`（随机使用 Array/LinkedList/HashMap/LinkedHashMap/TreeMap 等集合封装 object，并指定脏数据大小）、`dirtyClassSize`（用 LinkedList 包裹随机垃圾类名来封装 object）和 `overlongMode`（0 关闭；1 随机混合 2/3 字节 UTF-8 overlong；2 纯 2 字节；3 纯 3 字节）。这些填充不改变反序列化语义，却让 payload 体积大、字节分布随机、类名不以明文出现，降低 WAF 特征命中率。
- 超长编码：把类名/字符串的 ASCII 字节用 2/3 字节 UTF-8 overlong 形式重写，Java 解码后仍是原类名，但原始字节中不再有 `SpringAbstractBeanFactoryPointcutAdvisor` 等明文；与脏数据叠加后，基于子串/正则的 WAF 很难匹配。
- 命令回显：原文使用 javachain 的 Hessian2 原生 JDK 链，命令放在 `X-Authorization` 头（如 `ls`、`ifconfig`），响应体直接返回命令输出（79 字节的目录列表、4344 字节的 ifconfig）。这比 JNDI/反弹 Shell 更适合只出不进或 WAF 只监控 body 的场景。
- 版本/环境：原文用 xxl-job 2.0.2 与 JDK 8u231 验证；8u121 之后 RMI/LDAP 远程 codebase 默认受限，但 javachain 的原生 JDK 链仍可执行，说明该打法不依赖远程类加载。

## 触发条件

- 目标暴露 xxl-job admin `/api`（context path 可能是 `/xxl-job`、`/xxl-job-admin` 或其他），且后端存在 Hessian 反序列化入口。
- WAF 只按字面路径/固定 payload 子串匹配，未对路径做规范化、未对请求体做 Hessian 语义解析；或规则可被脏数据/超长编码稀释。
- Tomcat/Spring 会把 `//` 等重复斜杠规范化到真实路由。
- classpath 存在可用 Hessian gadget/JDK 原生链；JDK 8 环境（原文 8u231）可直接用原生链。
- 攻击者可发送较大的 POST body，且响应可观测（命令回显/异常栈）。

## 利用步骤

1. 识别 xxl-job 与真实 context path：访问登录页、静态资源，确认 `/xxl-job` 或 `/xxl-job-admin`。
2. 测试 `/api` 是否被 WAF 拦截；再试 `//api`（如 `/xxl-job//api`），观察是否返回 `xxl_rpc request data is empty` 或 Hessian 异常，确认绕过路径规则。
3. 用 javachain 选择 Hessian2Payload → Hessian2 反序列化 → 原生 JDK 链；设置 `dirtyCollectionSize=10000`、`dirtyClassSize=0`、`overlongMode=1`（按 WAF 调整 2/3 字节模式），生成 payload。
4. 把要执行的命令放入 `X-Authorization` 头（如 `ls`），POST 到 `/xxl-job(-admin)//api`，`Content-Type: x-application/hessian`，body 为原始/Base64 解码后的 Hessian 流。
5. 观察响应体是否返回命令输出；若被拦，调整脏数据大小、overlong 模式、路径变体（`/.;/`、`%2f`、大小写）或换 header 名。
6. 在 JDK 8u231 等高版本环境复测原生链；成功后清理文件/进程并记录 WAF 规则变化。

## PoC

路径绕过验证（返回 `request data is empty` 说明到达接口）：

```http
POST /xxl-job//api HTTP/1.1
Host: <target>
Content-Type: x-application/hessian
Content-Length: 0
```

带命令回显的请求（body 为 javachain 生成的 Hessian2 流，`X-Authorization` 为命令）：

```http
POST /xxl-job-admin/api HTTP/1.1
Host: <target>
Accept: */*
Content-Type: x-application/hessian
X-Authorization: ls
Content-Length: <len>

<hessian2-bytes>
```

原文响应体（节选）返回目录列表：

```text
LICENSE
NOTICE
doc
pom.xml
xxl-job-admin
xxl-job-core
xxl-job-executor-samples
```

另一目标用 `X-Authorization: ifconfig` 返回 4344 字节的网卡信息，确认命令执行。原文还展示了 `{{base64dec(...)}}` 形式与 `//api` 路径；本卡不复述完整 payload 字节。

## 变体与关联

- 路径变体：`//api`、`/.;/api`、`%2f`、重复斜杠、大小写、context path 前后加 `/`；核心是 WAF 与后端规范化差异。
- 混淆变体：`dirtyCollectionSize` 调大、`dirtyClassSize` 混入垃圾类、`overlongMode` 2/3 字节、Base64/Gzip 编码；与现有 UTF-8 overlong 卡同源。
- 链变体：Spring AOP/JNDI、Rome、XBean、JDK8 原生链；出网用 JNDI/反弹，不出网用原生链 + 命令回显。
- 关联卡：[[web-java-deser-hessian-xxl-job-admin-api-entry]]（同一入口的基础利用）、[[web-java-deser-hessian-utf8-overlong-encoding-bypass]]（超长编码原理）、[[web-generic-auth-403-resource-suffix-path-dictionary-bypass]]（路径规范化/后缀绕过）、[[web-java-deser-jdk-xslt-process-main-chain]]（JDK8 原生链）。
- 边界：WAF 若对请求体做 Hessian 语义解析/类名解码后匹配，脏数据与 overlong 无效；后端若不规范化 `//` 或网关直接拒绝，路径绕过失效。

## 检测与防御

- WAF/网关：先规范化路径（解码、合并重复斜杠、去 `;` 参数、大小写归一）再匹配；不要把 `/api` 规则只写在单斜杠路径上。
- Hessian 防护：启用 SerializerFactory 类白名单，拒绝 `AbstractBeanFactoryPointcutAdvisor`、`UIDefaults`、`SwingLazyValue`、`Process` 等 gadget；仅黑名单不足。
- 请求体检测：对 Hessian 流做解码后再检查类名/方法名，不能只看原始字节；对超大 body、随机集合/垃圾类名、异常编码做告警。
- 访问控制：`/api` 只允许执行器网段访问，增加鉴权/token；不要把 admin 暴露到公网。
- 检测：`//api`、`%2f`、重复斜杠请求；`X-Authorization` 等非标准头携带命令；响应体出现 `ls`/`ifconfig` 输出或异常 Hessian 栈；升级 xxl-job 并监控。
