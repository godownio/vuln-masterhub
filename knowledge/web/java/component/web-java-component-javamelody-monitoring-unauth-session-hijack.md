---
id: web-java-component-javamelody-monitoring-unauth-session-hijack
title: JavaMelody /monitoring 未授权：会话列表泄露 JSESSIONID 可劫持在线用户，JNDI/MBeans 泄露密钥文件名与数据库配置
type: scenario
domain: web
path: web/java/component
technique: javamelody-unauth-monitoring-session-id-hijack-jndi-mbeans-disclosure
aliases:
- JavaMelody 未授权
- JavaMelody /monitoring
- javamelody session hijack
- JSESSIONID 会话列表
- monitoring?part=sessions
- JNDI 树信息泄露
- MBeans 数据库配置泄露
tags:
- java
- javamelody
- monitoring
- unauthenticated
- session-hijack
- jsessionid
- information-disclosure
- jndi
- mbeans
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V268
  verified_at: '2026-11-07T18:25:58+08:00'
  notes: 已对照原文与11张图核对：统一身份认证跳转、Google 语法找到 /apply 路由、/monitoring?part=sessions 会话列表（sessionID 列）、替换 JSESSIONID 后进入业务系统（图5）、/monitor/log 旧日志、进程 part=processes、JNDI part=jndi&path=comp/Resources/WEB-INF/classes 列出 svr_pkcs8.key/svr_private.key/tsm_public.key/spring-*.xml/mybatis-config.xml、part=mbeans 的 Druid 数据源 jdbc:mysql://192.168.134.216:3306/student 与 Username 均与正文一致；文章未蹲到管理员会话、未读文件内容，卡按 medium 标注并明确不构成直接 RCE 合理。dedup 候选 Druid/SessionFilter 等为不同链；dup-scan 无涉及本篇 pair。未复现会话劫持。
---

## 一句话结论

Java 应用常集成 JavaMelody 监控组件，若 `/monitoring` 未配置访问控制，攻击者可直接打开监控台；`/monitoring?part=sessions` 会列出当前所有 HTTP 会话的 `sessionID`，把浏览器 Cookie 中的 `JSESSIONID` 换成某个在线用户的会话 ID，即可绕过统一身份认证直接以该用户身份访问业务系统；同一监控台还可查看操作系统进程、JNDI 树（项目结构、密钥文件名）和 MBeans（数据库 JDBC URL、用户名等）。文章未拿到管理员会话、也无法直接读取文件内容，因此主要是未授权访问、会话劫持与敏感信息泄露，不构成直接 RCE。

## 原理

- **JavaMelody 监控端点**：JavaMelody 是 Java Web 应用的性能监控组件，默认通过 `/monitoring`（或 `/<context>/monitoring`）提供页面，支持 `part=sessions`、`part=processes`、`part=jndi`、`part=mbeans` 等视图。该端点是否鉴权取决于部署配置；很多应用只依赖外层 SSO/网关，而监控端点本身未纳入保护或未配置 `javamelody` 的授权参数。
- **会话列表泄露**：`part=sessions` 页面展示每个会话的 `sessionID`、最后访问时间、年龄、IP、用户等信息。Java Web 应用通常用 `JSESSIONID` Cookie 标识会话；只要知道一个有效且未过期的 `sessionID`，就可以在本地设置同名 Cookie，服务端会把它当作该用户的会话，鉴权状态随之继承。
- **绕过 SSO**：统一身份认证通常在访问业务入口时重定向登录；但攻击者已经通过监控台拿到了业务应用的 `JSESSIONID`，可以直接请求业务 URL 并携带该 Cookie，跳过登录流程。文章正是用监控台列出的某个普通用户会话成功进入了系统。
- **JNDI 树信息泄露**：`part=jndi` 可浏览 `comp/Resources/WEB-INF/classes` 等 JNDI 命名空间下的资源条目，文章看到 `svr_pkcs8.key`、`svr_private.key`、`tsm_public.key`、`spring-*.xml`、`mybatis-config.xml`、`*.properties` 等文件名；该视图只列名称/类型，不能直接读取文件内容，但足以指导后续攻击（如密钥文件、配置文件路径）。
- **MBeans 信息泄露**：`part=mbeans` 展示 JMX MBean 属性，文章在 Druid 数据源 MBean 中看到 `jdbc:mysql://192.168.134.216:3306/student?...` 的 JDBC URL 与用户名，可用于内网定位与凭据攻击。
- **进程列表**：`part=processes` 泄露操作系统进程、PID、内存与 CPU 时间，暴露运行环境与部署形态。
- **为什么危害成立**：会话 ID 是认证凭据；拿到任意在线用户的会话即可读写该用户可见的数据与操作，若管理员在线则可进一步接管管理后台。即使没有管理员在线，泄露的数据库地址/用户名、密钥文件名和项目结构也可用于横向。

## 触发条件

- 目标 Java Web 应用集成了 JavaMelody，且 `/monitoring`（含各 `part`）可从攻击者网络访问、未配置认证或 IP 白名单。
- 应用使用 `JSESSIONID` 作为会话 Cookie；监控台的 session 列表与业务应用共享同一会话存储/容器。
- 至少存在一个有效在线会话（普通用户即可）；管理员在线时危害更大。
- 监控台未禁用 `sessions`/`jndi`/`mbeans`/`processes` 等敏感 part，或未做权限分级。
- 文章环境：目标入口会跳统一身份认证，作者通过目录爆破/搜索引擎找到应用路由与 `/monitoring`，再用会话 ID 替换绕过。

## 利用步骤

1. 对目标做目录/路径发现，或通过搜索引擎语法（如 `site:target.edu.cn monitoring`、`inurl:monitoring`）寻找 JavaMelody 入口；也可从 JS 资源、错误页、响应头推断应用路由。
2. 访问 `/monitoring`，确认监控台未要求登录；尝试 `/monitoring?part=sessions` 查看会话列表。
3. 从列表中选择一个有效、未过期、年龄较小的 `sessionID`（优先选择用户名列非空、IP 与目标业务匹配的会话）。
4. 在浏览器开发者工具或 Burp 中把业务站点 Cookie 的 `JSESSIONID` 改为该值，直接请求业务首页/接口，观察是否已登录。
5. 如拿到的是普通用户会话，可继续翻看该用户可见的数据与功能；同时监控新的会话列表，等待管理员登录后替换其 sessionID（文章编写 Burp 插件监控 session 变化，但未蹲到管理员）。
6. 访问 `/monitoring?part=processes` 收集进程信息，`part=jndi` 枚举项目结构与密钥/配置文件路径，`part=mbeans` 查找 Druid 等数据源的 JDBC URL、用户名等。
7. 将泄露的数据库地址/用户名、密钥文件名与业务功能结合，评估横向或凭据攻击路径（文章到此为止，未进一步利用）。

## PoC

```http
# 1) 未授权监控台
GET /monitoring HTTP/1.1
Host: target

# 2) 列出会话，获取 sessionID
GET /monitoring?part=sessions HTTP/1.1
Host: target

# 3) 用泄露的 sessionID 访问业务，绕过 SSO
GET /index HTTP/1.1
Host: target
Cookie: JSESSIONID=<从监控台获取的 sessionID>
```

```http
# 4) 敏感信息视图
GET /monitoring?part=processes HTTP/1.1
Host: target

GET /monitoring?part=jndi&path=comp/Resources/WEB-INF/classes HTTP/1.1
Host: target

GET /monitoring?part=mbeans HTTP/1.1
Host: target
```

监控台会话列表的关键字段：`sessionID`、最后接入时间、年龄、结束时间、IP 地址、用户；替换 `JSESSIONID` 即可复用该会话。

## 变体与关联

- 入口变体：JavaMelody 可能部署在 `/<context>/monitoring`、`/monitoring` 或自定义路径；`part` 参数可枚举 `sessions`、`processes`、`jndi`、`mbeans`、`http_sessions`、`sql` 等。
- 会话利用变体：拿到 sessionID 后可直接 Cookie 替换；若应用同时校验 IP/UA，需要匹配目标会话的来源特征，或寻找不校验的接口。
- 信息利用变体：JNDI 树只能看名字，可据此定位密钥/配置文件；MBeans 中的 JDBC URL/用户名可配合弱口令、数据库未授权或内网横向。
- 关联：[`web-java-component-druid-monitor-default-credentials`](web-java-component-druid-monitor-default-credentials.md)（另一 Java 监控台默认口令信息泄露）、[`web-generic-auth-sessionfilter-username-cache-key-session-hijack`](web-generic-auth-sessionfilter-username-cache-key-session-hijack.md)（会话缓存键导致劫持）、[`web-generic-auth-servlet-null-role-fail-open`](web-generic-auth-servlet-null-role-fail-open.md)（鉴权失败放行）。

## 检测与防御

- 对 `/monitoring` 及其所有 `part` 强制认证、IP 白名单或仅内网访问；不要仅依赖外层 SSO，监控端点自身也要纳入鉴权。
- 禁用不必要的监控视图（sessions/processes/jndi/mbeans），或按角色限制敏感 part；生产环境关闭 JavaMelody 或只暴露聚合指标。
- 使用不可预测、可轮换的会话 ID，登录后重新生成 session；Cookie 设置 `HttpOnly`/`Secure`/`SameSite`；对会话绑定 IP/UA 需谨慎避免误伤。
- 检测：`/monitoring?part=sessions|jndi|mbeans|processes` 的异常访问、短时间内大量会话枚举、同一 JSESSIONID 从不同 IP/UA 使用、监控台返回 200 的未认证请求。
- 响应：发现泄露后立即失效所有会话、轮换密钥与数据库凭据、检查是否被用于访问业务数据；升级/加固 JavaMelody 配置。
