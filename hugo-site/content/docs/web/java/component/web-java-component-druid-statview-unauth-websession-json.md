---
id: web-java-component-druid-statview-unauth-websession-json
title: Druid StatViewServlet 监控台整体未鉴权：直接访问 /druid/websession.html 与 websession.json 读取全站会话 ID
type: scenario
domain: web
path: web/java/component
technique: druid-statview-unauth-monitor-access
tags:
- java
- druid
- spring-boot
- unauthorized
- monitoring-console
- session-disclosure
- information-disclosure
cve: []
severity: medium
confidence: high
status: verified
created: '2026-02-26'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T14:02:01+08:00'
  notes: 已对照原文核对：登录后台后 Burp 被动发现 Druid、/druid/websession.html 直接渲染 Session 列表（SESSIONID/Principal/创建时间/最后访问时间/访问 IP/请求次数，图 18/19）与原文一致；StatViewServlet loginUsername/loginPassword 未配置或被鉴权白名单排除的成因解释与 Druid 官方机制相符。未验证点：原文未展示 websession.json/basic.json 的具体响应体，卡片 PoC 中的 JSON 样例为按 Druid 通用格式补写。
url: /docs/web/java/component/web-java-component-druid-statview-unauth-websession-json/
draft: false
kb_aliases:
- Druid Unauthorized
- /druid/basic.json
- druid/websession.html
- Druid 未授权访问
- Druid Session 监控
---

## 一句话结论

当 Druid 的 `StatViewServlet` 未配置 `loginUsername`/`loginPassword`，或把 `/druid/**` 放进了业务鉴权拦截器的白名单，监控台就对所有人开放：不用登录、不需要任何凭据，直接访问 `/druid/websession.html`（或 `/druid/websession.json`）就能拿到全站活跃 session 的 SessionID、Principal、创建时间、最后访问时间、访问 IP 与请求次数，配合 SQL/URI/数据源监控即可把目标转成半白盒，并具备会话劫持的前提条件。

## 原理

- Druid 的 `StatViewServlet` 由 `loginUsername`、`loginPassword` 两个初始化参数决定是否开启登录；两个参数都不配置时，`/druid/index.html`、`/druid/websession.html` 等页面不要求认证即可直接渲染，`/druid/*.json` 接口同理直接返回数据。
- 另一种常见成因是“配置了登录但被绕过”：项目为了让前端或运维方便访问，把 `/druid/**` 排除在 Spring Security / Shiro / 自研拦截器的鉴权路径之外，于是监控台本身虽然存在登录页，其子路径却不校验会话，`/druid/websession.html` 依然可达。
- 监控页的数据来源是 Druid 的 StatFilter 统计：`websession` 视图列出 Druid 采集到的 `HttpSession` 记录，字段含 SessionID、Principal（登录主体）、创建时间、最后访问时间、请求次数、访问 IP 地址。这些 SessionID 就是容器的会话标识，一旦目标把会话 ID 直接放在 Cookie 里且没有额外绑定，就构成劫持素材。
- 为什么危害不止“信息泄露”：数据源视图给出 JDBC URL 与用户名（便于数据库弱口令尝试）；SQL 监控给出真实表名与完整查询；URI 监控给出全部业务路由（含隐藏后台）；classpath/JVM 视图给出依赖与部署路径。多个视图合起来等于一次免费白盒审计。
- 和“Druid 默认口令登录”的区别在于入口条件：默认口令场景需要猜中口令，本场景是监控台根本没有开启认证（或认证路径被排除），无需任何凭据即可读，触发更容易。

## 触发条件

- 目标为 Spring Boot 或传统 Java Web 项目，引入 Druid 并启用 `StatViewServlet`（`stat-view-servlet.enabled=true` 或 web.xml 中注册）。
- `loginUsername`/`loginPassword` 未配置（不启用登录），或虽配置但 `/druid/**` 未被业务鉴权覆盖。
- `/druid/index.html`、`/druid/basic.json`、`/druid/websession.html` 从外网可达，未被 nginx/网关整体拦截。
- 监控路径未做来源 IP 白名单。
- 攻击者无需任何账号。

## 利用步骤

1. 指纹：访问 `/druid/index.html`，若直接渲染监控台（不跳 `/druid/login.html`）即为未鉴权；也可请求 `/druid/basic.json` 看是否返回 `ResultCode`/`Content` 结构。
2. 先用 `/druid/basic.json` 或 `/druid/stat.json` 确认 Druid 版本与统计可用。
3. 访问 `/druid/websession.html` 查看 Session 列表；或直接拉 `/druid/websession.json` 便于批量提取（返回 JSON 含 `SESSIONID`、`Principal`、`CreateTime`、`LastAccessTime`、`RequestCount`、`RemoteAddress`）。
4. 访问 `/druid/datasource.html`、`/druid/sql.html`、`/druid/uri.html`、`/druid/spring.html` 收集 JDBC URL、真实 SQL、全部路由、Spring bean 映射。
5. 用泄露的 SessionID 在 Cookie 中替换自身会话（如 `JSESSIONID=<泄露值>`）尝试接管；用 JDBC URL/用户名做数据库弱口令尝试；用 URI 列表寻找未授权后台接口。

## PoC

```http
GET /druid/index.html HTTP/1.1
Host: target

HTTP/1.1 200 OK
<!-- 直接渲染监控台，无 302 跳 login.html -->
```

```http
GET /druid/websession.json HTTP/1.1
Host: target

HTTP/1.1 200 OK
{"ResultCode":1,"Content":[{"SESSIONID":"...","Principal":"admin","CreateTime":"2024-08-20 20:00:00","LastAccessTime":"2024-08-21 21:44:00","RequestCount":224,"RemoteAddress":"5.2.x.x"}]}
```

```http
GET /druid/datasource.json HTTP/1.1
GET /druid/sql.json HTTP/1.1
GET /druid/uri.json HTTP/1.1
Host: target
```

## 变体与关联

- 变体：仅 `index.html` 与 `login.html` 可达但被网关拦截时，直接逐个试 `/druid/*.json`，不少部署只保护了 html 页面。
- 变体：URL 大小写/后缀绕过（`/druid/index.html;.jpg`、`/Druid/index.html`、`//druid/index.html`）可绕过基于前缀匹配的拦截器。
- 变体：Druid 版本较新时默认不再暴露部分视图，需用 `/druid/basic.json` 判断可用性。
- 关联：[[web-java-component-druid-monitor-default-credentials]]（同组件、同监控台；该卡入口是默认/弱口令登录，本卡是不开启认证直接读，触发条件与 PoC 不同）。
- 关联：[[web-java-framework-shiro-spring-path-auth-bypass]]（同为“鉴权路径被排除/前缀匹配缺陷”导致的监控面暴露）。

## 检测与防御

- 防御：不需要监控时关闭 `stat-view-servlet.enabled`；必须开启时配置强随机 `loginUsername`/`loginPassword`，并加 `allow` 来源 IP 白名单。
- 防御：不要把 `/druid/**` 放入鉴权白名单；用统一的鉴权过滤器覆盖全部管理/监控路径，避免前缀匹配漏配。
- 防御：生产环境把监控台放在内网或独立管理端口，外网不可达；对 `/druid/*.json` 同样做鉴权。
- 检测：外网访问 `/druid/websession.html`、`/druid/websession.json`、`/druid/basic.json` 的日志；短时间内连续访问多个监控视图；同一 IP 拉取 websession 后出现大量异常会话 Cookie 尝试。
- 检测：告警 Druid 监控台在未认证状态下返回 200（正常应为 302 到 login.html）。
