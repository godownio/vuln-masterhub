---
id: web-java-component-mcms-dual-route-prefix-auth-bypass
title: MCMS 5.2.4 双路由前缀鉴权绕过：/ms/** 需登录、无前缀 /cms/** 直接未授权访问
type: scenario
domain: web
path: web/java/component
technique: cms-dual-requestmapping-prefix-auth-filter-bypass
aliases:
- MCMS 未授权访问
- MingSoft CMS 鉴权绕过
- ms.manager.path
- /cms 绕过 /ms
- 双 RequestMapping 前缀
- MCMS 5.2.4
tags:
- web
- java
- mcms
- mingsoft
- spring
- shiro
- auth-bypass
- unauth
- access-control
cve: []
severity: high
confidence: high
affected_versions: MCMS（MingSoft CMS）5.2.4（原文审计版本；其他版本未验证）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V223
  verified_at: '2026-11-07T06:47:54+08:00'
  notes: 已对照原文61张图逐张核对：图13 ContentAction @RequestMapping({${ms.manager.path}/cms/content,/cms/content}) 双路由、图14 未登录 GET /cms/category/list 返回栏目JSON、图15 /ms/cms/category/list 跳登录页均与卡一致；图16-31证实 /file/upload.do 等无 /ms 前缀接口未授权。未验证点：PoC未本机复跑；原文版本为MCMS-5.2.4审计环境，affected_versions已按原文审计版本标注（未给影响区间）；frontmatter无 sources/source_url；已修正卡内指向不存在卡 id 的 wiki 链接为 web-generic-sqli-mcms-mdiy-dict-orderby-injection。
---

## 一句话结论

MCMS 的 Action 用 `@RequestMapping({"${ms.manager.path}/cms/content", "/cms/content"})` 同时注册两套路由，而鉴权过滤器只保护带 `ms.manager.path`（默认 `ms`）前缀的 `/ms/**`；攻击者直接访问不带 `/ms` 的 `/cms/...` 路由即可绕过登录调用后台业务接口（文中 `/cms/category/list` 未登录返回栏目 JSON，访问 `/ms/...` 则跳转登录页）。

## 原理

- Spring MVC 的 `@RequestMapping` 支持数组，同一 Controller 方法会绑定多个 URL 路径；MCMS 把管理端路由写成 `${ms.manager.path}/cms/content` 和无前缀的 `/cms/content` 两套。
- 项目的登录/权限过滤器（Shiro 或自定义 HandlerInterceptor）按路径前缀拦截 `/ms/**`；`/cms/**` 不在过滤链里，于是同一业务方法经无前缀入口访问时完全不经过登录与权限校验。
- 参数绑定、Service、DAO 逻辑与 `/ms` 入口完全相同，所以 SQL 注入、上传、模板操作等后台功能都能从未授权入口触达；这解释了文章里多处“接口未授权，因为路由没有在 /ms 下”。
- 这是“鉴权挂在 URL 前缀而不是 Controller/方法”的典型错误：只要存在第二条不带前缀的映射，权限就形同虚设。

## 触发条件

- 目标为 MCMS 5.2.4 或采用同样双前缀映射的版本，且 `ms.manager.path` 配置为 `ms`。
- 目标 Action 同时注册了带 `${ms.manager.path}` 与不带前缀的路径（源码中大量存在）。
- 无前缀路由未被网关/WAF单独限制。

## 利用步骤

1. 从源码确认目标 Action 的 `@RequestMapping` 数组（如 `ContentAction`、`CategoryAction`、`FileAction`）。
2. 直接请求无前缀路径，例如 `GET /cms/category/list`，不带 Cookie/会话。
3. 对比访问 `/ms/cms/category/list`：后者会被重定向到 `/ms/login.do`，前者直接返回业务 JSON。
4. 对写操作（上传、模板保存/解压/删除）同样使用无前缀路由或 `FileAction` 的 `/file/**` 入口。

## PoC

```http
GET /cms/category/list HTTP/1.1
Host: target:8081
Accept: application/json
```

未登录即可返回栏目列表 JSON；而：

```http
GET /ms/cms/category/list HTTP/1.1
Host: target:8081
```

会返回 302 跳转到 `/ms/login.do`。文中测试环境为 `http://127.0.0.1:8081/ms/login.do`，默认口令 `msopen/msopen`，用于对照登录后的正常访问。

## 变体与关联

- **完全无前缀的 Action**：`FileAction` 直接映射 `/file`（`/file/upload.do` 等），连双前缀都不需要，天然绕过登录。
- **前缀可配置**：`ms.manager.path` 若被改为空或其他值，过滤规则与实际路由的对应关系会进一步错位。
- **关联**：[[web-java-component-mcms-fileaction-upload-blacklist-jspx-ads]]（未授权上传）、[[web-generic-sqli-mcms-mdiy-dict-orderby-injection]]（未授权 SQL 注入）、[[web-java-component-mcms-template-unzip-zipslip]]（后台 Zip Slip）。

## 检测与防御

- **检测**：对同一业务路径分别请求带/不带管理前缀的两个版本，比较响应是否都需要认证；源码审计时搜索 `@RequestMapping` 数组中的多路径映射。
- **防御**：权限校验绑定到 Controller/方法（注解或全局路由元数据），不要只按 URL 前缀过滤；对所有 `/cms/**`、`/file/**` 也纳入认证链；生产环境移除无前缀映射或统一由网关鉴权。
