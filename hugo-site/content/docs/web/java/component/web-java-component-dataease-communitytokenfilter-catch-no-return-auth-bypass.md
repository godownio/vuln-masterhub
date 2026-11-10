---
id: web-java-component-dataease-communitytokenfilter-catch-no-return-auth-bypass
title: DataEase CommunityTokenFilter 校验失败后未在 catch 中断（fail-open）+ 伪造 uid=1 JWT 的鉴权绕过
type: scenario
domain: web
path: web/java/component
technique: servlet-filter-fail-open-jwt-auth-bypass
tags:
- dataease
- auth-bypass
- jwt
- filter
- fail-open
- java
- x-de-token
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-13
  verified_at: '2026-11-08T07:10:43+08:00'
  notes: '已对照原文与24张图核对：FilterConfig 中 TokenFilter setOrder(0) 高于 CommunityTokenFilter setOrder(5)(图12)、TokenUtils#validate 仅校验 length<100(图14)、userBOByToken 取 uid 且只判空(图15)、CommunityTokenFilter catch 发送 401 后无 return、其后仍执行 filterChain.doFilter(图11)，v2.10.10 修复 diff 在 catch 内新增 return(图10下)、release notes『修复社区版存在的权限绕过漏洞』(图07)、commit『fix: 安全漏洞-社区版权限绕过 H2 RCE Bypass』(图08/09)，结论与原理成立；用 uid=1 的 X-DE-TOKEN 请求 /de2api/datasource/getSchema 已进入业务 handler(图16 返回 400 getWriter already called)可证绕过。已 --clear affected_versions：原文未给受影响区间，v2.10.9 只是安装包/源码 tag 的测试环境版本(v2.10.10 release note 与 compare 只能说明修复位置)，原字段还带括号注释，按 brief 清除。未验证点：PoC 请求体 configuration 被原文作者刻意打码，卡片以省略号代替，鉴权绕过本身不依赖该字段；H2 RCE 半链已在 skipped 中并入既有卡，未新增。'
url: /docs/web/java/component/web-java-component-dataease-communitytokenfilter-catch-no-return-auth-bypass/
draft: false
kb_aliases:
- DataEase 权限绕过
- CommunityTokenFilter doFilter 绕过
- X-DE-TOKEN uid=1 JWT
- 过滤器 catch 未 return
---

## 一句话结论

DataEase v2.10.9 的 `io.dataease.auth.filter.CommunityTokenFilter#doFilter` 在校验 token 失败时，异常被 `catch` 捕获后虽写入了 401 UNAUTHORIZED 响应，却**没有 return/抛错中断**，代码继续向下执行 `filterChain.doFilter(...)`，请求仍进入业务 handler（fail-open）；攻击者只需在 `X-DE-TOKEN` 请求头里放一个长度 <100、含 `uid=1` 的 JWT（可直接复用登录接口返回的 JWT），让优先级更高的 `TokenFilter` 通过并进入本 filter 的绕过分支，即可未授权访问后台接口（如数据源管理），为后续 H2 JDBC RCE 铺路。

## 原理

- 鉴权由 `io.dataease.auth.filter` 下两个 Filter 串联：`TokenFilter#doFilter`（优先级更高，见 `FilterConfig`）与 `CommunityTokenFilter#doFilter`。请求需依次走完两个 doFilter 才能进入业务 handler。
- `TokenFilter` 要求存在 `X-DE-TOKEN` 请求头；`TokenUtils#validate` 校验其长度小于 100；`TokenUtils#userBOByToken` 要求 JWT 里存在 `uid` 字段（`uid=1` 即可，无需与真实签名匹配即可走到下一个 filter）。满足后进入 `CommunityTokenFilter`。
- `CommunityTokenFilter#doFilter` 的 token 校验逻辑放在 try 块里（`verifier.verify(token)`），校验失败抛出的异常被 `catch` 捕获；catch 分支组装并发送了 `HttpStatus.UNAUTHORIZED` 响应，但**没有 `return`/`throw` 中断**，方法继续顺序执行到 catch 之外的 `filterChain.doFilter(...)`，于是请求仍被放行进入业务 handler——典型的 fail-open 认证缺陷（已写 401 但链未断）。v2.10.10 的修复即在 catch 中补上中断（release notes 写明"修复社区版存在的权限绕过漏洞"，commit 为"安全漏洞-社区版权限绕过 H2 RCE Bypass"）。
- 构造 JWT：原文直接取登录接口后端返回的 HS256 JWT，解码为 `{"typ":"JWT","alg":"HS256"}.{"uid":1,"oid":1,"exp":...}.<签名>`，说明只需一个结构合法、含 uid 的 token 即可触发该路径。
- 根因：过滤器把"验证失败"当作可继续的异常而非终止条件，且前置过滤器对 token 的校验可被低成本满足。

## 触发条件

- 目标为 DataEase v2.10.9（社区版），未升级到 v2.10.10 修复版；
- 攻击者能访问 Web 接口并自定义 `X-DE-TOKEN` 请求头；
- 目标接口经过 `TokenFilter` + `CommunityTokenFilter` 链（后台接口如 `/de2api/datasource/*`）；
- 前置校验只要求 token 长度 <100 与含 uid，不强制有效签名/会话绑定（或可用登录返回的 token）。

## 利用步骤

1. 拿到任意一个含 `uid` 的 JWT（可正常登录一次取后端返回的 X-DE-TOKEN），或自行构造 `{"uid":1,"oid":1,"exp":<未来时间戳>}` 的 HS256 JWT。
2. 在请求里带上 `X-DE-TOKEN: <JWT>`，长度控制在 100 以内，访问后台接口。
3. `TokenFilter` 校验长度与 uid 后放行进入 `CommunityTokenFilter`；其校验异常被 catch 吞掉，继续 `doFilter` 放行。
4. 未授权访问后台功能（数据源添加/测试连接等），继续利用 H2 JDBC RCE（见关联卡）。

## PoC

```http
POST /de2api/datasource/getSchema HTTP/1.1
Host: <target>:8100
Content-Type: application/json
X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoxNzUwMjUwNjI3fQ.<sig>

{"id":"","name":"test","type":"h2", ...}
```

```text
# JWT 载荷（长度 <100，含 uid）
{"typ":"JWT","alg":"HS256"}.{"uid":1,"oid":1,"exp":<未来时间戳>}.<任意签名>
```

说明：结构复现的通用请求，token/接口按目标调整；不访问、不执行。

## 变体与关联

- 变体：同类"filter catch 未 return / 校验失败继续 doFilter"的 fail-open 认证缺陷在其它 Java Web 应用中普遍存在；也可借 `linkToken` 等前置分支进入下一个 filter。
- 变体：JWT 侧可尝试 `alg:none`、弱密钥伪造、uid 越权（uid=1 常为管理员）；配合 `X-Forwarded-For`/`X-Remote-Addr` 等头伪造来源 IP 绕过基于 IP 的限制。
- 关联：[[web-java-component-dataease-json-driver-override-jdbc-rce]]（DataEase JDBC RCE）；[[web-java-component-h2-jdbc-url-filter-bypass-runscript]]（后续 H2 JDBC URL 绕过 RCE）；[[web-generic-auth-jersey-getpath-isbasefile-semicolon-dot-jwt-bypass]]（其它 JWT/路径鉴权绕过）。

## 检测与防御

- 检测：代码审计定位 Filter 的 `catch` 块未中断仍调用 `filterChain.doFilter`；日志中大量 `X-DE-TOKEN` 校验失败却成功访问后台接口的请求；未登录会话访问 `/de2api/*` 管理接口。
- 检测：异常频率突增的 token 解析错误伴随 200 响应。
- 防御：认证失败必须**立即终止**（return / 发送 401 / 抛异常），禁止 fail-open；catch 中不得继续 filter 链。
- 防御：升级到 v2.10.10+；JWT 强制校验签名、过期、会话绑定与用户状态，uid 不可仅凭声明信任；后台接口加独立的鉴权/授权注解与来源校验。
