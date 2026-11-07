---
id: web-generic-auth-proxy-history-unauth-user-all-leak
title: 代理历史响应长度异常定位未鉴权 user/all 接口：全站手机号与密码哈希泄露
type: scenario
domain: web
path: web/generic/auth
technique: proxy-history-unauth-user-list-discovery
tags:
- web
- auth
- access-control
- unauthorized
- data-exposure
- burp
- recon
- pii
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V73
  verified_at: '2026-11-05T16:40:07+08:00'
  notes: 已对照原文核对：图08 GET /user/all 响应含 users 数组与 id/role_id/is_inner/platform_id/name/mobile/email/password/encrypt/type/credit_score/status/auditor_id/id_card/note，响应长度异常；图22 Burp 历史按颜色高亮敏感响应。卡内正确指出截图请求带 Bearer/Cookie，需去掉凭据重放才能确认未授权，并引用原文最终'user/all 不需登录'的结论；字段与截图一致。未验证点：未复跑；原文无系统名/版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-proxy-history-unauth-user-all-leak/
draft: false
kb_aliases:
- user/all 未授权
- 响应长度异常
- Burp 历史数据包
- 全站用户泄露
- 未授权用户列表
- HaE 爆红
---

## 一句话结论

注册一个普通账号并遍历功能点时，很多管理接口会 401，但把 Burp 历史数据包按响应长度排序/翻看，常能发现像 `GET /user/all` 这样本应受保护、实际没有鉴权的接口；它直接返回全站用户对象（id、手机号、邮箱、password hash、身份证号、角色等），手机号即登录名，为后续任意密码登录、密码喷洒与越权提供完整输入。

## 原理

- 前端路由与后端接口鉴权常常不是同一套控制：页面跳转前有 401 拦截，不代表每个 XHR/API 都经过鉴权中间件。开发时为了“先跑通功能”，某些列表接口可能被加入白名单、漏配拦截器，或只在前端隐藏入口。
- 代理历史（Burp HTTP history）保留了浏览器在点击各功能点时发出的全部请求；按响应长度排序或观察异常大的 200 响应，可以快速筛出返回大量数据的接口。文章在遍历功能点、大量 401 之后，回头翻历史包发现 `user/all` 的响应长度明显异常。
- `user/all` 返回的是后端用户表对象，包含 `id`、`role_id`、`is_inner`、`platform_id`、`name`、`mobile`、`email`、`password`（哈希）、`encrypt`、`type`、`credit_score`、`status`、`auditor_id`、`id_card` 等字段。手机号就是登录账号；密码哈希可尝试离线爆破（文章用 cmd5 未成功），即使破解失败，手机号本身已足够做定向弱口令尝试与任意密码登录验证。
- 鉴权缺失的判定不能只看“带 token 的请求成功了”，还要把同一请求去掉 Cookie/Authorization 重放；若仍返回 200 和数据，才是真正未授权。文章最终确认 `user/all` 不需要登录即可访问，比“登录后越权”更严重。
- 泄露的手机号与密码哈希可直接支撑：账号枚举、弱口令/密码喷洒、任意密码登录（若登录校验缺失）、社工钓鱼、身份证号等 PII 滥用。

## 触发条件

- 目标系统有注册功能或攻击者已有普通账号，能够进入系统并触发前端各功能点。
- 浏览器/代理（Burp、HaE 等）记录完整历史流量；后端存在未纳入鉴权中间件的用户列表路由。
- `user/all`（或同类 `/user/list`、`/api/user/all`）路由可达，返回用户数组且未校验会话。
- 响应中包含手机号、邮箱、密码哈希、身份证号等敏感字段；数据量足以造成全站泄露。

## 利用步骤

1. 注册普通账号（文章注册职工账号成功），登录后逐个点击功能点，保持 Burp 代理开启，让每个 XHR 进入 HTTP history。
2. 管理功能大量返回 401 时不要直接放弃；回到 Burp 历史，按响应长度排序，或使用 HaE 等插件对响应中的手机号/身份证/密码等正则高亮，寻找异常大的 200 JSON 响应。
3. 定位 `GET /user/all`（或类似用户列表路由），查看响应体是否包含用户数组与敏感字段。
4. 去掉请求中的 Cookie/Authorization，在浏览器或 Repeater 中重放；若仍返回 200 与用户数据，确认未授权访问。
5. 解析 JSON，提取 `mobile`、`name`、`password`、`id_card`、`role_id` 等；手机号作为登录名，密码哈希尝试 cmd5/hashcat 离线破解。
6. 用手机号列表做弱口令/任意密码登录测试（注意账号锁定与频率），或结合登录框缺陷直接接管管理员账号。
7. 若接口支持分页/搜索参数，确认是否能拉取全量数据；记录请求响应作为证据并评估 PII 影响。

## PoC

```http
GET /user/all HTTP/1.1
Host: <target>
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0
```

```text
# 去掉 Cookie / Authorization 后仍返回 200，响应示例（字段来自文章截图）
{
  "code": 0,
  "data": {
    "users": [
      {
        "id": 1,
        "role_id": 17,
        "is_inner": 1,
        "platform_id": 3,
        "name": "<姓名>",
        "mobile": "<手机号>",
        "email": "",
        "password": "<密码哈希>",
        "encrypt": "...",
        "type": 1,
        "credit_score": 100,
        "status": 1,
        "auditor_id": 0,
        "id_card": "",
        "note": ""
      }
    ]
  }
}
```

```text
# 发现方法
1) 登录后遍历功能点，开启 Burp 代理
2) HTTP history 按 Length 排序，找响应体异常大的 200 JSON
3) 对候选请求去掉 Cookie/Authorization 重放，确认未授权
4) HaE 正则高亮 mobile/password/id_card，快速筛敏感响应
```

## 变体与关联

- 变体：路由名可能为 `/user/list`、`/api/user/all`、`/sys/user/list`、GraphQL `users` 查询；可对常见用户列表路径做字典探测。
- 变体：接口需要登录但只校验“任意有效 token”而不校验角色，普通账号即可拉全量用户；与完全未授权不同，但同样造成全站泄露。
- 变体：返回字段经过脱敏（手机号打码、密码为空）时，价值下降；可继续找导出、详情、审核等接口获取完整字段。
- 边界：若去掉凭据后返回 401/403，则只是登录后越权，需结合普通账号的权限矩阵测试；若响应被 WAF 拦截，需换路径/方法/编码。
- 关联：[[web-generic-auth-login-phone-any-password]]（用泄露手机号 + 任意密码登录）、[[web-generic-auth-type-dispatch-unauth-data-exposure]]（未授权接口返回全量用户表）、[[web-generic-auth-xiaozhi-public-paths-user-prefix-unauth-data-exposure]]（白名单前缀导致用户接口未授权）、[[web-generic-auth-authenticated-change-password-idor]]（拿到账号后的越权改密）。

## 检测与防御

- 检测（测试方）：Burp 历史按响应长度/内容类型筛选；HaE 正则高亮手机号、身份证、password 字段；对候选接口做“带凭据/不带凭据”双请求对照。
- 检测（防御方）：对所有返回用户数据的路由做统一鉴权与角色校验；审计拦截器/白名单，避免 `/user/` 前缀整体放行；对异常大的用户列表响应与未登录访问做告警。
- 修复：`user/all` 等管理接口强制登录 + 管理员角色校验；响应字段最小化，永不返回 password hash、id_card 等敏感字段；分页与导出接口同样鉴权。
- 加固：集中式授权中间件（默认拒绝）、接口清单与定期越权测试；对 PII 字段加密/脱敏；监控同一账号/来源的批量用户查询。
