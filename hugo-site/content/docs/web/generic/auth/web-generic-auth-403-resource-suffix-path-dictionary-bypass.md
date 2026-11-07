---
id: web-generic-auth-403-resource-suffix-path-dictionary-bypass
title: 403/401 接口字典化绕过：静态资源后缀、分号与编码路径穿越
type: scenario
domain: web
path: web/generic/auth
technique: 403-resource-suffix-path-dictionary-bypass
tags:
- web
- auth
- access-control
- bypass
- 403
- waf
- path-traversal
- burp
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:37:04+08:00'
  notes: 已对照原文与图17/21/22核对：OneScan URL403bypass字典含?a.css/.js/.jpg/.png、../admin、..%2f，递归目录逐层拼接，BypassPro对403/301/404/302自动重发；卡中分号/编码/Header变体为通用扩展，案例200响应长度相同，卡已注明需二次确认；无CVE、无sources/source_url；未对真实目标发送请求。
url: /docs/web/generic/auth/web-generic-auth-403-resource-suffix-path-dictionary-bypass/
draft: false
kb_aliases:
- 403 bypass 字典
- ?a.css 绕过
- 静态资源后缀绕过
- ..%2f 403 绕过
- OneScan URL403bypass
- BypassPro 自动绕过
---

## 一句话结论

当受保护接口返回 403/401 时，可以对同一路径追加静态资源后缀（`?a.css`、`?a.js`、`?a.jpg`、`?a.png`）、分号参数（`;a.css`）或编码路径穿越（`../admin`、`..%2f`），利用 WAF/访问控制规则“放行静态资源”或“按原始路径前缀判断”的差异，让后端仍路由到原接口；案例用 OneScan 自定义字典在目录的 1/2/3 层批量注入这些变体，并用 BypassPro 对 403/301/404/302 自动重试。

## 原理

- **静态资源白名单差异**：很多 WAF、Nginx `location` 或应用过滤器会对 `*.css/*.js/*.jpg/*.png` 放行，或对“看起来像静态资源”的 URL 降低拦截等级。把 `?a.css` 作为查询串、或 `;a.css` 作为路径参数附加到受保护 URL 后，WAF 可能按后缀放行，而后端路由/参数解析仍指向原接口。
- **路径规范化差异**：`/admin/../admin/secret`、`/public/..%2fadmin` 这类路径在 WAF 看来位于允许目录下，但后端/容器在路由前会做 `..`、`%2f` 解码与规范化，最终命中 `/admin/secret`。这与“前缀判断鉴权 + 容器规范化”的绕过同源。
- **参数层级放大**：递归目录扫描器会在每一级目录（1/2/3 层）都拼接字典，因此同一个 payload 会以 `/a/?x.css`、`/a/b/?x.css`、`/a/b/c/?x.css` 等形式出现，覆盖不同路由深度。
- **自动化**：BypassPro 监听代理流量中的 403/401/301/404/302，自动对原请求套用 bypass 变体并重放；OneScan 用自定义字典在扫描阶段直接生成变体请求。
- **判定不能只看状态码**：`200` 可能是软 404、首页或 WAF 的“正常页面”；必须比较响应长度/哈希、是否包含受保护数据、是否执行了敏感操作，才能确认绕过成功。案例截图中大量 200 且长度相同，需进一步核对内容。

## 触发条件

- 目标接口对未授权访问返回 403/401，且存在 WAF/反向代理/框架级路径或后缀白名单。
- 后端路由会忽略未知查询参数/路径参数，或会对 `..`、`%2f` 做规范化。
- 鉴权基于原始 URI 前缀、文件扩展名或静态资源规则，而非规范化后的路由。
- 有 Burp/OneScan/BypassPro 等工具可批量发送变体并比较响应。

## 利用步骤

1. **基线**：直接请求受保护 URL，记录状态码、响应长度、body 哈希、WAF 页面特征；确认是 403/401 而非 404。
2. **准备字典**：至少包含 `?a.css`、`?a.js`、`?a.jpg`、`?a.png`、`;a.css`、`;.css`、`../admin`、`..%2f`、`%2e%2e%2f`、双写编码等；按目标技术栈补充 `%00`、尾点、尾空格、大小写。
3. **批量注入**：用 OneScan 自定义字典在 1/2/3 层目录批量拼接；或 Burp Intruder 对路径/查询串逐项替换；BypassPro 可对代理中出现的 403/301/404/302 自动重试。
4. **结果比对**：按状态码、长度、body 相似度分组；对 200 响应检查是否包含敏感字段/功能，必要时用唯一 canary（如创建一条测试数据）确认操作确实执行。
5. **扩展 header 变体**：测试 `X-Original-URL`、`X-Rewrite-URL`、`X-Forwarded-Prefix`、`X-Forwarded-For` 等；部分框架/网关会按这些头重写路径或来源。
6. **记录与收敛**：保存成功请求的原始报文、响应差异与时间；避免对生产数据做破坏性操作。

## PoC

```http
# 基线：403
GET /admin/secret HTTP/1.1
Host: target

# 静态资源后缀
GET /admin/secret?a.css HTTP/1.1
GET /admin/secret?a.js HTTP/1.1
GET /admin/secret?a.jpg HTTP/1.1
GET /admin/secret?a.png HTTP/1.1

# 分号路径参数
GET /admin/secret;.css HTTP/1.1

# 编码路径穿越
GET /public/../admin/secret HTTP/1.1
GET /public/..%2fadmin%2fsecret HTTP/1.1
GET /public/%2e%2e%2fadmin%2fsecret HTTP/1.1
```

```bash
# 用 ffuf 批量跑后缀字典（仅授权目标）
ffuf -u 'https://target/admin/secret?FUZZ' -w suffixes.txt -mc 200,204,302 -fs 0
```

字典示例：

```text
a.css
a.js
a.jpg
a.png
;.css
../admin
..%2f
%2e%2e%2f
```

本卡不针对真实目标执行；案例中的 200 响应需结合响应内容二次确认。

## 变体与关联

- 后缀可换成 `.ico`、`.woff`、`.map`、`.json`、`.txt`；也可用 `%3f`、`%23`、`;`、`//` 等分隔符。
- 路径穿越可与大小写、双重编码、Unicode 编码、尾点/空格组合；不同容器（Tomcat、Nginx、IIS、Spring）规范化顺序不同。
- Header 变体：`X-Original-URL`/`X-Rewrite-URL` 在部分框架中可直接重写路径；`X-Forwarded-Prefix` 影响 base path。
- 关联：[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]（前缀判断 + 路径规范化绕过）、[[pentest-recon-error-driven-api-param-discovery]]（参数发现）、[[web-generic-auth-swagger-unauth-user-management]]（未授权接口）。
- 边界：若后端对规范化后的完整路径做统一鉴权、或 WAF 对后缀与路径同时校验，字典绕过会失败；200 也可能是软 404，必须以敏感数据/操作结果为准。

## 检测与防御

- 鉴权应在规范化后的路由上做，统一使用框架解析后的路径，不要用原始 URI 做 `startsWith/endsWith/contains`。
- 禁止按文件后缀做白名单放行；静态资源与动态接口分域/分端口，WAF 规则不要只匹配后缀。
- 规范化 `..`、`%2f`、`;`、重复斜杠、尾点/空格；拒绝包含多种编码的异常路径。
- 监控同一会话对同一路径的 403 后紧跟 200、异常后缀查询串、`..%2f` 等特征；对 BypassPro/OneScan 的批量请求做速率限制与告警。
- 对敏感接口增加二次鉴权（角色/对象级权限），即使路径绕过也不应直接返回数据。
