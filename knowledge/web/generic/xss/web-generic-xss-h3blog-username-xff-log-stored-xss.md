---
id: web-generic-xss-h3blog-username-xff-log-stored-xss
title: h3blog 后台存储型 XSS：注册用户昵称与 X-Forwarded-For 登录日志未编码，管理员查看用户/操作日志时触发
type: scenario
domain: web
path: web/generic/xss
technique: h3blog-stored-xss-username-xff-log
aliases:
- h3blog 存储型XSS
- 用户名 XSS
- X-Forwarded-For XSS
- 操作日志 XSS
- get_real_ip XSS
- 后台审计日志存储型XSS
tags:
- python
- flask
- h3blog
- xss
- stored-xss
- admin-panel
- x-forwarded-for
- log-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:21+08:00'
  notes: 已对照原文核对（36 图）；昵称与 XFF 日志均实测弹窗；已修正“登录失败也记录/无需正确密码”的过度表述，原文用 caigosec/123456 正常登录。
---

## 一句话结论

h3blog 有两处把用户可控输入未编码地存进后台并在管理员页面渲染：注册用户在个人中心把昵称改成 `<script>alert('Caigosec');</script>` 后，管理员打开用户管理页面即触发；未登录攻击者（持任意注册账号凭据）也可以对 `/login` 提交带 `X-Forwarded-For: <script>alert('XSS');</script>` 的请求，`get_real_ip()` 优先信任 XFF，`opt_log()` 把该 IP 原样写入操作日志，管理员查看“操作日志”时触发存储型 XSS。

## 原理

- **存储型 XSS + 管理员受害者**：昵称和登录 IP 都是攻击者可写、管理员会查看的低信任数据；后端仅做存储，前端/模板未做 HTML 转义（或使用了 `|safe`、innerHTML 等），脚本在管理员浏览器中执行。管理员会话通常有更高权限，XSS 可代替管理员发起同源请求（创建管理员、调用代码生成/导出等后台功能），形成后台接管链。
- **昵称入口**：博客系统开放注册，普通用户可在 `/account/user_info` 修改昵称；管理员在 `/admin/` 用户管理列表加载用户数据时渲染昵称，payload 直接进入 DOM，原文实测弹出 `Caigosec`。
- **XFF 入口**：`get_real_ip()` 逻辑为优先取 `X-Forwarded-For`，其次 `X-Real-IP`，最后 `request.remote_addr`；该值未经校验直接作为 `ipaddr` 写入 `OptLog`。`@admin_perm(..., admin_required=False)` 的 `/login` 不要求已有登录 session，攻击者用任意已注册账号发起登录（原文用 `caigosec`/`123456`），`opt_log` 即把 XFF 写入操作日志。
- **日志展示**：后台“操作日志”页面从数据库读取 `ipaddr` 等字段并渲染；无输出编码时脚本执行，原文实测弹出 `XSS`。
- **为什么把两者合并**：同一系统、同一类“后台展示的低信任字段未编码”问题，只是入口不同（用户资料 vs 审计日志）；修复方式一致（输出编码/输入过滤），因此作为一张存储型 XSS 场景卡记录。

## 触发条件

- h3blog 开启注册，且管理员会访问用户管理页面；或管理员会查看操作日志（审计功能默认存在）。
- 昵称/日志字段在后台模板中未做 HTML 转义，或通过 innerHTML/JS 拼接渲染。
- `/login` 可匿名访问（`@admin_perm` 的 `admin_required=False`），或攻击者已有普通账号可修改昵称。
- 管理员浏览器允许执行内联脚本（无严格 CSP、无 Trusted Types），且后台页面与 API 同源。

## 利用步骤

1. **昵称 XSS**：
   - 注册普通账号并登录；
   - 进入个人中心修改昵称，填入 `<script>alert(document.domain)</script>` 或更完整的会话利用 payload；
   - 等待/诱导管理员打开后台用户管理列表，脚本在管理员上下文执行。
2. **XFF 日志 XSS**：
   - 向 `/login` 发送登录请求（使用任意已注册账号的正常凭据，原文为 `caigosec`/`123456`），在 `X-Forwarded-For` 中填入 `<script>alert('XSS');</script>`；
   - `get_real_ip()` 取 XFF，`opt_log()` 将其写入操作日志；
   - 管理员打开后台“操作日志”页面时触发。
3. 验证：若页面弹窗/控制台执行，说明渲染点未编码；进一步可用 fetch 同源请求读取后台数据或执行后台操作（需自行评估授权）。
4. 组合链：XSS 在管理员上下文可调用后台代码生成/导出等功能；若目标同时存在代码生成注入 RCE，可把 XSS 当作进入后台的跳板。

## PoC

昵称字段：

```html
<script>alert('Caigosec');</script>
```

登录请求伪造 XFF：

```http
POST /login?next=/ HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: <script>alert('XSS');</script>

csrf_token=<valid>&username=caigosec&password=123456
```

关键代码（原文）：

```python
def get_real_ip():
    headers = request.headers
    if headers.get('X-Forwarded-For'):
        ip = headers.get('X-Forwarded-For')
    elif headers.get('X-Real-IP'):
        ip = headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip

# opt_log 中
ipaddr = ip
# OptLog(..., ipaddr=ipaddr) 入库，后台操作日志页面直接渲染
```

## 变体与关联

- 其他可写字段：用户名、邮箱、个人简介、评论、文章标题、上传文件名、User-Agent、Referer、请求 URL、`open_param`（`opt_log` 会 `json.dumps(request.values)`，若后台展示请求参数也可能注入）。
- 其他头：`X-Real-IP`、`Forwarded`、`X-Client-IP` 等被日志/审计组件信任的头。
- 与后台 RCE 的组合：XSS 取得管理员上下文后调用代码生成/导出功能，可衔接 [[web-python-framework-h3blog-gencode-field-code-injection-rce]]。
- 关联 [[web-generic-auth-login-rate-limit-bypass-cookie-xff]]（XFF 被信任导致限速绕过，同一根因：无条件信任代理头）。
- 关联 [[web-python-framework-h3blog-download-path-traversal-file-read-delete]]（同系统未授权文件读取，可读取配置/密钥）。

## 检测与防御

- 对所有后台渲染的用户可控字段做上下文相关输出编码；Jinja2 默认自动转义，检查是否使用了 `|safe`、`Markup`、`innerHTML`、字符串拼接。
- 昵称等资料字段做输入校验/长度限制，禁止 `<`、`>`、引号等 HTML 元字符；但根本修复是输出编码。
- 不要信任 `X-Forwarded-For`/`X-Real-IP`：仅在明确配置的可信代理后取值，校验 IP 格式（`ipaddress.ip_address`），非法值记录为 unknown；日志展示时统一转义。
- 部署 CSP（禁止 inline script、限制 script-src），设置 HttpOnly/Secure/SameSite Cookie；敏感后台操作加 CSRF token 与二次确认。
- 监控昵称、日志等字段中出现 `<script`、`onerror`、`javascript:` 等特征；对管理员页面的异常请求与后台操作做审计。
