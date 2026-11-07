---
id: web-python-deserialization-bottle-signed-cookie-pickle-rce
title: Bottle 签名 Cookie 的 secret 泄露导致 Pickle 反序列化 RCE
type: scenario
domain: web
path: web/python/deserialization
technique: bottle-signed-cookie-secret-pickle-rce
tags:
- python
- bottle
- pickle
- deserialization
- signed-cookie
- hardcoded-secret
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:20:13+08:00'
  notes: 已对照原文核对：Bottle request.get_cookie(secret=...) 验签后 Pickle 反序列化、SECRET_KEY=h3ckTheworld123 硬编码、__reduce__ 构造与 response.set_cookie 生成签名 Cookie 均一致；原文为 CTF 环境无组件版本；未实际运行 PoC。
url: /docs/web/python/deserialization/web-python-deserialization-bottle-signed-cookie-pickle-rce/
draft: false
kb_aliases:
- pttole
- Bottle get_cookie
- request.get_cookie secret
- 签名 Cookie pickle
- Bottle 反序列化
- SECRET_KEY 泄露
---

## 一句话结论

Bottle 的 `request.get_cookie(name, secret=...)` 在带 `secret` 时会校验 Cookie 签名并对其内容做 Pickle 反序列化；若应用的 `SECRET_KEY` 硬编码在源码/配置中并泄露，攻击者可用该 secret 自行签名一个包含恶意 `__reduce__` 对象的 Cookie，服务端读取时触发 `pickle.loads` 执行任意命令。

## 原理

- **Bottle 的签名 Cookie**：`request.get_cookie(key, secret=...)` 用 secret 对 Cookie 值做 HMAC 校验，校验通过后调用内部反序列化逻辑还原对象。Bottle 默认使用 Pickle 作为 Cookie 序列化器，因此 Cookie 内容本质上是可执行的反序列化数据。
- **secret 即信任边界**：签名只保证“Cookie 未被篡改”，前提是 secret 保密。若源码/配置/镜像中硬编码 `SECRET_KEY`（本题为 `h3ckTheworld123`），攻击者就拥有与服务端相同的签名能力。
- **恶意对象构造**：Python 的 `pickle` 在反序列化时会调用对象 `__reduce__` 返回的可调用对象。定义 `class cmd: def __reduce__(self): return (exec, ("__import__('os').popen('...').read()",))`，Pickle 流中会记录 `exec` 与该字符串；`pickle.loads` 时执行命令。
- **生成合法 Cookie**：直接用 Bottle 的 `response.set_cookie("name", c, secret="<泄露的 secret>")` 让框架生成带签名的 Cookie，避免手工实现签名格式；把该 Cookie 发给目标即可。
- 之所以成立：签名算法与序列化器都是公开的，唯一秘密是 secret；secret 泄露后，攻击者可以伪造任意对象，而反序列化 sink 没有类白名单/安全反序列化限制。

## 触发条件

- 目标使用 Bottle 框架，并在 `request.get_cookie()` 中传入 `secret` 参数（启用签名 Cookie）。
- `SECRET_KEY` 硬编码在源码、配置文件、镜像层、备份或错误信息中，且未定期轮换。
- 服务端对 Cookie 内容使用 Pickle 反序列化，未使用 `RestrictedUnpickler`/白名单/JSON 替代。
- 攻击者能向目标发送自定义 Cookie，并知道 Cookie 名称（如 `name`、`session`）。

## 利用步骤

1. 审计源码/附件，确认使用 Bottle 且存在 `request.get_cookie(..., secret=...)`，提取 `SECRET_KEY`。
2. 在本地安装同版本 Bottle，定义带 `__reduce__` 的恶意类，命令执行结果写入可回显位置（文件、HTTP 请求、DNS 等）。
3. 用 `response.set_cookie(cookie_name, payload, secret=SECRET_KEY)` 生成签名 Cookie，打印 `response._cookies` 或 `Set-Cookie` 头。
4. 把生成的 `Cookie: <name>=<value>` 发送到目标触发 `get_cookie` 的页面/接口。
5. 服务端校验签名通过后 `pickle.loads`，执行命令；从回显/带外通道确认结果。

## PoC

```python
from bottle import response

class cmd:
    def __reduce__(self):
        return (exec, ("__import__('os').popen('cat /f*>login').read()",))

c = cmd()
response.set_cookie("name", c, secret="h3ckTheworld123")
print(response._cookies)
```

```http
GET / HTTP/1.1
Host: target
Cookie: name=<response.set_cookie 生成的签名值>
```

```text
# 服务端 request.get_cookie("name", secret="h3ckTheworld123")
# -> 验签通过 -> pickle.loads -> __reduce__ -> exec(...)
```

## 变体与关联

- secret 来源变体：源码硬编码、`.env`/配置泄露、Docker 镜像层、Git 历史、错误页/调试信息；secret 弱可爆破时也可离线猜解。
- 序列化器变体：Bottle 可配置 JSON/其他序列化器；只有使用 Pickle 时才能直接 RCE，JSON 序列化器通常只能做数据伪造。
- 触发点变体：除 `get_cookie` 外，任何把签名 Cookie 交给 `pickle.loads` 的逻辑都适用；Flask/Django 的签名 Cookie 若使用 Pickle 也有类似风险。
- 关联：[[web-python-deserialization-pickle-codetype-function-hijack]]（Pickle `__reduce__` 函数劫持）、[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（受限 Unpickler 绕过）、[[web-generic-auth-unsigned-cookie-admin-keys]]（未签名 Cookie 伪造）。

## 检测与防御

- 检测：Cookie 值中出现 Pickle 魔术字节（`\x80\x04`、`\x80\x05`）或 base64 解码后出现 `c__builtin__`/`os`/`exec` 等特征；同一 secret 签名的异常 Cookie；`get_cookie` 触发后出现异常进程/文件写入。
- 防御：不要把 `SECRET_KEY` 硬编码在源码/镜像中，使用密钥管理服务并定期轮换；签名 Cookie 使用 JSON 序列化器或 `RestrictedUnpickler` 白名单；对 Cookie 内容做结构校验，禁止反序列化任意对象。
- 加固：Cookie 设置 `HttpOnly`/`Secure`/`SameSite`；限制 Cookie 大小与字段；监控异常 Cookie 与反序列化错误。
