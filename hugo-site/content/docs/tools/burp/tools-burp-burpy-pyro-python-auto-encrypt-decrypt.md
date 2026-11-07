---
id: tools-burp-burpy-pyro-python-auto-encrypt-decrypt
title: Burpy：Burp 经 PyRO 调用 Python 脚本自动加解密请求/响应（Burpy 类接口与三个常见报错）
type: scenario
domain: tools
path: tools/burp
technique: burpy-pyro-python-auto-encrypt-decrypt
tags:
- burp
- burpy
- python
- pyro
- encryption
- decryption
- tooling
- api-testing
- aes
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V241
  verified_at: '2026-11-07T13:11:06+08:00'
  notes: 已对照原文与15张图核对；Burpy 接口、pyro4/pyro5、19999 端口与三个报错均一致；首脚本 key 与整包解密导致块对齐报错的因果未独立复现。
url: /docs/tools/burp/tools-burp-burpy-pyro-python-auto-encrypt-decrypt/
draft: false
kb_aliases:
- Burpy 插件
- Burpy 使用攻略
- Burp Python 加解密插件
- PyRO pyro5
- Burp 自动 Enc/Dec
- 加密请求解密
- Burpy 报错排查
---

## 一句话结论

Burpy 是 Burp Suite 的 Python 桥接插件：Burp 通过 PyRO（Python 3 用 `pyro5`、Python 2 用 `pyro4`）调用本地 Python 脚本，脚本只需实现 `Burpy` 类的 `main/encrypt/decrypt/processor` 方法；开启 Auto Enc/Dec 后，Burp 发请求前自动调用 `encrypt(header, body)`、收到响应后自动调用 `decrypt(header, body)`，把加密接口变成可读可改的明文流量。常见失败点集中在“把整个 body 当一个密文解”“按 `k=v` 切错 body”“把 header 当字符串”三类。

## 原理

- **架构**：Burp 插件（Burpy）在本地启动/连接一个 PyRO 服务器，加载用户 Python 脚本并反射出 `Burpy` 类的方法；Burp 的上下文菜单/自动模式通过 PyRO RPC 调用这些方法，返回值替换请求/响应。Python 脚本运行在独立进程，可用标准库、`pycryptodome`、`gmssl` 等任意依赖。
- **必需接口**：
  - `class Burpy` 是必须的，插件从该类提取方法；
  - `main(header, body)`：通用处理入口；
  - `encrypt(header, body)` / `decrypt(header, body)`：Auto Enc/Dec 功能需要；Burp 在“发送请求”时调用 `encrypt`，在“收到响应”时调用 `decrypt`；
  - `processor(payload)`：启用 Processor 时用于处理 Intruder 等 payload；
  - 以 `_`/`__` 开头的方法不会出现在上下文菜单（可放内部辅助函数）。
- **数据格式**：`header` 是 dict，包含 `first_line`（如 `POST /aes_1/login.php HTTP/1.1`）等字段；`body` 是字符串（原始请求/响应体，可能仍是 URL 编码）。
- **执行流**：Burp 发送请求 → 调用脚本 `encrypt` → 脚本解析 body、还原明文/重新加密 → 返回新的 header/body → Burp 发出；收到响应 → 调用 `decrypt` → 返回明文 body 展示。若只想改请求不想动响应，可在 `decrypt` 中直接返回原 header/body；反之亦然。
- **为什么需要按字段处理**：很多登录接口不是“整个 body 一个 AES 密文”，而是每个参数值分别加密后再 URL 编码成 `username=<base64>&password=<base64>`。直接对整段 body 做 AES 解密会因长度不是块大小整数倍报 `Data must be aligned to block boundary in ECB mode`；正确做法是先按 `&`/`=` 提取目标参数值，URL 解码、Base64 解码，再 AES 解密。
- **三个高频报错**：
  1. `Data must be aligned to block boundary in ECB mode`：把整个 body 当密文；应提取单个参数值后再解密。
  2. `list index out of range`：`body.split('&')[0].split('=')[1]` 之类的假设不成立（body 为空、不是 `k=v`、或处理到了响应包）；应加 `if '=' in ...`/method 判断和异常处理。
  3. `'dict' object has no attribute 'split'`：`header` 是 dict 不是字符串；要取请求行用 `header["first_line"]`，不要 `header.split(...)`。
- **环境细节**：Python 3 装 `pyro5`，Python 2 装 `pyro4`；Burpy 配置需要填 Python 解释器路径（不是 `python` 命令）、PyRO host `127.0.0.1`、PyRO 端口（如 19999）、脚本路径；每次重启尽量换端口，避免 PyRO 旧对象注册/端口占用导致的“奇怪 bug”。

## 触发条件

- 已安装 Burp Suite 与 Burpy 插件，并有本地 Python 2/3 环境可安装 `pyro4`/`pyro5`。
- 目标请求/响应体由前端加密（AES/DES/SM4/RSA/自定义），且算法、Key/IV、编码顺序可在 JS 中还原，或可直接用 Python 复刻。
- 需要开启 Auto Enc/Dec 时，脚本必须实现 `encrypt`/`decrypt`，且能根据 `header["first_line"]` 区分请求/响应。
- 目标接口的 body 是表单/JSON 等可解析格式；若是整体加密的二进制/特殊分隔格式，需要按实际结构调整解析。
- 测试在授权范围内；脚本只处理本地流量，不要把 PyRO 端口暴露到公网。

## 利用步骤

1. 安装 Burpy：Burp → Extensions → Add，选择 Burpy 插件 jar；扩展加载成功后 Burp 出现 `Burpy` 标签页。
2. 安装 PyRO：Python 3 执行 `pip install pyro5`；Python 2 执行 `pip2 install pyro4`；确保 Burpy 配置的 Python 解释器路径就是安装了对应库的解释器。
3. 编写脚本：定义 `class Burpy`，实现 `main/encrypt/decrypt`（按需实现 `processor`）；先不要开启 Auto Enc/Dec，用上下文菜单手动调用验证。
4. 在 Burpy 标签页配置：Python binary path、Pyro host `127.0.0.1`、Pyro port（如 19999）、Burpy PY file path；点击 Start server，确认 `Pyro server started successfully` 且脚本加载无语法错误。
5. 抓一个加密登录请求：确认 body 形如 `username=<URL 编码的 Base64 密文>&password=<...>`；在脚本中提取 `username` 值 → URL 解码 → Base64 解码 → AES 解密 → 去 PKCS7 填充 → 返回明文。
6. 开启 Auto Enc/Dec（勾选 Enable Auto Enc/Dec），重新发送请求；在 Burpy 控制台观察 `print` 输出与报错，确认请求被解密、响应可读。
7. 在 Repeater 中修改明文参数后发送；若服务端要求重新加密，需要在同一脚本的 `encrypt` 中实现“明文 → 加密 → URL 编码/Base64”的反向流程，再返回给 Burp。
8. 出现报错时按三类问题排查：块对齐（是否整包解密）、索引越界（body 解析假设）、header 类型（是否误用 `split`）；必要时在脚本中打印 body/header 的实际类型与内容。
9. 使用 Processor 时可对 Intruder payload 做编码/加密；测试结束关闭 server、移除脚本，避免端口占用。

## PoC

Burpy 脚本最小结构（按原文最终可运行的 AES-ECB 示例整理）：

```python
from Crypto.Cipher import AES
import base64
import urllib.parse


def pcs7_unpad(data: bytes) -> bytes:
    padding_length = data[-1]
    return data[:-padding_length]


def decrypt_request_body_username(body: str) -> str:
    key = "secret_key111111"          # 16 字节，按目标 JS 实际 key 替换
    cipher = AES.new(key.encode(), AES.MODE_ECB)

    # 只取第一个参数的值；不要对整段 body 做 AES 解密
    username_encoded = body.split("&")[0].split("=")[1]
    url_decoded = urllib.parse.unquote(username_encoded)     # URL 解码
    encrypted = base64.b64decode(url_decoded)                # Base64 解码
    decrypted = cipher.decrypt(encrypted)
    return pcs7_unpad(decrypted).decode()


class Burpy:
    def main(self, header, body):
        return header, body

    def encrypt(self, header, body):
        # header 是 dict；取请求行必须用 header["first_line"]
        method = header["first_line"].split(" ")[0]
        if method in ("GET", "POST"):
            print("处理请求包:", header["first_line"])
            return header, decrypt_request_body_username(body)
        print("处理返回包")
        return header, body

    def decrypt(self, header, body):
        # 响应方向按需实现；不需要时原样返回
        return header, body
```

对应的加密请求示例：

```http
POST /aes_1/login.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=XfEiAnNZOPt6uIh277KQag%3D%3D&password=6I%2BRCYnCCZCxuK8BBRPHcg%3D%3D
```

解密结果（原文）：

```text
Decrypted Username: orange
```

说明：原文第一次用 key `'7777777'` 且对整段 body 解密，分别触发块对齐报错；随后用 `header.split(...)` 触发 `'dict' object has no attribute 'split'`；最终以 `header["first_line"]` + 单参数提取成功。密钥/字段名需按目标实际替换；以上 PoC 未在本机执行。

## 变体与关联

- 变体：AES-CBC/SM4/DES/RSA 只需替换 `decrypt_request_body_username` 中的算法与 Key/IV 来源；如果是整体加密的 JSON body，则先解密整个 body，再 `json.loads`。
- 变体：响应也加密时，在 `decrypt` 中按相同逻辑处理响应 body；若响应是 JSON 内的 `data` 字段密文，先解析 JSON 再解密字段。
- 变体：需要自动重签/重放时，可在 `encrypt` 中同时重算 `sign`/`timestamp`/`nonce`；Burpy 只负责调用，签名逻辑仍由 Python 脚本实现。
- 变体：`processor(payload)` 可把 Intruder 的 payload 先编码/加密；`main` 可用于非加解密的通用改写。
- 关联：[[tools-burp-encrypted-api-proxy-decrypt-resign]]（mitmproxy 上下游代理透明解密/重签）、[[tools-burp-js-hook-bridge-traffic-encrypt-decrypt]]（不还原算法，直接 hook 前端 encrypt/decrypt）、[[mobile-android-mcp-assisted-sign-reverse-autodecoder]]（Android 端 sign 逆向 + autoDecoder 自动重签）。
- 边界：Burpy 只解决“Burp 内自动调用 Python 加解密”；算法/Key 仍需自行还原；如果目标使用 mTLS/证书固定、PyRO 端口被安全软件拦截、或 body 是不可解析的二进制，需要换用其他代理/插件方案。

## 检测与防御

- 这是授权测试工具；对防守方，前端加密只是提高逆向成本，不能替代 TLS、服务端鉴权与参数校验。
- 加固：不要依赖客户端加密作为安全边界；服务端对密文解密后仍需做身份/权限/业务校验；关键接口使用服务端一次性 nonce/时间戳并绑定会话，防止解密后重放。
- 检测：本地出现 PyRO 默认端口（如 19999/9090）监听、Burp 进程加载 Burpy/调用 Python 子进程；同一账号短时间大量请求且明文参数分布异常；请求体在 URL 编码/Base64/AES 之间呈现规律变换。
- 加固（客户端）：对 JS 做混淆/完整性校验、启用 CSP 限制异常连接只能提高成本；不能阻止攻击者用本地脚本复刻算法。
