---
id: tools-burp-autodecoder-flask-custom-encrypt-decrypt-script
title: autoDecoder 自定义加解密脚本：Flask /encode /decode 接口、bytes/str 与 Base64 编码、PKCS 填充及 JSON 字段处理
type: scenario
domain: tools
path: tools/burp
technique: autodecoder-flask-custom-encrypt-decrypt-script
aliases:
- autoDecoder 脚本编写
- autoDecoder 接口加解密
- Flask encode decode
- Burp 自动加解密脚本
- autoDecoder 调试
- dataBody dataHeaders
tags:
- burp
- autodecoder
- flask
- python
- encryption
- decryption
- tooling
- api-testing
- base64
- padding
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V265
  verified_at: '2026-11-07T18:49:16+08:00'
  notes: 重试核验：已对照 content.md 与 21 张图核对；autoDecoder 官方流程图（图01-03）、数据类型流程（图04）、常见算法 key/iv/填充表（图05/06）、bytes/str encode-decode（图07）、b64encode/encodebytes 换行差异（图08/09）、Flask /encode /decode + dataBody/dataHeaders/requestorresponse 与 headers+四段CRLF 格式（图10/11/15-17）、DES/CBC/PKCS5 示例脚本与 Python 3.9.7（图13/14）、代理模块与保存配置（图12/18-21）均一致；卡片 PoC 为缩略整理、pyDes 与 pycryptodome 填充差异表述正确；未实际运行
---

## 一句话结论

用 Flask 写一个本地服务，暴露 `/encode` 与 `/decode` 两个 POST 接口，在 Burp 的 autoDecoder 插件“接口加解密”里分别填入加密/解密 URL，就能把目标站点的加密请求体自动解成明文供 Repeater/Intruder 修改，改完再自动加密发回；脚本能否跑通的关键不在算法本身，而在 bytes/str 边界、Base64 变体与 PKCS 填充是否处理正确，以及请求/响应是否需要只处理 JSON 中的某个字段。

## 原理

- **autoDecoder 的处理流**：插件在 Burp 发送请求前把密文 body 交给用户配置的解密接口，得到明文展示/编辑；发送时把编辑后的明文交给加密接口，得到密文再发出。只查看不解包时只需要解密接口；要改包重放则需要同时实现加密接口。响应包同样可配置为经解密接口转成明文。
- **Flask 接口约定**：脚本通过 `request.form.get('dataBody')` 取 body、`request.form.get('dataHeaders')` 取 headers、`request.form.get('requestorresponse')` 区分请求/响应。请求方向必须返回 `headers + "\r\n\r\n\r\n\r\n" + body`（autoDecoder 的 HTTP 包格式要求），响应方向直接返回解密/加密后的 body 字符串。
- **bytes 与 str 的边界**：Python 加解密库（pycryptodome、pyDes 等）的输入/输出是 `bytes`，而 Flask 表单和网络传输是 `str`。加密前 `text.encode()`、解密后 `plain.decode()`；Base64 编码得到 `bytes`，需要 `.decode()` 才能返回给插件。把 `str` 直接传给 C 扩展会抛 `TypeError: Object type <class 'str'> cannot be passed to C code`——这就是“一会儿 encode 一会儿 decode”的根本原因，不是写法随意。
- **Base64 变体**：`base64.b64encode()` 不插入换行，适合短数据/JSON/URL；`base64.encodebytes()` 每 76 字符插入 `\n`，适合 MIME/长文本，但解密前必须去掉换行（如 `.replace(b"\n", b"")` 或 `.strip("\n")`）。解码侧 `b64decode()` 不处理换行，遇到 `encodebytes` 产物要用 `decodebytes()` 或先去换行。
- **PKCS 填充**：pycryptodome 的 `AES.new(...).encrypt()`/`DES.new(...).encrypt()` 不会自动填充，即使算法/模式写成 PKCS5/7，也要显式 `pad(data, block_size)` 与 `unpad(data, block_size)`；AES 块 16、DES/3DES 块 8。pyDes 则是把 `padmode=PAD_PKCS5` 传给 `encrypt/decrypt`，由库内部处理填充（与 pycryptodome 的用法不同）。
- **算法参数约束**：AES key 16/24/32 字节、IV 16；DES/3DES key 8/16/24、IV 8；SM4 key/IV 16；ChaCha20 key 32、nonce 12；RC4 key 1–256 字节、无 IV、无填充；RSA 需要 key 对象并按 PKCS#1 分段。参数类型或长度不对，要么直接抛异常，要么解出乱码。
- **JSON 字段处理**：请求方向若服务端要求 `{"data":"<Base64 密文>"}` 这类包装，应在加密完成后拼 JSON 再返回；响应方向若只有 `result` 字段是密文，应先 `json.loads(text)` 取 `data["result"]`，再 Base64 解码/解密，否则会把整个 JSON 当密文解而失败。
- **调试与生效**：Flask 以 `app.run(host="0.0.0.0", port="8888")` 启动；autoDecoder 的“接口加解密”页可粘贴原始 HTTP 包，点“解密>>>”“<<<加密”验证双向转换。修改脚本后 `debug=True` 会自动重载；改目标域名/IP 后要同步改配置并点“保存配置”，否则设置不生效。

## 触发条件

- 目标请求/响应体经过前端或客户端加密（AES/DES/3DES/SM4/RC4/RSA 等），且已从 JS/客户端还原出算法、模式、key、IV、编码与填充方式。
- Burp Suite 已安装 autoDecoder 插件；本机有 Python 3（原文用 3.9.7，Python 2 问题较多）与 flask、pycryptodome/pyDes 等依赖。
- Burp 所在机器能访问 Flask 服务（同一台机用 `127.0.0.1`，跨机用内网 IP），且目标流量经过 Burp 代理。
- 目标 body 是表单/JSON 等可解析格式；若为整体二进制或自定义分隔格式，需要按实际结构调整解析。
- 仅用于授权测试；Flask 的 debug 模式不要暴露到公网。

## 利用步骤

1. 抓包确定加密字段与结构：是整体 body 一个密文，还是 JSON 中某个字段/表单中某个参数；记录算法、模式、key、IV、Base64 变体与填充方式。
2. 写 Flask 脚本：定义 `des_encrypt/des_decrypt` 或 `aes_encrypt/aes_decrypt`；确保加密前 `encode()`、解密后 `decode()`，并处理 Base64 换行。
3. 实现 `/encode`：取 `dataBody`、`dataHeaders`、`requestorresponse`，加密后按 `requestorresponse` 返回 `headers + "\r\n\r\n\r\n\r\n" + body`（请求）或仅 body（响应）。
4. 实现 `/decode`：对请求方向同样返回 headers+四段 CRLF+明文；对响应方向只返回明文。需要时先解析 JSON 取目标字段再解密。
5. 启动 Flask（如 `python3 autoDecoderTest.py`，监听 8888）；确认日志显示 `Running on http://127.0.0.1:8888`，无缺库报错；缺库按提示安装，仍报错可换 Python 3.9+。
6. 在 autoDecoder 的“接口加解密”页填写解密接口 `http://127.0.0.1:8888/decode`、加密接口 `http://127.0.0.1:8888/encode`，选择模块（Proxy/Repeater/Intruder），填写加解密域名与明文/密文关键字（作用于 body），点击“保存配置”。
7. 在调试区粘贴一条真实请求包，点“解密>>>”看是否得到明文（如 `{"id":"1"}`）；再输入明文点“<<<加密”看密文是否与原始包一致或能被服务端接受。
8. 调试通过后转到 Repeater/Intruder，直接修改明文参数发送；若服务端有签名/时间戳/防重放，需要在脚本中同步重算或改用 JSRPC 调用前端函数。
9. 换目标环境时修改 autoDecoder 配置中的域名/IP 与 Flask 脚本中的 key/iv，重新保存并抓包验证，避免“配置未保存导致不生效”。

## PoC

最小 Flask + autoDecoder 脚本结构（DES/CBC/PKCS5 示例，按原文缩略）：

```python
from flask import Flask, request
from pyDes import des, CBC, PAD_PKCS5
import base64

def des_encrypt(s):
    k = des("f0ngtest", CBC, "f0ngf0ng", pad=None, padmode=PAD_PKCS5)
    return base64.b64encode(k.encrypt(s, padmode=PAD_PKCS5)).decode()

def des_decrypt(s):
    k = des("f0ngtest", CBC, "f0ngf0ng", pad=None, padmode=PAD_PKCS5)
    return k.decrypt(base64.b64decode(s), padmode=PAD_PKCS5).decode()

app = Flask(__name__)

@app.route('/encode', methods=["POST"])
def encrypt():
    body = request.form.get('dataBody')
    headers = request.form.get('dataHeaders')
    req_or_resp = request.form.get('requestorresponse')
    enc = des_encrypt(body.strip("\n"))
    if req_or_resp == "request":
        return headers + "\r\n\r\n\r\n\r\n" + enc
    return enc

@app.route('/decode', methods=["POST"])
def decrypt():
    body = request.form.get('dataBody')
    headers = request.form.get('dataHeaders')
    req_or_resp = request.form.get('requestorresponse')
    plain = des_decrypt(body.strip("\n"))
    if req_or_resp == "request":
        return headers + "\r\n\r\n\r\n\r\n" + plain
    return plain

if __name__ == '__main__':
    app.run(host="0.0.0.0", port="8888")
```

原文验证：请求体 `I9z1fsH5QQ2NUbJi/7a8lw==` 经 `/decode` 得到 `{"id":"1"}`；明文 `{"userName":"admin","userPwd":"123456"}` 经 `/encode` 得到可被服务端接受的密文。JSON 包装场景：加密后返回 `'{"data":"' + body.decode() + '"}'`；响应场景：`json.loads(text)["result"]` 取出后再解密。

## 变体与关联

- **JSON 字段级加解密**：请求加密后包一层 `{"data": ...}`，响应只解 `result` 字段；与整体 body 加解密的脚本结构不同，需在路由内单独处理。
- **Base64 变体**：`encodebytes` 产物带换行，必须去换行再解密；跨系统传输时也可能出现 URL-safe Base64 或缺失 padding，需要 `urlsafe_b64decode` 与补齐 `=`。
- **pycryptodome vs pyDes**：pycryptodome 必须手动 `pad/unpad`；pyDes 用 `padmode=PAD_PKCS5` 自动填充。混用写法会出现 `padding is incorrect` 或块对齐错误。
- **替代插件/方案**：Burpy 通过 PyRO 调用 Python 类方法，接口形态不同；JSRPC 直接调用浏览器前端加密函数，适合 key 动态或算法难还原；mitmproxy 透明加解密适合上下游代理链。
- **关联**：[[tools-burp-burpy-pyro-python-auto-encrypt-decrypt]]（另一插件 Burpy 的 Python 自动加解密）、[[web-generic-auth-frontend-js-random-key-fixation-autodecoder]]（autoDecoder 固定前端随机密钥的实战）、[[web-generic-auth-js-signature-jsrpc-autodecoder]]（JSRPC + autoDecoder 动态代签）、[[tools-burp-js-hook-bridge-traffic-encrypt-decrypt]]（JS Hook + 本地 Bridge 不还原算法直接加解密）、[[code-analysis-reverse-obfuscation-mcp-skill-jsrpc-autodecoder-automation]]（AI 生成 Flask/autoDecoder 工件）。

## 检测与防御

- **检测**：同一账号短时间大量请求、参数长度/结构突变、密文重复或规律性变化；若前端密钥被固定或脚本被复用，密文模式可能与正常客户端不同；服务端可对请求签名、时间戳、nonce 做一致性校验。
- **防御**：不要把客户端加密当作安全边界；关键参数在服务端做二次校验与权限判断；使用服务端下发短期密钥、防重放 nonce、请求签名与设备指纹；对异常重放、批量枚举与参数篡改做风控。
- **测试注意**：Flask 服务只监听内网/本机，测试结束关闭；脚本中不要硬编码生产密钥并提交到公开仓库；autoDecoder 配置需点“保存配置”后才生效，换环境后重新验证。
