---
id: mobile-android-mcp-assisted-sign-reverse-autodecoder
title: MCP 辅助 Android App 验签逆向：ida-pro-mcp 还原排序拼接 + hooker 取 AES key + Flask autoDecoder 自动重签
type: scenario
domain: mobile
path: mobile/android
technique: mcp-assisted-app-sign-reverse-autodecoder
tags:
- android
- mcp
- ida-pro-mcp
- frida
- hooker
- signature-bypass
- md5
- autodecoder
- burp
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T13:39:19+08:00'
  notes: 已对照原文及图01-17核对：hooker 抓到 MessageDigest.update 明文与 digest=Sign、Cipher.init AES/CBC/PKCS5 key/iv、ida-pro-mcp 定位 BaseWohomeEncryptRequest.getJsonStr StringBuilder 拼接并按字母排序、Flask /encode 重算 Sign + autoDecoder 配置均与截图一致；原文明确请求体自动加解密未完成，卡内已作为边界记录；密钥打码未复跑
url: /docs/mobile/android/mobile-android-mcp-assisted-sign-reverse-autodecoder/
draft: false
kb_aliases:
- MCP 绕过验签
- App 验签自动化
- ida-pro-mcp 签名逆向
- hooker 取 AES key
- Flask autoDecoder 重签
- Sign=MD5(排序参数)
- clientSecret 验签
---

## 一句话结论

当 Android App 的请求头 `Sign` 由客户端用硬编码 `clientSecret` 对“排序后的请求头/请求体参数”做 MD5 生成时，可用 hooker 观察 `MessageDigest.update/digest` 拿到签名明文与算法、用 hooker 观察 `Cipher.init` 拿到 AES key/iv、用 ida-pro-mcp 分析混淆后的拼接顺序，最后写一个 Flask `/encode` 服务配合 Burp autoDecoder 在每次改包时自动重算 Sign，实现全自动化绕过验签。

## 原理

- **签名结构**：目标请求头包含 `Method`（接口/类名）、`Time`（毫秒时间戳）、`Sign`、`Version`、`Client-Type`（如 android）；请求体中有 `mobile` 等字段（部分接口对其做 AES/CBC/PKCS5 + Base64）。
- **签名明文**：hook `MessageDigest.update` 可看到类似
  `clientSecret=<固定值>&clientType=<手机型号>&method=<接口名>&mobile=<请求体中的值>&requestUri=<路径去掉/vuc>&time=<时间戳>&version=<版本>`
  的字符串；`MessageDigest.digest` 的输出与请求头 `Sign` 一致，确认 `Sign = MD5(该字符串)`。
- **参数顺序**：不同接口的 JSON 字段顺序与拼接顺序不一致，直接按 JSON 顺序拼接会算错。作者用 ida-pro-mcp 对混淆后的 APK 执行 `find_regex`/`list_funcs`/`disasm`，定位 `BaseWohomeEncryptRequest.getJsonStr` 中的 `StringBuilder.append` 序列，确认参数按**字母排序**拼接；不同接口只改变参与拼接的键值，排序规则不变。
- **AES key/iv**：hook `Cipher.init(String, Key, AlgorithmParameterSpec)` 可看到 `AES/CBC/PKCS5Padding` 的 Key/IV（Utf8/Hex/Base64 三种视图）；作者用 AI 脚本验证 key 正确，说明客户端密钥硬编码、可离线复用。最终自动化只重算 Sign，因为很多接口的 body 本身就是明文，加密字段可作为不透明字符串参与签名。
- **重签服务**：Burp autoDecoder 把每个请求的 `dataHeaders` 与 `dataBody` POST 给 Flask `/encode`；Flask 解析第一行请求行拿 path、从 headers 取 `Method`/`Time`/`Version`/`Client-Type`、从 body 取其他参数，补上 `clientSecret` 与 `clientType`，按字母排序拼 `k=v&`，MD5 后替换 `Sign` 头，返回 `headers + "\r\n\r\n\r\n\r\n" + body`；`/decode` 原样返回。autoDecoder 在 Repeater/Intruder/Proxy 等模块打开后，改任何参数都会自动带上合法签名。
- **为什么能绕过**：签名密钥与算法完全在客户端，服务端只校验 Sign 与请求内容一致，没有一次性 nonce、设备绑定或服务端密钥；攻击者取得 `clientSecret` 后可对任意修改后的请求离线重签。
- **MCP 的价值**：混淆后的 APK 人工找拼接逻辑耗时；把 IDA 的函数/字符串/反汇编能力通过 ida-pro-mcp 暴露给 AI，分步提问（先找 MD5 函数，再找 StringBuilder 拼接，再确认排序），可在不写代码的情况下定位算法。提示词应拆成小任务，避免上下文超限。

## 触发条件

- Android App 请求带自定义 `Sign`/`signature` 头，服务端对 body/headers 做完整性校验；直接改包返回签名错误。
- 签名算法为 MD5/SHA/HMAC 等可离线复刻的哈希，密钥（clientSecret）或固定串在客户端可提取；参数顺序可确定。
- 能抓包并修改请求（Burp + 代理/证书；App 未启用不可绕过的 SSL Pinning 或已绕过）。
- 能 hook App（Frida/hooker，需 root/可调试包）或能静态分析 APK（jadx/IDA）；有 Burp autoDecoder 环境。
- 服务端无一次性 nonce、时间窗过严、设备绑定或频控；否则需同步更新 Time/Nonce 或降低自动化程度。

## 利用步骤

1. 抓一个发验证码/登录请求，记录 `Method`、`Time`、`Sign`、`Version`、`Client-Type` 与 body；改 body 确认服务端验签。
2. 用 hooker（Frida 脚本集）hook `MessageDigest.update`/`digest`，抓取签名明文与 MD5 结果；确认 `Sign = MD5(plaintext)`。
3. hook `Cipher.init`，记录 AES Key/IV 的 Utf8/Hex/Base64；用脚本解密 `mobile` 等字段验证密钥正确。
4. 若明文拼接顺序不清晰，用 ida-pro-mcp 对 APK/SO 执行 `find_regex`、`list_funcs`、`disasm`，定位 `getJsonStr`/`StringBuilder.append` 序列，确认按字母排序及 `requestUri` 去前缀规则。
5. 本地用 Python 复算：参数 dict 加入 `clientSecret`、`clientType`、`method`、`requestUri`、`time`、`version` 及 body 字段，`sorted(keys)` 后拼 `k=v&`，MD5 与抓包 Sign 对比。
6. 写 Flask `/encode`（重算并替换 Sign）与 `/decode`（原样返回），启动在 `127.0.0.1:8888`。
7. Burp 安装 autoDecoder，解密/加密接口填 `http://127.0.0.1:8888/decode` 与 `/encode`，勾选“处理请求头”“请求数据包”，开启 Proxy/Repeater/Intruder 模块。
8. 修改参数发包，确认返回 200/业务成功；随后用 Intruder 对手机号、验证码等字段做自动化测试。

## PoC

```python
import hashlib

CLIENT_SECRET = "<从 hook/IDA 得到的固定串>"
CLIENT_TYPE = "android"
VERSION = "2.2.0"
URI_PREFIX = "/vuc"

def build_sign(headers, path, body):
    params = {
        "clientSecret": CLIENT_SECRET,
        "clientType": CLIENT_TYPE,
        "version": VERSION,
        "method": headers["Method"],
        "time": headers["Time"],
        "requestUri": path[len(URI_PREFIX):] if path.startswith(URI_PREFIX) else path,
    }
    for k, v in body.items():
        if k != "sign" and v is not None:
            params[k] = str(v)
    plaintext = "&".join(f"{k}={params[k]}" for k in sorted(params))
    return hashlib.md5(plaintext.encode()).hexdigest(), plaintext
```

```python
# Flask autoDecoder 端点核心（省略解析/异常处理）
from flask import Flask, request
import json, re

app = Flask(__name__)

@app.route("/decode", methods=["POST"])
def decode():
    return request.form.get("dataHeaders", "").strip() + "\r\n\r\n\r\n\r\n" + request.form.get("dataBody", "")

@app.route("/encode", methods=["POST"])
def encode():
    headers_str = request.form.get("dataHeaders", "")
    body_str = request.form.get("dataBody", "")
    headers, path = parse_headers_string(headers_str)
    body = json.loads(body_str) if body_str.strip() else {}
    sign, _ = build_sign(headers, path, body)
    new_headers = re.sub(r"(?i)(Sign:\s*)[^\r\n]+", rf"\g<1>{sign}", headers_str)
    return new_headers.strip() + "\r\n\r\n\r\n\r\n" + body_str
```

```text
Burp autoDecoder 配置：
  解密接口 http://127.0.0.1:8888/decode
  加密接口 http://127.0.0.1:8888/encode
  [x] 请求数据包  [x] 处理请求头
  在 Proxy/Repeater/Intruder 模块开启
```

原文用该流程成功让修改后的请求通过验签（返回业务成功）；密钥/固定串在原文中打码，本卡未复跑。

## 变体与关联

- **变体：运行时代签**：不重写算法，改用 JSRPC 调用 App/页面里的原签名函数；适合混淆严重或含动态 key 的场景，见 [[web-generic-auth-js-signature-jsrpc-autodecoder]]。
- **变体：Burp Python 扩展**：把重签逻辑写进 Burp 扩展而非 Flask，见 [[mobile-android-login-codesign-md5-burp-auto-resign]]。
- **变体：签名参与字段不同**：有的接口只签 body，有的签 headers+body；有的按字母排序，有的按固定顺序；以 hook 到的明文和 IDA 的 append 顺序为准。
- **关联**：[[mobile-android-okhttp-addheader-stack-native-sign-locate]]（hook addHeader 堆栈定位 native 签名）、[[code-analysis-reverse-obfuscation-mcp-skill-jsrpc-autodecoder-automation]]（MCP+Skill 生成 JSRPC/autoDecoder 工件）、[[tools-burp-js-hook-bridge-traffic-encrypt-decrypt]]（JS Hook+Bridge 加解密）。
- **边界**：服务端若使用一次性 nonce/时间窗/设备指纹绑定，需要同步生成；clientSecret 若由服务端下发或动态派生，离线重签失败；SSL Pinning/反调试未绕过时无法抓包/hook；AES body 加密未自动化时只能把密文当不透明字段，不能任意改其内部明文。

## 检测与防御

- 这是授权测试/逆向技巧；对防守方，客户端 Sign 只是提高篡改成本，不能替代服务端鉴权、参数校验与频控。
- 加固：把签名密钥放到服务端或使用服务端下发的一次性 nonce；校验时间窗、设备指纹、请求序号；对高频/异常参数变更做风控。
- 检测：同一账号/设备在短时间内出现大量签名合法但参数规律变化的请求；请求头 Method/Time/Sign 与 body 的关联异常；代理证书/抓包特征。
- 响应：发现自动化重签/爆破时，限流、封禁、增加验证码或二次认证；轮换客户端密钥并评估是否需要 App 升级。
