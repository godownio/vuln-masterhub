---
id: code-analysis-reverse-obfuscation-jwt-secretkey-secretiv-aes-cbc-traffic
title: 前端 AES-CBC 密钥与 IV 存放在 JWT/localStorage（SecretKey/SecretIV）：解 token 还原 requestData 解密-篡改-重加密
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: jwt-secretkey-secretiv-frontend-aes-traffic-decrypt-tamper
aliases:
- SecretKey SecretIV
- requestData 解密
- JWT 载荷取 AES 密钥
- System_Token 密钥
- 加密流量改包
- Burpy 加解密
- 前端加密 SQL 注入
tags:
- javascript
- reverse
- frontend-encryption
- aes
- cbc
- jwt
- burpy
- traffic-decrypt
- tamper
- sql-injection
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V391
  verified_at: '2026-11-09T11:30:17+08:00'
  notes: 已对照原文与全部4张图片核对：DevTools 中 requestData 发送函数取 localStorage System_Token 的 SecretKey/SecretIV 调 AES-CBC/PKCS7 加密并 Base64；Python 复刻加解密验证、Burp 改 OrderType=desc')" 触发 updatexml XPATH 报错、Burpy 插件自动加解密截图均与卡一致。卡内补充 JWT payload Base64URL 解码（urlsafe+补齐）比原文 b64decode 更稳妥，属等价实现。原文未声明组件版本、无 CVE，未设 affected_versions 正确；无 sources/URL/长段摘录，路径 code-analysis/reverse/obfuscation 合法。
---

## 一句话结论

应用把请求体 `requestData.data` 用 AES-CBC/PKCS7 + Base64 加密，而每会话的密钥与 IV 以 `SecretKey`/`SecretIV` 字段放在 JWT 载荷（或 localStorage 的 `System_Token` 对象）里下发；测试者只需解 JWT payload 取出这两个值，就能用 Python（或 Burpy 插件）对任意请求解密、修改明文参数（如注入 `desc')\"`）再重新加密发送，前端加密不仅无法阻止篡改，还会把 SQL 注入等漏洞藏在密文后面。

## 原理

- **加密位置与算法**：抓包见 `{"requestData":{"data":"<Base64>","sign":""}}`；在 DevTools 全局搜索 `requestData` 定位发送函数，最终进入加密函数 `d(e, t, a)`：`Utf8.parse(t)`、`Utf8.parse(a)` 分别作为 key/iv，`AES.encrypt(Utf8.parse(JSON字符串), key, {iv, mode: CBC, padding: Pkcs7})`，结果 `Base64.stringify(ciphertext)`。
- **密钥来源**：发送函数中 `a = A.defaultLocalStorage.get("System_Token")`，`requestData.data = d(JSON.stringify(e), a.SecretKey, a.SecretIV)`；该对象同时带 `authorizationValue`（JWT）。JWT 的 payload 是 Base64URL 明文 JSON，`SecretKey`/`SecretIV` 就在其中——只要拿到任意有效 token，就能还原加解密。
- **为什么这不是安全边界**：前端要完成加密，密钥必须到达浏览器；把密钥放进可读的 JWT claims/localStorage 只是换了个存放位置，测试者用 `token.split('.')[1]` 解码即可取得。每会话更换 key/iv 只增加脚本取 key 的一步，不增加保密性。
- **解密-篡改-重加密流程**：用同一 key/iv 对 `data` 做 AES-CBC 解密、去 PKCS7 填充得到 JSON；修改业务参数后按同样方式填充、加密、Base64 编码写回；服务端解密后按修改后的参数执行。文章把 `OrderType` 改为 `desc')\"` 后服务端返回 `XPATH syntax error`（updatexml 报错），确认了报错 SQL 注入。
- **自动化**：把上述逻辑实现为 Burp 的 Burpy 脚本的 `encrypt/decrypt`，即可在 Repeater 中右键解密/加密，实现“抓包→解密→改参→重加密→发包”的闭环；注意 JSON 序列化后的空格需按原格式处理（文章用 `json.dumps(...).replace(" ", "")`），响应解密时也按同一 key/iv。

## 触发条件

- 目标接口的请求体（如 `requestData.data`）为 AES-CBC/PKCS7 + Base64 密文，响应也可能加密。
- 密钥/IV 随会话下发：在 JWT payload 的 claims（示例字段 `SecretKey`/`SecretIV`）或 localStorage/前端配置对象（如 `System_Token`）中，可被脚本读取。
- 测试者持有合法账号与有效 token，能访问页面并调试 JS（DevTools）。
- 服务端未对解密后的参数做额外签名校验（示例 `sign` 为空），或签名算法也可前端复现。

## 利用步骤

1. 抓包标记密文字段（`requestData.data`）与伴随字段（`sign`、`checkSum`、`CurrentTimeStamp`、`traceId`），确认哪些参与校验。
2. DevTools 全局搜索 `requestData`，在发送函数下断，单步进入加密函数 `d`，记录算法（AES-CBC/PKCS7）、编码（Base64）与 key/iv 来源（`System_Token.SecretKey/SecretIV`）。
3. 从 localStorage 或 JWT 载荷取出 `SecretKey`、`SecretIV`（JWT payload 做 Base64URL 解码即得 JSON）。
4. 用 Python 解密请求中的 `data` 得到明文 JSON；修改目标参数（如把 `OrderType` 改成带闭合符的 payload）。
5. 用相同 key/iv 重新加密并替换 `data` 发送；观察错误回显/响应差异验证注入（文章以 updatexml 报错触发 `XPATH syntax error`）。
6. 需要高频测试时把加解密写进 Burpy 的 `encrypt/decrypt`（从 `Authorization` 头解析 JWT 取 key/iv），在 Burp 中右键自动解密与重加密。

## PoC

```python
import base64, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def get_key_iv(token: str):
    p = token.split('.')[1]
    p += '=' * (-len(p) % 4)                      # JWT 为 Base64URL，补齐长度
    payload = json.loads(base64.urlsafe_b64decode(p))
    return payload['SecretKey'].encode(), payload['SecretIV'].encode()

def decrypt(data_b64: str, key: bytes, iv: bytes) -> str:
    ct = base64.b64decode(data_b64)
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16).decode()

def encrypt(plain: str, key: bytes, iv: bytes) -> str:
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain.encode(), 16))
    return base64.b64encode(ct).decode()

# 示例：解密 -> 修改 -> 重加密
key, iv = get_key_iv(jwt_token)
obj = json.loads(decrypt(enc_data, key, iv))
obj['OrderType'] = "desc')\""                          # 注入点
new_data = encrypt(json.dumps(obj, separators=(',', ':')), key, iv)
```

Burpy 脚本要点（示意）：

```python
class Burpy:
    def decrypt(self, header, body):
        key, iv = self.get_key_iv(header.get('Authorization'))
        obj = json.loads(body)
        obj['requestData']['data'] = decrypt(obj['requestData']['data'], key, iv)
        return header, json.dumps(obj)
    def encrypt(self, header, body):
        key, iv = self.get_key_iv(header.get('Authorization'))
        obj = json.loads(body)
        obj['requestData']['data'] = encrypt(json.dumps(obj['requestData']['data'],
                                                         separators=(',', ':')), key, iv)
        return header, json.dumps(obj)
```

## 变体与关联

- 变体：key/iv 硬编码在 JS 字面量（见 [[front-end-hardcoded-aes-ecb-traffic-decrypt]]）；key 由接口下发、放 Cookie/localStorage；算法换 DES/3DES/SM4/RSA+AES 混合；响应体同样加密时需在 `decrypt` 中处理响应。
- 关联卡片：[[code-analysis-reverse-frontend-request-response-encryption-automation]]（XHR 断点/Initiator 定位与 PyExecJS 自动化）、[[tools-burp-burpy-pyro-python-auto-encrypt-decrypt]]（Burpy 插件接口与常见报错）、[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]（JS AES 参数还原）。
- 边界：若服务端对明文做 HMAC/签名且签名密钥不在前端可得（或签名覆盖参数且不可复算），单纯改密文会被拒；若 key 由服务端 session 绑定且 token 解码后无 key，需另找下发接口。

## 检测与防御

- 加密只是混淆：不要把密钥/IV 放进可读 JWT claims 或 localStorage 当作保护；JWT 只用于签名/认证，敏感材料不应放入 payload。
- 服务端必须做输入校验/参数化查询与权限校验；对解密后的参数同样按不可信输入处理（本例即 SQL 注入）。
- 检测：同一 token 的密文被重复构造/篡改、解密失败率异常、`XPATH syntax error`/SQL 报错；WAF 对解密后流量做审计；对关键接口做 HMAC 签名并要求签名密钥服务端持有。
