---
id: web-python-deserialization-jwt-claim-base64-pickle-admin
title: 签发改 RS256、验签允许 HS256：用公钥当 HMAC 密钥伪造 admin 令牌，再让服务端 pickle.loads 令牌里的 introduction 声明
type: scenario
domain: web
path: web/python/deserialization
technique: jwt-alg-confusion-claim-pickle-deserialization
tags:
- python
- flask
- jwt
- pickle
- deserialization
- algorithm-confusion
- rs256
- hs256
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:54:05+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原题服务端 jwt.encode(ss,privateKey,RS256) 与 jwt.decode(token,publicKey,algorithms=[HS256,RS256]) 的算法不一致、/admin 里 base64.b64decode(introduction) 后 pickle.loads、is_admin 分支与 md5 口令校验均与正文源码一致；公钥恢复（rsa_sign2n / sig2n）与 jwt.io 伪造步骤、__reduce__ 返回 exec 的载荷与正文一致；PoC 为按该结构整理，未对真实目标执行
url: /docs/web/python/deserialization/web-python-deserialization-jwt-claim-base64-pickle-admin/
draft: false
kb_aliases:
- JWT 声明里藏 pickle
- introduction base64 pickle
- RS256 签发 HS256 验证
- 公钥当 HMAC 密钥 + pickle
- Flask JWT pickle 链
---

## 一句话结论

服务端用 `jwt.encode(claims, privateKey, algorithm='RS256')` 签发、却用 `jwt.decode(token, publicKey, algorithms=['HS256','RS256'])` 验签时，攻击者可以用**公钥文本**当 HMAC 密钥签一个 HS256 令牌，把 `is_admin` 改成 `true` 并通过校验；如果该应用随后把令牌里的某个声明做 `base64.b64decode` + `pickle.loads`（本题是管理员才有的 `introduction` 字段），伪造令牌就等于把任意 pickle 载荷送进服务端，直接 RCE——算法混淆与反序列化两处错误叠加，任一处单独存在危害都小得多。

## 原理

- **算法混淆（CVE 类通病）**：`algorithms=[...]` 列表里同时允许 `HS256` 和 `RS256`，而验签回调未按 `token.Header['alg']` 强制绑定密钥类型。HS256 验签时 PyJWT 把传入的 key 当 HMAC secret，于是“公钥字节”变成对称密钥；由于公钥是公开信息（或可从两个 RS256 令牌用 `s^e mod n` 反推，见关联卡），任何人都能算出合法签名。
- **声明即数据通道**：`/admin` 里 `if is_admin: serial_S = base64.b64decode(real["introduction"]); pickle.loads(serial_S)`。业务把它当“个人简介”存储，实际是一个**由令牌承载的序列化 blob**；令牌可伪造 ⇒ blob 可控 ⇒ `pickle.loads` 执行 `__reduce__` 返回的任意 callable。
- **身份校验只剩口令哈希**：`if password != md5(user_list[username])` 会挡住随意改用户名，但攻击者可以保留一个已知账号（或注册自己的账号并把自己的 `password`/`is_admin` 一起写进令牌），因为 `user_list` 是内存字典、`md5(已知口令)` 可自行计算。
- **为什么必须两次错误叠加**：只有算法混淆，攻击者能进 admin 页面但 `introduction` 是自己可控的字符串（无 `pickle.loads` 则无害）；只有 `pickle.loads`，攻击者没有合法 admin 令牌就摸不到该分支。二者同时存在才是完整链。
- **PyJWT 的行为细节**：`jwt.decode(token, key, algorithms=[...])` 会用列表里的算法族校验 `alg` 头；HS256 分支直接把 `key` 当 bytes secret，不做 PEM 解析，因此“公钥 PEM 文本”能原样当密钥用（换行、头尾 `-----BEGIN PUBLIC KEY-----` 都必须完全一致）。

## 触发条件

- 签发与验签使用不同算法族，且 `algorithms` 列表同时包含 HMAC 与 RSA。
- 能获取公钥：直接暴露（`/public.pem`、前端 JS、JWKS 接口），或通过两个以上合法 RS256 令牌用 `s^e mod n` 恢复。
- 令牌中的某个声明会被 `base64.b64decode` + `pickle.loads`（或 `yaml.load`、`eval`）处理。
- 目标环境存在可用 gadget（`os.system`/`subprocess` 等内建即可，pickle 不依赖第三方库）。

## 利用步骤

1. 注册/登录一个普通账号，取两个合法 RS256 令牌（用于恢复公钥，若公钥未直接暴露）。
2. 用 rsassa-pkcs1 数学关系恢复公钥（`docker run --rm -it portswigger/sig2n <jwt1> <jwt2>`，或脚本算 `gcd(s1^e - m1, s2^e - m2)`），得到 PEM 文本。
3. 构造 claim：保留合法的 `username`/`password`（md5），把 `is_admin` 设为 `true`，`introduction` 设为 `base64(pickle_payload)`。
4. 用公钥 PEM 文本作 HMAC secret、`algorithm='HS256'` 签发令牌（注意 PyJWT 版本差异：新版会在 `decode` 时拒绝 `alg` 不匹配，需实测目标版本）。
5. 带该 `Token` Cookie 访问 `/admin`，服务端 `pickle.loads` 触发 `__reduce__` 里的 `exec`/`os.system`。
6. 无回显时把命令结果写到 Web 目录或反弹 shell。

## PoC

```python
import base64, hashlib, pickle, jwt

# 1) pickle 载荷：__reduce__ 返回 (exec, ("cmd",))
class A:
    def __reduce__(self):
        return (exec, ("import os; os.system('id > /tmp/pwned')",))

payload = base64.b64encode(pickle.dumps(A())).decode()

# 2) 用公钥 PEM 文本当 HMAC 密钥，签 HS256
public_key = open("public.pem", "rb").read()
claims = {
    "username": "film",                                  # 已注册账号
    "password": hashlib.md5(b"yourpass").hexdigest(),     # 该账号口令的 md5
    "is_admin": True,
    "introduction": payload,
}
token = jwt.encode(claims, public_key, algorithm="HS256")
print(token)
```

```http
GET /admin HTTP/1.1
Host: target
Cookie: Token=<HS256 令牌>
```

说明：PoC 按原文服务端代码与 exp 结构整理；原文最终用 jwt.io 的 “secret base64 encoded” 选项等工具完成签名（截图步骤），未给出完整脚本输出。`exec` 的 `__reduce__` 在 Python 3 可用，若被限制可换 `os.system`、`subprocess.check_output`、`eval`。

## 变体与关联

- **公钥获取变体**：`/public.pem` 直接下载、`jwks.json`、前端打包、错误信息泄露；无公开公钥时用两令牌恢复（见关联卡）。
- **声明 sink 变体**：`pickle.loads`、`yaml.load`（非 safe）、`eval`、`jsonpickle.decode`、`marshal.loads`、`torch.load`；也可能藏在 Cookie（Flask session）或 `X-*` 头里。
- **算法变体**：`alg: none`（若 `algorithms` 含 none）、`PS256`/`ES256` 混用、`kid` 注入指向可控文件/命令。
- **关联**：`web-generic-jwt-rs256-hs256-confusion-key-recovery`（无公钥时用两个 JWT 恢复公钥的数学方法）、`web-generic-jwt-alg-none-bypass`（同类算法混淆的另一分支）、`web-python-deserialization-flask-pickle-after-request-command-echo`（Flask 内 pickle 触发与回显形态）、`web-python-deserialization-bottle-signed-cookie-pickle-rce`（签名 Cookie 里藏 pickle 的同构链）。
- **边界**：`algorithms` 只允许 `RS256`、或验签时按 `alg` 绑定密钥类型（PyJWT 2.x 对 `alg`/key 组合更严格）时算法混淆失效；`introduction` 走白名单 JSON 时不触发反序列化；`jdk.serialFilter` 类机制不适用于 Python，但 `pickle` 可用 `RestrictedUnpickler` 限制。

## 检测与防御

- **JWT 库用法**：`algorithms` 只写实际使用的那一种；签发与验签使用同一密钥类型；PyJWT 升级到 2.x 并按 `jwt.decode(..., algorithms=["RS256"])` 严格声明。
- **不要把可执行格式放进令牌**：声明只放标量（字符串/数字/布尔）；需要结构化数据用 JSON 并做字段白名单校验。
- **绝不 `pickle.loads` 不可信数据**：包括令牌、Cookie、缓存、消息队列；改用 JSON + 显式 schema。
- **密钥/公钥管理**：公钥可以公开，但必须保证验签不把它当 HMAC 密钥；对称密钥不入前端、不入令牌。
- **检测**：同一 `Token` 的 header `alg` 从 RS256 变为 HS256；`introduction`/`data` 声明为长 Base64 且解码后以 `\x80\x04`（pickle protocol 4）或 `c`（protocol 0）开头；`/admin` 出现 `pickle` 相关异常栈；进程出现 `os.system`/`subprocess` 子进程。
