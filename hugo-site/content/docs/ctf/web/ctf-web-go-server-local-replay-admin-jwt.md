---
id: ctf-web-go-server-local-replay-admin-jwt
title: Go server.exe 逆向 + 本地复现签发管理员 JWT：改 SQLite role 复用同一 HS256 密钥
type: scenario
domain: ctf
path: ctf/web
technique: go-server-local-replay-admin-jwt
tags:
- ctf
- web
- go
- reverse
- jwt
- hs256
- sqlite
- local-replay
- auth-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:44:20+08:00'
  notes: 已对照原文 lit_reverse_my_web 与 9 张图片核对：二进制符号、golang-jwt/v5、claims role/iss/sub、SQLite schema、本地改 role 后由原程序签发 admin token、Bearer/Cookie 两种携带均与原文一致；本地 token 打远端 200 已由原文验证。PoC 未本机执行
url: /docs/ctf/web/ctf-web-go-server-local-replay-admin-jwt/
draft: false
kb_aliases:
- lit_reverse_my_web
- Go 二进制逆向
- golang-jwt/jwt/v5
- 本地复现签发 JWT
- SQLite role 修改
- reverseMyWeb
---

## 一句话结论

题目只给一个编译后的 Go 服务 `server.exe`。从二进制字符串可恢复 `handleRegister/handleLogin/handleFlag/signJWT/parseToken`、`golang-jwt/jwt/v5`、claims 中的 `role`、SQLite 建表语句与 `JWT secret` 模块；`/flag` 只允许 `role=admin`。与其爆破 HS256 密钥，不如本地运行同一份二进制，注册用户后直接改本地 SQLite 的 `users.role='admin'`，让原程序自己签发一枚合法管理员 JWT，再把这枚 token 带到远端 `/flag`——因为本地与远端是同一构建、同一密钥/iss，签名直接通过。

## 原理

- **二进制即源码**：Go 二进制保留大量函数名/字符串/SQL 语句；`strings`/Ghidra 可恢复路由（`/register`、`/login`、`/flag`、`/logout`）、JWT 签发/解析、claims 结构 `{role, iss, sub, exp, iat}`、SQLite 建表 `users(id, username, password_hash, role default 'user')` 与查询。
- **权限模型**：登录时从数据库读 `role` 写入 JWT；`/flag` 解析 token 后检查 `role == admin`。因此只要能拿到 `role=admin` 的合法签名 token 即可。
- **为什么不爆破密钥**：HS256 密钥在二进制/配置中；爆破需要字典/已知明文攻击。更直接的是“让原程序自己签”：本地运行同一二进制，使用同一 `internal/jwtsecret.Key`/环境变量，签发出的 token 与远端同密钥、同 `iss`，远端无法区分。
- **本地复现**：直接运行可能因 SQLite DSN 路径（如 `/tmp/reversemyweb.db`）不存在报 `unable to open database file`；创建对应目录/路径后服务启动。注册 -> 登录拿普通 token；用 `sqlite3` 把本地用户 `role` 改为 `admin`；重新登录，程序按数据库角色签发管理员 token。
- **角色探测**：为不盲猜，可本地把 role 依次改成 `root/manager/auditor/.../admin`，观察 `/flag` 状态码；只有 `admin` 通过权限判断（本地 500 可能只是缺少真实 flag 资源）。
- **为什么成立**：JWT 只验证签名与 claims，不绑定签发环境；同一密钥下本地签发的 token 在远端有效。根因是“把角色写进 token + 部署间共享密钥”，而不是加密算法被攻破。

## 触发条件

- 目标提供编译后的服务端二进制（Go/Java/等），且字符串/符号未完全剥离。
- 鉴权使用 JWT，角色/权限写在 claims，签名密钥在二进制/配置/环境中且本地与远端相同。
- 可本地运行同一二进制（依赖/DSN 可修复），并能修改本地数据库/配置让程序签发高权限 token。
- 远端 `/flag` 只校验 token 签名与 role，不校验签发来源/设备。

## 利用步骤

1. `strings server.exe`/Ghidra 恢复路由、JWT 库、claims、SQLite schema、`jwtsecret.Key` 引用。
2. 本地运行 `server.exe`，按报错创建 SQLite DSN 路径；确认监听端口。
3. 本地 `/register` + `/login`，拿到普通 JWT；解码确认 `role=user`、`iss=reverseMyWeb`。
4. 用 `sqlite3` 执行 `UPDATE users SET role='admin' WHERE username='localprobe'`；重新 `/login` 拿管理员 JWT（`role=admin`，签名由原程序生成）。
5. 把 token 以 `Authorization: Bearer <token>` 或 `Cookie: token=<token>` 发到远端 `/flag`，读取 flag。
6. 若远端密钥不同，token 会 401/403；此时需从二进制/环境恢复真实密钥或找其他泄露。

## PoC

```python
import sqlite3

conn = sqlite3.connect(r"E:\tmp\reversemyweb.db")
conn.execute("UPDATE users SET role=? WHERE username=?", ("admin", "localprobe"))
conn.commit()
```

```bash
# 本地注册/登录
curl -i -d "username=localprobe&password=localpass123" http://127.0.0.1/register
curl -i -H "Accept: application/json" -d "username=localprobe&password=localpass123" http://127.0.0.1/login
# 取管理员 token 后打远端
curl -i -H "Authorization: Bearer <admin_token>" http://target/flag
curl -i -H "Cookie: token=<admin_token>" http://target/flag
```

## 变体与关联

- 若二进制不保留符号，可用 GoReSym/Go 1.18+ pclntab 恢复函数名，或动态调试找 JWT 签发点。
- 若无法本地运行，可 patch 二进制/伪造数据库/环境变量，或从内存/配置提取 HS256 密钥后自行签名。
- 角色探测可换成枚举/字典；若 token 还含 `sub/iss/aud`，本地签发时保持一致。
- 关联：Go 二进制逆向、JWT HS256 伪造、SQLite 本地复现、权限模型缺陷卡。

## 检测与防御

- 每个部署使用独立高熵 JWT 密钥（KMS/密钥管理），不要把同一密钥硬编码进发布二进制；定期轮换。
- 权限判断不要只信 token 中的 `role`；服务端按 `sub` 查数据库当前角色/权限，支持撤销。
- 不发布带调试符号/明文字符串的服务端二进制；剥离符号、加密配置。
- 检测：同一 `iss` 但 `sub` 为陌生用户的 admin token；token 签发地与请求来源不一致；本地/测试密钥出现在生产。
