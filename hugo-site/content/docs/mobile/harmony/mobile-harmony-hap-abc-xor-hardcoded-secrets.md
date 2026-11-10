---
id: mobile-harmony-hap-abc-xor-hardcoded-secrets
title: HarmonyOS HAP 的 ABC 字节码反编译后用固定 XOR key 还原硬编码接口与密钥
type: scenario
domain: mobile
path: mobile/harmony
technique: hap-abc-xor-string-decrypt
tags:
- harmonyos
- hap
- abc
- reverse-engineering
- xor
- hardcoded-secret
- client-side-secret
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-10
  verified_at: '2026-11-08T01:09:14+08:00'
  notes: 已对照原文核对；图 16/17/18/19 ABC 反编译与固定 key=134522123 逐字节循环 XOR、还原端点/JWT 密钥/RSA 公钥一致；dedup_review 成立；未验证点：未在真实 HAP 上复现反编译流程
url: /docs/mobile/harmony/mobile-harmony-hap-abc-xor-hardcoded-secrets/
draft: false
kb_aliases:
- HAP 反编译 XOR 解密
- ABC 字节码字符串还原
- 客户端硬编码密钥提取
- HarmonyOS 应用逆向
---

## 一句话结论

HarmonyOS 应用 HAP 包内的方舟字节码（ABC）可反编译出字符串常量；若敏感串只用「固定 key 的逐字节循环 XOR」混淆，而 key 与解密函数同在包内，则等价于明文，攻击者可批量还原出 API 端点、JWT 签名密钥、RSA 公钥与请求动作串。

## 原理

- HAP 是 HarmonyOS 的应用分发包，ArkTS/JS 代码编译成 ABC（方舟字节码）。反编译工具能恢复出函数逻辑与字符串常量，包括被混淆的密文串和解密函数本身。
- 为什么 XOR 混淆无效：解密函数是 `res[i] = cipher[i] ^ key[i % len(key)]`，key 是一个内置的数字字符串。key、算法、密文三者全部随客户端分发，攻击者不需要任何服务端秘密，按同式即可还原，纯粹是「编码」而非「加密」。
- 为什么等于泄露信任边界：本例还原出的内容包括接口路径（`/api/v1/getflag`、`/api/v1/contacts?uid=`）、JWT 签名密钥、RSA 公钥、动作串 `{"action":"getflag"}` 与字段名。客户端因此掌握了构造特权请求所需的全部材料，服务端若信任这些客户端可推导的凭据即被绕过。
- 与通用字符串混淆的关系：这是「混淆/字符串加密」在移动应用里的具体实例，根因不是混淆强度不够，而是把本应只在服务端存在的秘密放进了客户端。

## 触发条件

- 客户端分发包（HAP/APK/IPA/JS bundle）内硬编码密钥、接口或签名逻辑；
- 仅用可逆对称混淆（XOR/Base64/简单替换）且 key 内置于包；
- 服务端信任客户端可推导的凭据（签名密钥、角色字段、动作串）做鉴权。

## 利用步骤

1. 解包 HAP，定位 ABC/反编译产物，搜索 `decrypt`/`xor`/固定 key 字符串。
2. 找到解密函数与其 key，逐字节对密文常量套用 `c ^ key[i%len(key)]`。
3. 批量还原所有字符串常量，整理出端点、密钥、公钥、动作串、字段名。
4. 用还原出的凭据去构造服务端请求（见「客户端可复算签名伪造特权请求」一类场景）。

## PoC

```python
# 仅在授权环境验证；密文与 key 均来自反编译结果
def decrypt_string(cipher: str, key: str = "<XOR_KEY>") -> str:
    return "".join(chr(ord(c) ^ ord(key[i % len(key)]))
                   for i, c in enumerate(cipher))

for c in ["<CIPHERTEXT_1>", "<CIPHERTEXT_2>", "<CIPHERTEXT_3>"]:
    print(decrypt_string(c))
```

## 变体与关联

- 变体：key 放在资源文件、so 库、或由多段拼接生成；Base85/Base64 二次编码；白盒密码/运行时才解密（提高成本但不改变「秘密在客户端」这一根因）；Android/iOS/小程序包同理。
- 关联：客户端硬编码密钥提取、JWT 硬编码密钥伪造、服务端信任可复算签名的越权、接口枚举/SQL 注入（用还原出的 `uid` 参数）。

## 检测与防御

- 防御：密钥、签名算法、敏感动作不要放进客户端；必须下发时用系统 keystore/硬件背书并与服务端会话绑定；服务端对每个请求独立做鉴权与授权，不信任客户端提交的 uid/角色/动作；对发布包做密钥与敏感串扫描。
- 加固/混淆只提高逆向成本，不能作为安全边界；把「客户端能算出来的东西」一律视为公开数据来设计。
- 检测：对客户端包做静态扫描发现硬编码密钥/私钥；服务端监控出现客户端不该知道的接口路径或动作串的调用。
