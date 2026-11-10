---
id: front-end-hardcoded-aes-ecb-traffic-decrypt
title: 前端 JS 硬编码 AES/ECB 密钥导致应用层加密流量可解密
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: 前端 JS 逆向定位硬编码密钥，恢复应用层加解密并解密通信流量
tags:
- crypto
- aes
- ecb
- frontend
- traffic-decrypt
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-29
  verified_at: '2026-11-08T15:43:27+08:00'
  notes: 已对照原文核对：img03 前端 JS 硬编码密钥 :*mU@-"S61Eujx$c 且 mode ECB/padding Pkcs7，img04 Burp AES Crypto hex 密钥加解密成功，img05 脚本解密得明文 102，img08 Burp 双向明文效果；dedup 相关候选（MQTT 凭据卡等）不同链；无组件版本信息。
url: /docs/code-analysis/reverse/obfuscation/front-end-hardcoded-aes-ecb-traffic-decrypt/
draft: false
kb_aliases:
- 前端加密流量解密
- AES ECB 硬编码密钥
- autoDecoder 全自动加解密
---

# 前端 JS 硬编码 AES/ECB 密钥导致应用层加密流量可解密

## 一句话结论

Web 应用在浏览器端用硬编码于前端 JS 的 AES/ECB 密钥对请求与响应做应用层加密时，攻击者可直接从前端源码还原算法与密钥，进而批量解密（并重新加密）全部通信流量，使该层加密对渗透测试与协议分析完全失效。

## 原理

应用层加密（区别于 HTTPS）依赖密钥保密，但加解密在浏览器端执行，算法与密钥必然随 JS 下发到客户端。若密钥以字面量硬编码在 JS 文件中（如 `:*mU@-"S61Eujx$c`），任何人查看前端源码即可获得。密文经 URL 编码与 Base64 编码后传输；AES/ECB 模式对相同明文块产生相同密文块且无 IV 参与，只需 16 字节密钥即可独立解密任意密文块，无需知道其他上下文。因此攻击者可以用 Python（pycryptodome 的 `AES.new(key, AES.MODE_ECB)`）还原解密函数，把请求/响应密文还原为明文，也可反向加密构造请求。

## 触发条件

- 目标系统请求/响应正文被加密，密文可见于请求参数或 JSON 响应中（通常为 Base64 字符串，URL 传输时带 `%3D` 等编码尾缀）。
- 加解密逻辑实现在前端 JS，密钥硬编码在 JS 源码中。
- 加密算法为 AES/ECB/PKCS7Padding（或无 IV 的分组模式），密钥为 16/24/32 字节字面量。

## 利用步骤

1. 抓包观察：URL、请求参数与响应 JSON 中出现无法直接阅读的密文字段（Base64 特征，尾部 `%3D`/`==`）。
2. 在浏览器 DevTools 的 Sources 面板中，依据 URL 路径特征（如包含 `performance` 的接口）定位同名目录/JS 文件，全局搜索 `crypt`、`AES`、`encrypt`、`decrypt` 等关键字。
3. 在命中代码处提取三要素：密钥字面量、模式（`mode: ECB`）、填充（`padding: Pkcs7`），以及密文编码方式（Base64、URL 编码）。
4. 用 Burp AES Crypto 类插件以密钥原文验证加解密；或编写 Python 解密函数：URL 解码 → Base64 解码 → `AES.new(key, AES.MODE_ECB)` 解密 → 去除 PKCS7 填充字节（注意填充字节 `\x01`–`\x0f` 需手动剥离）。
5. 密钥若在代码中以 hex 表示，先做 b16decode 还原为字节串。
6. 若响应为多层 JSON 嵌套且需逐字段解密，可部署本地 HTTP 服务（如 Flask `/decode`、`/encode` 接口），用字符串替换或 JSON 解析方式对每个密文 value 解密/加密。
7. 配合 Burp 插件（如 autoDecoder）把加解密接口挂进代理链，实现请求头/请求体/响应体的全自动加解密，之后即可像明文流量一样进行常规漏洞测试（越权、注入、逻辑缺陷等）。

## PoC

```python
from Crypto.Cipher import AES
import base64, urllib.parse

def aes_decrypt(text):
    key = b':*mU@-"S61Eujx$c'   # 从前端 JS 提取的硬编码密钥
    text = base64.b64decode(urllib.parse.unquote(text))
    aes = AES.new(key, AES.MODE_ECB)
    en_text = aes.decrypt(text)
    for zifu in [b'\x0a', b'\x0b', b'\x0c', b'\x0d', b'\x0e', b'\x0f',
                 b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06',
                 b'\x07', b'\x08', b'\x09']:
        en_text = en_text.replace(zifu, b"")
    return en_text.decode()
```

以上为原文展示的解密函数思路（密钥随站点而异，仅演示方法），未实际运行。

## 变体与关联

- 密钥也可能存放于独立的配置/初始化 JS、由前端运算派生（如 hex 编码后再解码），需先运行时观察再还原。
- 若为 AES/CBC，则还需提取 IV（可能在 JS 中硬编码或与密文同传）。
- 密钥若由服务端下发（session key），则需结合逻辑漏洞获取，本文场景不适用。
- 与 Shiro RememberMe 等服务端硬编码密钥场景不同：本场景密钥在前端，任何访问者都能获取，无需爆破。
- 工具链可用 Burp AES Crypto 插件手动验证，或 autoDecoder/mitmproxy 自定义脚本实现全流量自动加解密。

## 检测与防御

- 不应在客户端硬编码长期密钥；应用层加密无法对抗拥有客户端代码的攻击者，敏感数据的机密性应交给 TLS，客户端加密只作为混淆手段评估其收益。
- 如必须前端加密，密钥应会话级派生且经服务端认证绑定，避免所有用户共用同一静态密钥。
- 检测：对自家 JS 构建产物审计硬编码密钥字面量（长度 16/24/32 的字符串常量、hex 密钥），CI 中加入前端密钥泄漏扫描。
- ECB 模式泄露明文模式信息，改用 CBC/GCM 并正确处理 IV。
