---
id: defense-forensics-behinder-php-webshell-traffic-decrypt
title: 冰蝎 PHP WebShell 流量解密：从马文件取 AES key，Base64+AES-CBC 还原命令与响应
type: scenario
domain: defense
path: defense/forensics
technique: behinder-php-webshell-traffic-decrypt
tags:
- forensics
- traffic-analysis
- webshell
- behinder
- php
- aes
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:08:51+08:00'
  notes: 已对照原文冰碧蝎段核对：$key=1ca3b8c9c81a5fdc、Base64+AES-128-CBC、16 字节零 IV、PKCS#7 去填充、响应 JSON 字段再 Base64、stream 10-14 行为均一致；未复跑 pcap 解密；原文未标注组件版本。
url: /docs/defense/forensics/defense-forensics-behinder-php-webshell-traffic-decrypt/
draft: false
kb_aliases:
- 冰蝎流量解密
- Behinder PHP 流量分析
- AES128 冰蝎
- 冰蝎 key 提取
- WebShell 加密流量取证
---

## 一句话结论

冰蝎 PHP 马的请求/响应是 `Base64 + AES-128-CBC` 的嵌套密文，AES key 以明文写在马文件里；拿到马文件或内存中的 key 后，对 HTTP POST 体与响应体做 Base64 解码、AES-CBC 解密（16 字节全零 IV）并去 PKCS#7 填充，即可还原攻击者执行的命令、目录探测结果和外带文件。

## 原理

- 典型冰蝎 PHP 马会声明 `$key="<16字节>"`，把请求体读入后：
  - 若未加载 openssl，则 `base64_decode` 后按 `key[$i+1 & 15]` 做 XOR；
  - 若加载 openssl，则 `openssl_decrypt($post, "AES128", $key)`，即 AES-128-CBC、默认 PKCS#7 填充。
- 解密后的明文按 `|` 分割：第一部分是功能名，第二部分是参数（本质是加密后的 PHP 插件代码），最终通过 `call_user_func(new C(), $params)` 进入 `eval`。
- 实际流量中，请求体与响应体都是 Base64 文本，AES-CBC 使用 16 字节全零 IV（原文脚本按 `b"\x00"*16` 解密）；响应常是 JSON，字段值再 Base64 编码。
- 为什么可行：冰蝎的密钥必须随马文件落地（或从 session/内存取得），一旦获得马文件或主机权限，历史流量即可离线解密；对称加密只保护传输，不保护已泄露的密钥。
- 若马使用 XOR 回退（openssl 未加载）、动态 key（从 session/请求派生）或不同版本协议，需按实际马代码调整。

## 触发条件

- 有包含 WebShell 交互的 pcap/代理日志，且能定位到具体 PHP 马文件（或从内存/备份取得）。
- 马文件中能找到 `$key="..."` 16 字节密钥；或已知 key。
- 流量使用 Base64 + AES-128-CBC（或可识别的 XOR 回退）；HTTP POST 体/响应体完整。
- 攻击者通过该马执行过命令、上传/下载文件或执行插件。

## 利用步骤

1. 在流量中定位可疑 PHP 路径（如 `/upload/<timestamp>.php`）的连续 POST；首包可能较大，后续复用同一连接。
2. 获取马文件，正则提取 `$key` 的 16 字节值；若只有流量，可尝试从 `$_SESSION['k']` 或内存镜像获取。
3. 用 tshark 提取该 URI 的 POST 请求体（hex）与响应体：
   ```bash
   tshark -r 1.pcapng -Y 'http.request.method=="POST" && http.request.uri=="/upload/x.php"' \
     -T fields -e frame.number -e tcp.stream -e http.file_data
   ```
4. 对请求体做 `Base64 解码 → AES-128-CBC 解密（零 IV）→ 去 PKCS#7 填充`；对响应体做同样处理（若响应是 JSON，再对每个字段值做 Base64 解码）。
5. 从明文提取 `func|params`、命令输出、目录列表；对嵌套的 `base64_decode('...')` 再解码，得到上传/下载的插件或文件。
6. 将多个 stream/包按时间排序，还原完整攻击时间线；对可疑外带文件做进一步解码（如 Base58/压缩/多层加密）。

## PoC

```python
import base64, re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b"1ca3b8c9c81a5fdc"          # 从马文件 $key 提取

def dec(body_b64: str) -> bytes:
    raw = base64.b64decode(body_b64)
    return unpad(AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(raw), 16)

# tshark 提取的 http.file_data 是 hex 字符串；先转 bytes 再当 Base64 文本
body_hex = "..."                    # 来自 tshark -e http.file_data
plain = dec(bytes.fromhex(body_hex).decode("latin1"))
print(plain.decode("utf-8", "replace"))

# 响应 JSON 的字段值通常再 Base64 编码
# {"status":"success","msg":"<base64>"} -> base64.b64decode(msg)
```

说明：PoC 为原文脚本的结构化精简，未在本机执行；仅用于授权取证与应急响应。

## 变体与关联

- 变体（XOR 回退）：`extension_loaded('openssl')` 为假时，冰蝎用 `base64_decode + 单字节 XOR`，key 按下标 `i+1 & 15` 循环；需按马代码实现。
- 变体（协议/语言）：冰蝎 JSP/ASPX、不同版本（AES-ECB、动态 key、Multipart 上传）需按样本调整；哥斯拉是另一套协议。
- 变体（外带）：攻击者可能把文件 Base64/Base58/多层 OpenSSL 加密后通过命令输出回传；需逐层解码。
- 关联：[[defense-forensics-godzilla-php-webshell-traffic-decode]]（哥斯拉 PHP 的 XOR/Base64 流量）；[[defense-forensics-godzilla-java-webshell-traffic-decode]]（哥斯拉 Java AES-ECB）；[[web-php-rce-webshell-rsa-traffic-encoder]]（蚁剑 RSA 流量编码器）。
- 边界：key 动态生成且未落地、流量被 TLS 保护且无私钥、马文件被删除且无内存镜像、协议被魔改时，需结合主机取证或逆向样本。

## 检测与防御

- 检测：上传目录出现随机命名 `.php`；对同一 PHP 路径的高频 POST、请求/响应体为高熵 Base64；响应 JSON 字段值 Base64；请求体解密后出现 `eval`、`assert`、`system`、`base64_decode` 等。
- 检测：WebShell 流量常伴随目录探测（`ls`/`dir`）、`whoami`、文件读写、压缩/加密外带；结合文件完整性监控与访问日志。
- 防御：上传目录禁止 PHP 解析、白名单扩展名、随机重命名；禁用 `eval`/`assert`/危险函数；部署 WebShell 检测与流量侧规则。
- 响应：隔离主机、保存 pcap 与马文件作为证据、提取 key 解密全部流量、排查横向移动与持久化；轮换可能泄露的凭据。
