---
id: defense-forensics-behinder-php-rc4-xor-modified-traffic
title: 魔改冰蝎 PHP 马流量：Base64+RC4+key[i+1] 异或双层解密
type: scenario
domain: defense
path: defense/forensics
technique: behinder-php-rc4-xor-modified-traffic
tags:
- defense
- forensics
- traffic-analysis
- webshell
- behinder
- php
- rc4
- xor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:57:43+08:00'
  notes: 已对照原文碟中谍2.0与截图核对：$key=e45e329feb5d925b、base64_decode→RC4→key[(i+1)&15] XOR 顺序、CyberChef演示XOR key 45e329feb5d925be一致；未验证点：未对附件pcap复跑。
url: /docs/defense/forensics/defense-forensics-behinder-php-rc4-xor-modified-traffic/
draft: false
kb_aliases:
- 魔改冰蝎
- 冰蝎 RC4 变种
- 冰蝎 PHP RC4+XOR
- Behinder RC4 webshell
- 碟中谍2.0
---

## 一句话结论

魔改冰蝎 PHP 马把 `base64_decode` 后的请求体先过标准 RC4（16 字节 key），再逐字节异或 `key[(i+1)&15]`；按马代码的同一顺序（base64 解码 → RC4 → 异或）即可还原攻击者执行的命令与参数。

## 原理

- **马代码结构**：典型魔改马会把 `$key` 写成 16 字节字符串，`$data = base64_decode($data)` 后执行 RC4 的 KSA/PRGA，得到中间密文 `$cipher`，再做一次逐字节 XOR：
  ```php
  for ($i = 0; $i < strlen($cipher); $i++) {
      $cipher[$i] = $cipher[$i] ^ $key[$i + 1 & 15];
  }
  return $cipher;   // 之后 eval
  ```
  其中 `$key[$i + 1 & 15]` 的优先级是 `($i+1) & 15`，即从 key 的第 2 个字节开始循环，第 1 个字节 `key[0]` 不参与。
- **RC4 是对称流密码**：KSA 用 key 初始化 256 字节 S 盒，PRGA 生成密钥流并与数据异或；加密和解密使用同一函数。
- **XOR 是对合运算**：`A ⊕ K ⊕ K = A`，所以解密只需按相反顺序再异或一次；由于 RC4 与 XOR 不交换，顺序必须是“先 RC4 再 XOR”（与马代码的 `Decrypt` 一致）。
- **为什么能解**：`$key` 硬编码在马文件里，属于“密钥随载荷落地”；拿到马文件或流量中的马内容后即可离线解密历史流量。`$bs = "base64_" . "decode"` 只是把函数名拼接，属于静态查杀规避，不影响算法。
- **与标准冰蝎的区别**：标准冰蝎 PHP 常用 `Base64 + AES-128-CBC + 零 IV`；本题是 `Base64 + RC4 + 单字节 XOR`，因此用 AES 脚本解不出来，需要按马代码实现 RC4/XOR。

## 触发条件

- pcap/代理日志中有可疑 PHP 文件（如 `upload/<timestamp>.php`）的连续 POST，请求体是 Base64 文本。
- 能定位马文件，看到 `$key = "..."`、RC4 KSA 的 `for ($i=0;$i<256;$i++)`、PRGA 以及额外的 XOR 循环。
- 用标准冰蝎 AES 解密失败/乱码；题目提示“魔改/冰蝎/RC4/异或”。
- 请求体长度与命令长度不匹配（因 Base64 膨胀），响应可能是明文或同样加密。

## 利用步骤

1. 从流量中筛出目标 PHP 的 POST 请求体（Wireshark `Follow HTTP Stream` 或 `tshark -e http.file_data`）。
2. 获取马文件：通常在首个上传请求的 `multipart/form-data` 中，或在服务器上；正则提取 `$key` 的 16 字节值。
3. 实现 RC4（KSA + PRGA）和 XOR 循环；对请求体做 `base64_decode → RC4 → XOR key[(i+1)&15]`。
4. 解出的明文通常是 `功能名|参数` 或 PHP 代码/命令；对参数再做 Base64/hex/压缩解码。
5. 对响应体做同样处理（若响应也走同一 `Decrypt`/`Encrypt` 逻辑）；若是明文，直接提取命令输出。
6. 按时间排序多个请求，还原攻击者执行的命令、目录探测、文件上传/下载；用 CyberChef 的 RC4 + XOR 也可手工验证（注意 key 与 XOR 索引起点）。

## PoC

```python
import base64

KEY = b"e45e329feb5d925b"   # 从马文件 $key 提取

def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(out)

def decrypt(body_b64: str) -> bytes:
    raw = base64.b64decode(body_b64)
    mid = rc4(raw, KEY)                       # 先 RC4
    plain = bytes(b ^ KEY[(i + 1) & 15] for i, b in enumerate(mid))  # 再 XOR
    return plain

# 示例：把抓包得到的请求体 Base64 文本填进来
# print(decrypt("ypSNAOcf...").decode("utf-8", "replace"))
```

说明：PoC 按马代码的 `Decrypt` 顺序重写；`&15` 假定 key 为 16 字节，若 key 长度不同应改为 `& (len(KEY)-1)`。未在本机对附件复跑。

## 变体与关联

- **标准冰蝎 AES**：`Base64 + AES-128-CBC + 零 IV`；见 [[defense-forensics-behinder-php-webshell-traffic-decrypt]]。
- **纯 XOR 回退**：openssl 未加载时冰蝎会用 `key[$i+1 & 15]` 做 XOR；本变体在其前面又加了一层 RC4。
- **key 索引变体**：可能是 `$i & 15`（从 key[0] 开始）、`$i+1 & 15`（本题）、或 `$key[$i % strlen($key)]`；按马代码调整。
- **RC4 变体**：KSA/PRGA 可能被改动（如丢弃前 N 字节、S 盒初值不同）；以马代码为准。
- **响应加密**：部分马只加密请求、响应明文；也可能双向加密，需分别尝试。
- **关联**：[[defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt]]（JSP 冰蝎的 key 派生）、[[ctf-forensics-pcap-http-order-vm-opcode-reconstruction]]（从 pcap 还原后门指令）。

## 检测与防御

- 静态检测：PHP 文件中同时出现 `base64_decode`（或拼接函数名）、RC4 的 256 次 KSA 循环、以及 `$cipher[$i] ^ $key[...]` 循环，即可判定为魔改冰蝎/加密马；可写 YARA/正则规则。
- 流量检测：PHP 路径的 POST 体为 Base64、请求/响应长度有规律、同一 URI 高频交互；结合马文件哈希与 Web 访问日志定位。
- 防御：限制上传目录执行权限、禁用 `eval`/危险函数、WAF 拦截已知冰蝎特征；发现马后立即隔离主机、提取 key 解密历史流量、排查横向移动。
- 取证：保留原始 pcap 与马文件，先计算哈希；解密脚本只在隔离环境运行，不要执行解出的 payload。
