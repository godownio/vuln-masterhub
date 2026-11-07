---
id: defense-forensics-behinder-php-default-key-aes-ecb-traffic-decode
title: 冰蝎 PHP 默认密钥 e45e329feb5d925b：AES-128-ECB 魔数截断解密与 gzip/Base64 多层响应还原
type: scenario
domain: defense
path: defense/forensics
technique: behinder-php-default-key-aes-ecb-traffic-decode
tags:
- forensics
- traffic-analysis
- webshell
- behinder
- php
- aes-ecb
- gzip
- base64
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:24:26+08:00'
  notes: 已对照原文 MISC3 与图06-12核对：流48 马代码 key=e45e329feb5d925b、magicNum=hexdec(substr(key,0,2))%16=4、substr 截断+AES-128-ECB，流62 响应 Content-Encoding gzip/Transfer-Encoding chunked，CyberChef 多层解码得到 SQLite；与 CBC 候选卡 defense-forensics-behinder-php-webshell-traffic-decrypt 为不同模式/key 来源/截断步骤的独立变体，dedup_review 理由成立，保留。未验证点：未在附件 pcap 上复跑。
url: /docs/defense/forensics/defense-forensics-behinder-php-default-key-aes-ecb-traffic-decode/
draft: false
kb_aliases:
- 冰蝎默认 key
- e45e329feb5d925b
- 冰蝎 AES-ECB
- magicNum 截断
- 冰蝎 gzip 响应
- Behinder AES-ECB webshell
---

## 一句话结论

部分冰蝎 PHP 马使用默认 key `e45e329feb5d925b`，请求体是“Base64 文本末尾追加 `hexdec(key[0:2])%16`（默认 4）个随机字符 + AES-128-ECB 密文”；解密需先截掉末尾这 4 个字符、Base64 解码、AES-128-ECB 解密并去 PKCS#7 填充。响应常被 Apache 以 `chunked + gzip` 包裹，拆掉 HTTP/分块/gzip 后再逐层 Base64 解码，可还原 JSON、命令输出乃至 SQLite 等外带文件。

## 原理

- 典型马代码：
  ```php
  $key = "e45e329feb5d925b";
  $magicNum = hexdec(substr($key, 0, 2)) % 16;   // "e4" -> 228 % 16 = 4
  $data = substr($data, 0, strlen($data) - $magicNum);
  return openssl_decrypt(base64_decode($data), "AES-128-ECB", $key, OPENSSL_PKCS1_PADDING);
  ```
  请求到达后，马读取 `php://input`，按上述 `Decrypt()` 还原后直接 `eval`。Base64 末尾的随机字符是刻意加的“签名干扰”，长度由 key 前两个十六进制字符决定；默认 key 下固定为 4 字节。
- AES-128-ECB 是确定性的：同一明文块在同一 key 下得到同一密文块，无 IV、无随机化；因此只要 key 固定（默认 key 在所有使用该模板的马上都相同），历史流量可离线批量解密。ECB 也意味着攻击者可以重放/拼接块，但取证重点是恢复明文。
- 响应方向通常是应用层 Base64 + HTTP 压缩：Apache/nginx 看到请求头 `Accept-Encoding: gzip` 会对响应做 gzip，若同时启用 chunked 则还有分块编码。冰蝎的插件把执行结果（如文件内容）先 Base64 放进 JSON 的 `msg` 字段，再整体 Base64；所以需要按“HTTP 去头 → 去 chunk → gunzip → Base64 → JSON → Base64”的顺序逐层还原。
- 为什么能解：冰蝎为了“免杀/免流量特征”必须让马端持有可逆密钥；默认 key 直接硬编码在马里且公开，等于把解密能力交给任何拿到流量的人。若攻击者改了 key 或改用 AES-CBC/RC4 变体，则需按实际马代码调整。

## 触发条件

- 有包含 WebShell 交互的 pcap/代理历史/WAF 日志，且能定位到可疑 PHP 路径的连续 POST。
- 请求体是 Base64 字符集文本，末尾带少量随机字符；响应可能被 gzip/chunked 包裹。
- 马使用默认 key `e45e329feb5d925b` 或已知 key；使用 `AES-128-ECB` 与“截断末尾 magicNum 字符”的模板。
- 需要还原攻击者执行的命令、上传/下载的文件或外带的数据库。

## 利用步骤

1. 在流量中定位可疑 PHP 的 POST（如上传目录下随机命名的 `.php`、`/admin.php?p=...`），记录请求体与响应体。
2. 从马文件或首个 multipart 上传包中确认 `$key` 与 `Decrypt()` 结构；若为默认 key，直接令 `magicNum = int(key[:2], 16) % 16 = 4`。
3. 请求解密：对请求体去掉末尾 `magicNum` 个字符 → Base64 解码 → AES-128-ECB 解密 → 去 PKCS#7 填充；明文通常是 `功能名|参数`、PHP 插件代码或命令。
4. 响应解密：导出服务端到客户端的原始字节；按 `\r\n\r\n` 去掉 HTTP 头；若 `Transfer-Encoding: chunked` 先去分块；若 `Content-Encoding: gzip` 或数据以 `1f 8b` 开头则 gunzip。
5. 对得到的 Base64 文本解码：第一层通常得到 JSON（如 `{"status":"success","msg":"<base64>"}`），再对 `msg` 的值 Base64 解码；若仍是可打印 Base64，继续解码，直到出现文件魔数（`SQLite format 3`、`PK`、`MZ`、`%PDF` 等）。
6. 把还原出的文件按魔数命名保存，计算哈希；若为数据库，用对应引擎打开并继续做字段级解密（见关联卡）。
7. 按时间排序所有请求/响应，还原命令执行、目录探测、文件上传下载与外带数据的完整时间线。

## PoC

```python
import base64, gzip, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = b"e45e329feb5d925b"          # 默认 key；改过 key 时替换
MAGIC = int(KEY[:2], 16) % 16     # 默认 4

def dec_request(body_b64: bytes) -> bytes:
    if MAGIC:
        body_b64 = body_b64[:-MAGIC]          # 去掉末尾随机字符
    raw = base64.b64decode(body_b64)
    return unpad(AES.new(KEY, AES.MODE_ECB).decrypt(raw), 16)

def dechunk(body: bytes) -> bytes:
    out, i = bytearray(), 0
    while True:
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        size = int(body[i:j].split(b";")[0], 16)
        if size == 0:
            break
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return bytes(out)

# 响应还原示例
raw = open("stream62.bin", "rb").read()
body = raw.split(b"\r\n\r\n", 1)[1]
body = dechunk(body)
if body[:2] == b"\x1f\x8b":
    body = gzip.decompress(body)
stage1 = base64.b64decode(body)            # 常为 JSON
obj = json.loads(stage1)
stage2 = base64.b64decode(obj["msg"])      # 常为文件/命令输出
if stage2[:16] == b"SQLite format 3\x00":
    open("extracted.db", "wb").write(stage2)
```

说明：PoC 按原文马代码与 CyberChef 拆层顺序重写，未在附件 pcap 上复跑；响应可能只加密请求、明文回显，需先试解再用魔数验证。

## 变体与关联

- **AES-128-CBC 变体**：标准冰蝎 PHP 常用 `Base64 + AES-128-CBC + 16 字节零 IV`，key 从马文件提取；见 [[defense-forensics-behinder-php-webshell-traffic-decrypt]]。
- **RC4+XOR 魔改变体**：`Base64 + RC4 + key[(i+1)&15] XOR`；见 [[defense-forensics-behinder-php-rc4-xor-modified-traffic]]。
- **JSP 冰蝎**：key/pass 的静态提取与响应框架不同；见 [[defense-forensics-behinder-jsp-static-key-password-extraction]] 与 [[defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt]]。
- **magicNum 变化**：改 key 后 `hexdec(key[:2])%16` 可能不是 4；也可能改为在头部追加随机字符（`substr($data, $magicNum)`）或前后都加，必须以马代码为准。
- **压缩差异**：响应可能不压缩、只 chunked、只 gzip，或使用 br/deflate；先看响应头与文件魔数，不要盲套固定顺序。
- **关联**：[[defense-forensics-config-aes-key-iv-database-field-decrypt]]（还原出数据库后解字段）、[[defense-forensics-godzilla-php-webshell-traffic-decode]]（另一套 PHP 加密马协议）。

## 检测与防御

- 检测：上传目录出现随机命名 `.php`；同一 PHP 路径的 POST 体为高熵 Base64 且末尾带固定长度随机字符；响应 `Content-Type` 与 `Content-Encoding: gzip` 组合异常；请求解密后出现 `eval`、`assert`、`system`、`file_get_contents`、`base64_decode`。
- 检测：冰蝎默认 key `e45e329feb5d925b` 是强 IOC，可在马文件静态扫描、内存扫描与流量侧规则中使用；同时覆盖 AES-CBC/RC4 等变体。
- 防御：上传目录禁止 PHP 解析；禁用 `eval`/`assert` 与危险函数；启用 WAF/WebShell 检测；限制出网。
- 响应：隔离主机、保留 pcap 与马文件、提取 key 解密全部历史流量；轮换可能通过该马泄露的数据库/系统凭据，并排查横向移动。
