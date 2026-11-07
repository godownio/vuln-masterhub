---
id: defense-forensics-godzilla-php-webshell-traffic-decode
title: 哥斯拉 PHP WebShell 流量识别与解密（PHP_EVAL_XOR_BASE64 / PHP_XOR_BASE64 / PHP_XOR_RAW）
type: scenario
domain: defense
path: defense/forensics
technique: godzilla-php-webshell-traffic-decode
tags:
- forensics
- traffic-analysis
- webshell
- godzilla
- php
- xor
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:34:10+08:00'
  notes: 已对照原文与61张截图核对：PHP_EVAL_XOR_BASE64/PHP_XOR_BASE64/PHP_XOR_RAW 三类请求结构、XOR 下标 (i+1)&15、md5(pass+key) 前16/后16响应框架、PhpDynamicPayload 会话两阶段、Content-Length 64 与 PHPSESSID 特征均与卡片一致；原文明确 PHP 5.5.9/Apache 2.4.39 为实验环境、无受影响版本区间，故未标 affected_versions。未执行 PoC。
url: /docs/defense/forensics/defense-forensics-godzilla-php-webshell-traffic-decode/
draft: false
kb_aliases:
- 哥斯拉 PHP 流量分析
- Godzilla PHP 加密马流量
- PHP_EVAL_XOR_BASE64 解密
- PHP_XOR_BASE64 解密
- PHP_XOR_RAW 解密
- 哥斯拉 md5 响应框架
---

## 一句话结论

哥斯拉（Godzilla）PHP 加密马的流量有稳定的两阶段结构：首个大请求把 payload 解密后写入 `PHPSESSID` 会话并返回空响应，后续请求只携带模块参数；BASE64 系变体的响应固定为 `md5(pass+key)[:16] + Base64(XOR(执行结果)) + md5(pass+key)[16:]`，拿到马内的 `pass` 与 `key` 后即可按 `URL解码 → Base64解码 → 循环 XOR → 可选 gzip` 完整还原命令与回显。

## 原理

- **载荷生成**：哥斯拉生成 PHP 马时把 `$pass`（请求参数名，也是 `$_POST[$pass]` 的键）、`$key`（16 字节 XOR 密钥）、`$payloadName='payload'` 写进模板。不同加密器只改外层封装与参数位置。
- **XOR 函数**：模板中的 `encode($D,$K)` 对每个字节执行 `$D[$i] ^ $K[($i+1) & 15]`。密钥固定 16 字节并按 16 循环，但下标从 1 开始，因此第 0 个字节用 `key[1]`，第 15、31… 个字节才用 `key[0]`；实现解密时必须保留 `(i+1)&15`，不能从下标 0 简单循环。XOR 是对合运算，同一个函数既加密也解密。
- **首包装载 payload**：服务端先 `$data = encode(base64_decode($_POST[$pass]), $key)`。若 `$_SESSION[$payloadName]` 不存在且 `$data` 含 `getBasicsInfo`，则把 `encode($data, $key)` 写入 session，不执行。首包体积大（完整动态 payload），响应体为空，但会 `Set-Cookie: PHPSESSID=...` 建立会话。
- **后续请求执行**：服务端从 session 取出密文，`encode()` 还原 payload，若仍不含 `getBasicsInfo` 再 XOR 一次，`eval($payload)` 定义 `run()`，执行 `@run($data)`，然后按 `md5($pass.$key)` 的前 16 位、`base64_encode(encode(结果,$key))`、后 16 位依次输出。因此响应总长 64 字节（简单 `ok`）时，结构就是 16 字节 MD5 前缀 + 32 字节 Base64 + 16 字节 MD5 后缀。
- **外层 wrapper（仅 PHP_EVAL_XOR_BASE64）**：生成的 `pass` 参数值本身是一个 PHP 表达式 `eval(base64_decode(strrev(urldecode('...'))))`。字符串在生成时经过 `base64_encode → strrev → urlencode` 包装；取证时按 `urldecode → strrev → base64_decode` 还原，即可得到含 `$pass/$key` 的 loader PHP 代码。该变体的 loader 里 `$pass='key'`，所以真正的密文在请求的 `key=` 参数中，而 `pass=` 只是入口表达式。
- **PHP_XOR_BASE64**：loader 里 `$pass='pass'`，请求只有 `pass=<Base64(XOR(数据))>`，没有外层 eval 表达式；解出后同样按会话两阶段执行。
- **PHP_XOR_RAW**：服务端 `file_get_contents("php://input")` 读取原始请求体后直接 XOR，响应也只输出 `encode(@run($data),$key)` 的原始字节；没有 Base64、没有 MD5 前后缀、没有 `pass` 参数，`Content-Type` 常见为 `application/octet-stream`。抓包工具里正文是乱码，必须按 Hex/Base64 复制后解密。
- **为什么响应可以自校验**：`md5($pass.$key)` 完全由参数名和密钥决定，与请求内容无关，所以同一会话内所有响应的首尾 16 字节相同；这也给取证提供了直接的密钥验证方式，并可用于在 PCAP 中聚类同一 WebShell 的响应。
- **识别特征**（强→弱）：
  1. 请求体以 `pass=` 或 `key=` 开头，值为高熵 Base64；
  2. 首个请求体积明显偏大、响应 `Content-Length: 0` 且返回 `PHPSESSID`；后续请求复用该 Cookie，且哥斯拉生成的请求行里 Cookie 末尾常带一个分号（如 `Cookie: PHPSESSID=...;`），不符合常规 Cookie 写法；
  3. BASE64 变体响应呈现 16+Base64+16 的固定框架，简单应答长度为 64；
  4. `Accept` 默认为 `text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8`，`User-Agent` 为 Firefox 84 的 Gecko 串（弱特征）；
  5. `Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0` 是 PHP session 的默认缓存头，只能作为弱特征，不能单独判定哥斯拉。

## 触发条件

- 已取得或怀疑存在哥斯拉 PHP 马，且拥有完整的请求/响应（PCAP、Burp 历史、反向代理或 WAF 日志）。
- 知道马内的 `pass` 参数名与 `key`；或能从落地马文件、内存、备份中读到这两个值。只有密文而没有密钥时，XOR 密钥空间为 16 字节，实际通常由短口令经 `md5` 派生，可用字典尝试。
- 仅用于授权取证、应急响应和恶意流量分析；解密脚本只做数据还原，不执行还原出的 PHP 代码。

## 利用步骤

1. 在流量中定位同一 URL 的连续 POST：第一条体积最大、响应为空并 `Set-Cookie`，后续请求携带同一 `PHPSESSID`。
2. 若 `pass` 值是 `eval(base64_decode(strrev(urldecode(...))))`，先按 `urldecode → strrev → base64_decode` 还原 loader，读出 `$pass`、`$key`、`$payloadName`；否则从马文件或已知样本获取。
3. 计算 `md5(pass + key)`，与响应前 16/后 16 字节比对，确认密钥正确并确认响应框架。
4. 解密请求：
   - `PHP_EVAL_XOR_BASE64`：取 `key=` 参数；
   - `PHP_XOR_BASE64`：取 `pass=` 参数；
   - `PHP_XOR_RAW`：取原始请求体；
   统一执行 `URL 解码（raw 变体跳过）→ Base64 解码（raw 变体跳过）→ XOR(key, (i+1)&15) → 若以 1f 8b 开头则 gzip 解压`。
5. 解密响应：BASE64 变体先去掉前 16、后 16 字节，再 `Base64 解码 → XOR → 可选 gzip`；RAW 变体直接 `XOR → 可选 gzip`。
6. 按时间线还原 `methodName`、`getBasicsInfo`、`execCommand` 等模块调用和命令输出；首包解出的 payload 可进一步确认马的类型与版本。

## PoC

```python
import base64, gzip, hashlib, urllib.parse

def xor(data: bytes, key: bytes) -> bytes:
    # 必须复刻 (i + 1) & 15，而不是 i % 16
    return bytes(b ^ key[(i + 1) & 15] for i, b in enumerate(data))

def maybe_gunzip(data: bytes) -> bytes:
    return gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data

def decrypt_request(value: str, key: bytes, raw: bool = False) -> bytes:
    blob = value.encode() if raw else base64.b64decode(urllib.parse.unquote(value))
    return maybe_gunzip(xor(blob, key))

def decrypt_response(body: str, pass_name: str, key: bytes, raw: bool = False) -> bytes:
    if raw:
        blob = body.encode("latin-1")
    else:
        marker = hashlib.md5(pass_name.encode() + key).hexdigest()
        if body.startswith(marker[:16]) and body.endswith(marker[16:]):
            body = body[16:-16]
        blob = base64.b64decode(body)
    return maybe_gunzip(xor(blob, key))

# 示例参数来自公开分析环境，实际替换为目标流量值
# key = b"3c6e0b8a9c15224a"; pass_name = "key" (PHP_EVAL) 或 "pass" (PHP_XOR_BASE64)
# print(decrypt_request(req_value, key))
# print(decrypt_response(resp_body, pass_name, key))
```

还原 PHP_EVAL_XOR_BASE64 外层 loader（只解码，不执行）：

```php
<?php
echo base64_decode(strrev(urldecode('把 pass 参数中的字符串粘贴到这里')));
```

## 变体与关联

- **PHP_EVAL_XOR_BASE64**：`pass` 为 eval 包装器，密文在 `key` 参数；首包能直接还原出 loader 源码，最适合从流量反推马内密钥。
- **PHP_XOR_BASE64**：只有 `pass` 参数，响应同样带 MD5 框架；与上一者的区别仅是参数位置与是否经过 eval 外层。
- **PHP_XOR_RAW**：请求/响应均为原始 XOR 字节，无 Base64 与 MD5 框架，需按 Hex 复制，流量特征最弱但熵最高。
- **与 AES 变体的区别**：本卡是 XOR + Base64；哥斯拉另有 PHP_AES_BASE64 魔改马（见关联卡），其请求体是 AES-128-ECB 密文，响应结构类似但需要 AES 解密。
- 关联卡片：[[web-php-rce-godzilla-aes-session-webshell-disguise]]、[[defense-forensics-godzilla-java-webshell-traffic-decode]]。

## 检测与防御

- **流量侧**：对同一 URI 的 POST 序列做“首包大 + 首响应空 + 固定 Cookie”组合检测；响应体匹配 `^[0-9a-f]{16}[A-Za-z0-9+/=]{16,}[0-9a-f]{16}$`（PHP 小写 MD5）可作为高置信规则；`Accept` 与 UA 只作辅助。不要只依赖 `Cache-Control` 或 `PHPSESSID`，它们是 PHP 应用的常见头。
- **文件侧**：搜索 `eval(base64_decode(strrev(urldecode(`、`$_SESSION['payload']`、`$payloadName='payload'`、`encode($D,$K)` 等组合特征；检查 Web 目录中近期新增或修改的 `.php` 文件及访问日志中的首次大 POST。
- **主机侧**：PHP 进程加载的脚本内容、session 文件（`session_save_path`）中出现高熵 payload、`eval` 调用链；结合 Web 访问日志与文件时间线定位上传入口。
- **处置**：保留完整请求/响应与 session 文件作为证据；删除马文件并清理对应 session；排查同源上传/反序列化/文件包含入口；无法确认密钥时可用字典对短口令做 `md5` 派生尝试，但注意取证合规。
