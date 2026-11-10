---
id: defense-forensics-godzilla-php-xor-key-md5-bruteforce
title: 无密钥场景下哥斯拉 PHP_XOR_BASE64 密钥反推：用响应 16 个十六进制字符 md5 框架作 oracle 爆破原始口令再取 md5 前 16 位
type: scenario
domain: defense
path: defense/forensics
technique: godzilla-php-xor-key-md5-oracle-bruteforce
aliases:
- 哥斯拉密钥爆破
- PHP_XOR_BASE64 无密钥解密
- 响应 md5 前缀作 oracle
- Godzilla key 反推
- md5(pass+key) 校验爆破
tags:
- forensics
- traffic-analysis
- webshell
- godzilla
- php
- xor
- key-recovery
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:49:41+08:00'
  notes: 已对照原文核对：PHP_XOR_BASE64 的识别特征（请求参数值为密文、响应首尾各 16 个十六进制字符）、爆破脚本 `md5(pass + md5(候选)[:16])[:16]` 与响应前缀 e71f50e9773b23f9 比对、命中后二次派生 md5(候选)[:16] 才是真密钥、Anwsw0rd→a18551e65c48f51e、XOR 下标 (i+1)&15 均与本篇原文一致。核对时把正文中若干“16 字节”改为“16 个十六进制字符”（原文响应框架是 substr(md5(...),0,16) 的 16 个 hex 字符，长度 64 位而非 16 字节）。未验证点：未实际用字典跑通爆破，未执行文中 PoC。
---

## 一句话结论

抓到哥斯拉 `PHP_XOR_BASE64` 的请求/响应但没有马文件时，不必猜 16 字符 XOR 密钥：哥斯拉响应固定带 `md5(pass . key)` 的前 16 与后 16 位十六进制框架，而 `key` 本身是 `md5(原始口令)[:16]`，所以可用字典对「原始口令」逐个计算 `md5(pass + md5(候选)[:16])[:16]`，与响应首 16 个十六进制字符比对；命中即得原始口令，再由 `md5(候选)[:16]` 得到真正的 16 字节密钥，随后即可按 `Base64 → XOR((i+1)&15) → 可选 gzip` 还原全部历史命令与回显。

## 原理

- **响应里的 md5 前后缀是密钥的确定性函数**：`PHP_XOR_BASE64` 模板在每次应答时都会 `echo substr(md5($pass.$key),0,16)`、再输出密文、最后 `echo substr(md5($pass.$key),16)`。因为 `$pass`（参数名）与 `$key` 都与请求内容无关，同一马的所有响应首尾 16 个十六进制字符完全相同——这既可用于在 PCAP 中聚类同一 WebShell，也直接构成一个可离线计算的判定 oracle。
- **密钥是二次派生出来的**：哥斯拉客户端填入的「密钥」是一个原始字符串，客户端与服务端都按 `key = md5(rawKey) 的十六进制串取前 16 个字符` 派生实际 XOR 密钥。因此爆破空间落在「原始口令」上而不是 16 字节随机串上；命中后得到的候选值还需要再取一次 `md5` 前 16 位才是解密用的 key。把这两步混为一谈会得到「爆破成功却解不出流量」的错觉。
- **为什么 oracle 有效**：候选口令 `p` 代入 `md5(pass + md5(p)[:16])[:16]` 只在 `p` 恰好等于原始口令时才等于响应前缀的概率可忽略（16 个十六进制字符 = 64 位），所以字典遍历是确定性判定，无假阳性；代价是一次 md5 计算量，单机可达百万级/秒。
- **只有密码还不够**：已知 `pass`（参数名，如某次请求的表单键）但不知道 key 时，这仍是唯一可行的纯离线路径；若连 `pass` 也不知道，可先用 `PHP_EVAL_XOR_BASE64` 的外层表达式 `urldecode → strrev → base64_decode` 还原 loader 直接读出 `$pass`/`$key`（见关联卡），再判断是否仍需爆破。

## 触发条件

- 流量可判定为哥斯拉 PHP 马，且变体为 `PHP_XOR_BASE64`（请求参数值是密文、响应首尾各 16 个十六进制字符），不是 RAW/AES 变体。
- 已知 `pass` 参数名（来自请求表单键、WAF 日志字段、或 loader 还原结果）。
- 响应样本中至少有一份完整响应体，能读到 16 个十六进制字符 md5 前缀（单条即可，越短越好，如 `ok` 响应仅 64 字节）。
- 原始口令属于可被字典覆盖的弱口令/常见词；若口令是长随机串则本方法退化为不可行。

## 利用步骤

1. 从流量中挑一条响应最短的交互（如模块握手返回 `ok`），记录响应前 16 个十六进制字符作为目标值。
2. 确认请求体形态符合 `PHP_XOR_BASE64`：单个表单键 `pass=<高熵 Base64>`，且响应结构是 `16 位 hex + Base64 + 16 位 hex`；若请求体是 `hacker=eval(base64_decode(strrev(urldecode(...))))` 则是 EVAL 变体，应先还原 loader。
3. 准备字典（rockyou、中文弱口令表、工具默认口令表），逐条执行 `md5(pass + md5(candidate).hexdigest()[:16]).hexdigest()[:16]`，与第 1 步目标值比较。
4. 命中后输出候选明文 `p`，并计算真正的 16 字符密钥 `md5(p).hexdigest()[:16]`。
5. 用该密钥解密请求与响应：请求 `Base64解码 → XOR(key, (i+1)&15) → 若 1f8b 开头则 gzip`；响应先切掉首尾 16 个十六进制字符再同样处理。
6. 按时间线还原 `methodName`/`getCommand` 等模块调用与命令输出，形成取证报告；解密脚本只还原数据，不执行还原出的 PHP。

## PoC

```python
import base64, gzip, hashlib, urllib.parse

def xor(data: bytes, key: bytes) -> bytes:
    # 与哥斯拉模板一致：下标 (i+1)&15，不是 i%16
    return bytes(b ^ key[(i + 1) & 15] for i, b in enumerate(data))

def try_recover_rawkey(pass_name: bytes, target_prefix: str, dict_path: str):
    for line in open(dict_path, encoding="utf-8", errors="ignore"):
        cand = line.strip()
        if not cand:
            continue
        key = hashlib.md5(cand.encode()).hexdigest()[:16]          # 二次派生：md5(原始口令)[:16]
        marker = hashlib.md5(pass_name + key.encode()).hexdigest() # md5(pass . key)
        if marker[:16] == target_prefix:
            return cand, key
    return None, None

# pass_name = b"<请求体里的参数名>"
# target_prefix = "<响应前 16 个十六进制字符>"
# raw, key = try_recover_rawkey(pass_name, target_prefix, "rockyou.txt")

def decrypt_request(value: str, key: str) -> bytes:
    blob = base64.b64decode(urllib.parse.unquote(value))
    out = xor(blob, key.encode())
    return gzip.decompress(out) if out[:2] == b"\x1f\x8b" else out

def decrypt_response(body: str, key: str) -> bytes:
    marker = hashlib.md5(b"<参数名>" + key.encode()).hexdigest()
    if body.startswith(marker[:16]) and body.endswith(marker[16:]):
        body = body[16:-16]
    out = xor(base64.b64decode(body), key.encode())
    return gzip.decompress(out) if out[:2] == b"\x1f\x8b" else out
```

```bash
# 校验命中结果：同一马所有响应首尾 16 个十六进制字符应一致，可先做一致性检查再爆破
sort -u resp_prefix.txt | head
```

## 变体与关联

- **已知 key 直读**：`PHP_EVAL_XOR_BASE64` 的外层表达式可直接还原 loader 并读出 `$pass`/`$key`，不需要爆破；见 [[defense-forensics-godzilla-php-webshell-traffic-decode]]。
- **非二次派生变体**：部分魔改马把密钥直接硬编码（loader 里 `$key` 已是 16 字符），此时响应前 `md5(pass.$key)` 需按该 16 字符 key 计算，字典应遍历 key 空间而不是原始口令。
- **AES 变体**：`PHP_AES_BASE64` 响应框架相同但密钥派生/加密算法不同，需按 `openssl_encrypt` 分支处理，见 [[web-php-rce-godzilla-aes-session-webshell-disguise]]。
- **RAW 变体**：无 Base64 与 md5 框架，没有 oracle 可用，只能靠已知口令字典直接试解密并校验可读性（如 PHP 序列化/JSON 结构特征）。
- **关联**：[[defense-forensics-custom-xor-gzip-php-webshell-traffic]]（自定义 XOR 马无 md5 框架时的识别与解密）、[[defense-forensics-behinder-php-webshell-traffic-decrypt]]（冰蝎侧 key 从马文件提取的对照思路）。

## 检测与防御

- **取证侧**：先用响应首尾 16 个十六进制字符做同源聚类（同一 key/pass 的响应必然同前缀），再只对聚类代表样本做爆破，避免全量重算；记录命中口令与派生密钥作为证据链一环。
- **检测侧**：对同一 URI 的 POST 序列做「首包大 + 首响应空 + Set-Cookie + 后续 64 字节响应且首尾 16 个十六进制字符恒定」的组合规则，可高置信识别该变体；`Accept`、`Cache-Control` 只作辅助。
- **防御**：限制上传目录执行、禁用 `eval`/动态函数、WAF 拦截 `eval(base64_decode(strrev(urldecode(` 特征；发现马后立即轮换并排查上传入口，同时导出 session 文件中的高熵 payload。
- **注意**：md5 框架本身是攻击者为兼容客户端而设计的自校验，属于「协议指纹」，不能当作安全机制；任何持有流量的人都能离线验证密钥猜测。
